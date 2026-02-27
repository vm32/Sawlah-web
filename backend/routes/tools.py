import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import select

from tool_runner import runner, new_task_id, tasks
from database import async_session, Scan, Finding
from tools.nmap_tool import build_nmap_command, parse_nmap_output
from tools.sqlmap_tool import build_sqlmap_command
from tools.subdomain import build_subdomain_command
from tools.web_scan import build_webscan_command
from tools.nxc_tool import build_nxc_command
from tools.enum_tool import build_enum_command
from tools.exploit import build_exploit_command
from tools.password import build_password_command
from tools.recon import build_recon_command

router = APIRouter()

TOOL_BUILDERS = {
    "nmap": build_nmap_command,
    "sqlmap": build_sqlmap_command,
    "amass": build_subdomain_command,
    "gobuster_dns": build_subdomain_command,
    "dnsenum": build_subdomain_command,
    "nikto": build_webscan_command,
    "dirb": build_webscan_command,
    "gobuster_dir": build_webscan_command,
    "ffuf": build_webscan_command,
    "whatweb": build_webscan_command,
    "wfuzz": build_webscan_command,
    "nxc": build_nxc_command,
    "enum4linux": build_enum_command,
    "smbclient": build_enum_command,
    "searchsploit": build_exploit_command,
    "hydra": build_password_command,
    "john": build_password_command,
    "hashcat": build_password_command,
    "whois": build_recon_command,
    "dig": build_recon_command,
}


class ToolRunRequest(BaseModel):
    tool_name: str
    params: dict
    project_id: Optional[int] = None


@router.post("/run")
async def run_tool(req: ToolRunRequest):
    builder = TOOL_BUILDERS.get(req.tool_name)
    if not builder:
        return {"error": f"Unknown tool: {req.tool_name}"}

    command = builder(req.tool_name, req.params)
    if not command:
        return {"error": "Failed to build command"}

    task_id = new_task_id()

    scan_id = None
    if req.project_id:
        async with async_session() as session:
            scan = Scan(
                project_id=req.project_id,
                tool_name=req.tool_name,
                command=" ".join(command),
                status="running",
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            scan_id = scan.id

    async def _run():
        output = await runner.run(task_id, command, tool_name=req.tool_name)
        if scan_id:
            async with async_session() as session:
                scan = await session.get(Scan, scan_id)
                if scan:
                    scan.output = output
                    scan.status = tasks[task_id]["status"]
                    scan.finished_at = datetime.now(timezone.utc)
                    await session.commit()

    asyncio.create_task(_run())

    return {
        "task_id": task_id,
        "command": " ".join(command),
        "scan_id": scan_id,
        "status": "running",
    }


@router.get("/status/{task_id}")
async def task_status(task_id: str):
    status = runner.get_status(task_id)
    if not status:
        return {"error": "Task not found"}
    return status


@router.delete("/kill/{task_id}")
async def kill_task(task_id: str):
    ok = await runner.kill(task_id)
    return {"killed": ok}


@router.get("/list")
async def list_tasks():
    return runner.list_tasks()


@router.websocket("/ws/{task_id}")
async def ws_tool_output(websocket: WebSocket, task_id: str):
    await websocket.accept()
    sent_length = 0
    try:
        while True:
            task = tasks.get(task_id)
            if not task:
                await asyncio.sleep(0.3)
                continue
            current_output = task["output"]
            if len(current_output) > sent_length:
                new_data = current_output[sent_length:]
                await websocket.send_text(new_data)
                sent_length = len(current_output)
            if task["status"] in ("completed", "error", "killed"):
                current_output = task["output"]
                if len(current_output) > sent_length:
                    await websocket.send_text(current_output[sent_length:])
                await websocket.send_text(f"\n\n[Done - {task['status']}]\n")
                break
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        pass


@router.get("/history")
async def task_history(tool_name: str = ""):
    """Return completed task history, optionally filtered by tool_name."""
    result = []
    for tid, t in tasks.items():
        if tool_name and t.get("tool_name", "") != tool_name:
            continue
        result.append({"id": tid, **t})
    result.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return result


@router.get("/scans/{project_id}")
async def get_project_scans(project_id: int):
    async with async_session() as session:
        result = await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.started_at.desc())
        )
        scans = result.scalars().all()
        return [
            {
                "id": s.id, "tool_name": s.tool_name, "command": s.command,
                "status": s.status, "output": s.output[:500] if s.output else "",
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in scans
        ]
