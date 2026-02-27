import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from tool_runner import runner, new_task_id, tasks
from database import async_session, Scan
from tools.nmap_tool import build_nmap_command, parse_nmap_output
from tools.subdomain import build_subdomain_command
from tools.web_scan import build_webscan_command
from tools.nxc_tool import build_nxc_command
from tools.enum_tool import build_enum_command
from tools.exploit import build_exploit_command

router = APIRouter()

pipelines: dict[str, dict] = {}


class PipelineStage(BaseModel):
    tool_name: str
    params: dict


class PipelineRequest(BaseModel):
    project_id: int
    target: str
    stages: list[PipelineStage]


class QuickAutoRequest(BaseModel):
    project_id: int
    target: str
    mode: str = "full"


@router.post("/run")
async def run_pipeline(req: PipelineRequest):
    pipeline_id = new_task_id()
    pipelines[pipeline_id] = {
        "status": "running",
        "stages": [],
        "current_stage": 0,
        "total_stages": len(req.stages),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    async def _execute():
        for i, stage in enumerate(req.stages):
            pipelines[pipeline_id]["current_stage"] = i + 1
            pipelines[pipeline_id]["stages"].append({
                "tool": stage.tool_name,
                "status": "running",
                "task_id": None,
            })

            from routes.tools import TOOL_BUILDERS
            builder = TOOL_BUILDERS.get(stage.tool_name)
            if not builder:
                pipelines[pipeline_id]["stages"][-1]["status"] = "error"
                continue

            merged_params = {**stage.params, "target": stage.params.get("target", req.target)}
            command = builder(stage.tool_name, merged_params)
            if not command:
                pipelines[pipeline_id]["stages"][-1]["status"] = "error"
                continue

            task_id = new_task_id()
            pipelines[pipeline_id]["stages"][-1]["task_id"] = task_id

            output = await runner.run(task_id, command)

            async with async_session() as session:
                scan = Scan(
                    project_id=req.project_id,
                    tool_name=stage.tool_name,
                    command=" ".join(command),
                    status=tasks[task_id]["status"],
                    output=output,
                    finished_at=datetime.now(timezone.utc),
                )
                session.add(scan)
                await session.commit()

            pipelines[pipeline_id]["stages"][-1]["status"] = tasks[task_id]["status"]

        pipelines[pipeline_id]["status"] = "completed"
        pipelines[pipeline_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    asyncio.create_task(_execute())
    return {"pipeline_id": pipeline_id, "status": "running"}


@router.post("/quick")
async def quick_auto(req: QuickAutoRequest):
    """Run an automated pentest pipeline based on mode."""
    stages = []

    if req.mode in ("full", "recon"):
        stages.append(PipelineStage(tool_name="nmap", params={"target": req.target, "scan_type": "quick"}))

    if req.mode in ("full", "recon"):
        stages.append(PipelineStage(tool_name="nmap", params={"target": req.target, "scan_type": "service"}))

    if req.mode in ("full", "enum"):
        stages.append(PipelineStage(tool_name="nxc", params={
            "target": req.target, "protocol": "smb", "shares": True, "users": True
        }))
        stages.append(PipelineStage(tool_name="enum4linux", params={"target": req.target, "all": True}))

    if req.mode in ("full", "web"):
        stages.append(PipelineStage(tool_name="whatweb", params={"target": req.target}))
        stages.append(PipelineStage(tool_name="nikto", params={"target": req.target}))

    if req.mode in ("full", "vuln"):
        stages.append(PipelineStage(tool_name="nmap", params={"target": req.target, "scan_type": "vuln"}))

    pipeline_req = PipelineRequest(project_id=req.project_id, target=req.target, stages=stages)
    return await run_pipeline(pipeline_req)


@router.get("/status/{pipeline_id}")
async def pipeline_status(pipeline_id: str):
    p = pipelines.get(pipeline_id)
    if not p:
        return {"error": "Pipeline not found"}
    return p


@router.get("/list")
async def list_pipelines():
    return pipelines


@router.websocket("/ws/{pipeline_id}")
async def ws_pipeline(websocket: WebSocket, pipeline_id: str):
    await websocket.accept()
    try:
        last_sent = 0
        while True:
            p = pipelines.get(pipeline_id)
            if not p:
                await asyncio.sleep(0.5)
                continue
            stages = p.get("stages", [])
            if len(stages) > last_sent:
                for s in stages[last_sent:]:
                    await websocket.send_json(s)
                last_sent = len(stages)

            current_stage = stages[-1] if stages else None
            if current_stage and current_stage.get("task_id"):
                task = tasks.get(current_stage["task_id"])
                if task:
                    await websocket.send_json({
                        "type": "output",
                        "task_id": current_stage["task_id"],
                        "output_tail": task["output"][-2000:] if task["output"] else "",
                    })

            if p["status"] in ("completed", "error"):
                await websocket.send_json({"type": "done", "status": p["status"]})
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
