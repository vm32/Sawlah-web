import asyncio
import shutil
import re
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from tool_runner import runner, new_task_id, tasks
from config import TOOL_PATHS

router = APIRouter()

DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


class SubEnumAllRequest(BaseModel):
    target: str
    threads: int = 30
    extensions: str = ""
    dns_wordlist: str = DNS_WORDLIST
    dir_wordlist: str = DIR_WORDLIST
    project_id: Optional[int] = None


def _extract_domain(target: str) -> str:
    t = target.strip()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0].split(":")[0]
    return t


def _build_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = f"http://{t}"
    return t.rstrip("/")


@router.post("/run-all")
async def run_all(req: SubEnumAllRequest):
    target = req.target.strip()
    if not target:
        return {"error": "Target is required"}

    domain = _extract_domain(target)
    url = _build_target_url(target)
    threads = str(min(max(req.threads, 1), 100))

    gobuster_bin = shutil.which("gobuster") or TOOL_PATHS.get("gobuster", "")
    dnsenum_bin = shutil.which("dnsenum") or TOOL_PATHS.get("dnsenum", "")

    if not gobuster_bin:
        return {"error": "gobuster not found on system"}

    task_id = new_task_id()

    scan_id = None
    if req.project_id:
        from database import async_session, Scan
        async with async_session() as session:
            scan = Scan(
                project_id=req.project_id,
                tool_name="subenum_all",
                command=f"all-in-one scan: {domain}",
                status="running",
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            scan_id = scan.id

    async def _run():
        tasks[task_id] = {
            "status": "running",
            "tool_name": "subenum_all",
            "command": f"all-in-one scan: {domain}",
            "output": "",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

        def _append(text):
            tasks[task_id]["output"] += text

        # --- Phase 1: Gobuster DNS (subdomains) ---
        _append(f"\n{'='*60}\n[*] Phase 1: Subdomain Discovery (gobuster dns)\n[*] Domain: {domain}\n{'='*60}\n\n")
        dns_cmd = [
            gobuster_bin, "dns",
            "--do", domain,
            "-w", req.dns_wordlist,
            "-t", threads,
            "-q",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *dns_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                _append(line.decode("utf-8", errors="replace"))
            await proc.wait()
        except Exception as e:
            _append(f"[ERROR] gobuster dns failed: {e}\n")

        # --- Phase 2: DNSEnum ---
        if dnsenum_bin:
            _append(f"\n{'='*60}\n[*] Phase 2: DNS Enumeration (dnsenum)\n[*] Domain: {domain}\n{'='*60}\n\n")
            dnsenum_cmd = [dnsenum_bin, "--noreverse", "--threads", threads, domain]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *dnsenum_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    _append(line.decode("utf-8", errors="replace"))
                await proc.wait()
            except Exception as e:
                _append(f"[ERROR] dnsenum failed: {e}\n")

        # --- Phase 3: Gobuster Dir (directories) ---
        _append(f"\n{'='*60}\n[*] Phase 3: Directory Discovery (gobuster dir)\n[*] URL: {url}\n{'='*60}\n\n")
        dir_cmd = [
            gobuster_bin, "dir",
            "-u", url,
            "-w", req.dir_wordlist,
            "-t", threads,
            "-q", "--no-error",
        ]
        if req.extensions:
            dir_cmd.extend(["-x", req.extensions])
        try:
            proc = await asyncio.create_subprocess_exec(
                *dir_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                _append(line.decode("utf-8", errors="replace"))
            await proc.wait()
        except Exception as e:
            _append(f"[ERROR] gobuster dir failed: {e}\n")

        # --- Summary ---
        _append(f"\n{'='*60}\n[*] All-in-One Scan Complete\n{'='*60}\n")

        tasks[task_id]["status"] = "completed"
        tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        if scan_id:
            from database import async_session, Scan
            async with async_session() as session:
                scan = await session.get(Scan, scan_id)
                if scan:
                    scan.output = tasks[task_id]["output"]
                    scan.status = "completed"
                    scan.finished_at = datetime.now(timezone.utc)
                    await session.commit()

        try:
            from notifications import add_notification
            add_notification(
                title="All-in-One scan completed",
                message=f"Subdomain + directory scan of {domain} finished",
                severity="success", tool_name="subenum_all", task_id=task_id,
            )
        except Exception:
            pass

    asyncio.create_task(_run())

    return {
        "task_id": task_id,
        "command": f"all-in-one scan: {domain}",
        "scan_id": scan_id,
        "domain": domain,
        "status": "running",
    }
