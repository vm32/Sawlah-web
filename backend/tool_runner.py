import asyncio
import os
import pty
import signal
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import WebSocket

tasks: dict[str, dict] = {}

def _notify_completion(task_id: str, task: dict):
    try:
        from notifications import add_notification
        status = task["status"]
        tool = task.get("tool_name", "unknown")
        if status == "completed":
            add_notification(
                title=f"{tool} scan completed",
                message=f"Task {task_id} finished successfully",
                severity="success", tool_name=tool, task_id=task_id,
            )
        elif status == "error":
            add_notification(
                title=f"{tool} scan failed",
                message=f"Task {task_id} exited with error",
                severity="error", tool_name=tool, task_id=task_id,
            )
        elif status == "killed":
            add_notification(
                title=f"{tool} scan killed",
                message=f"Task {task_id} was terminated by user",
                severity="warning", tool_name=tool, task_id=task_id,
            )
    except Exception:
        pass


class ToolRunner:
    """Core engine: spawns CLI tools as async subprocesses and streams output via WebSocket."""

    def __init__(self):
        self.active: dict[str, asyncio.subprocess.Process] = {}

    async def run(
        self,
        task_id: str,
        command: list[str],
        websocket: Optional[WebSocket] = None,
        tool_name: str = "",
    ) -> str:
        tasks[task_id] = {
            "status": "running",
            "tool_name": tool_name,
            "command": " ".join(command),
            "output": "",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "TERM": "xterm-256color"},
            )
            self.active[task_id] = process

            output_lines = []
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace")
                output_lines.append(decoded)
                tasks[task_id]["output"] += decoded
                if websocket:
                    try:
                        await websocket.send_text(decoded)
                    except Exception:
                        pass

            await process.wait()
            full_output = "".join(output_lines)
            tasks[task_id]["status"] = "completed" if process.returncode == 0 else "error"
            tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            tasks[task_id]["return_code"] = process.returncode
            _notify_completion(task_id, tasks[task_id])

        except Exception as e:
            tasks[task_id]["status"] = "error"
            tasks[task_id]["output"] += f"\n[ERROR] {str(e)}\n"
            tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            full_output = tasks[task_id]["output"]
            _notify_completion(task_id, tasks[task_id])
        finally:
            self.active.pop(task_id, None)

        return full_output

    async def kill(self, task_id: str) -> bool:
        proc = self.active.get(task_id)
        if proc:
            try:
                proc.terminate()
                await asyncio.sleep(1)
                if proc.returncode is None:
                    proc.kill()
                tasks[task_id]["status"] = "killed"
                tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _notify_completion(task_id, tasks[task_id])
                return True
            except Exception:
                return False
        return False

    def get_status(self, task_id: str) -> Optional[dict]:
        return tasks.get(task_id)

    def list_tasks(self) -> dict:
        return tasks


runner = ToolRunner()


def new_task_id() -> str:
    return str(uuid.uuid4())[:8]
