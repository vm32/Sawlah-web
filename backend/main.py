import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import init_db
from tool_runner import runner, tasks, new_task_id
from routes.projects import router as projects_router
from routes.tools import router as tools_router
from routes.automation import router as automation_router
from routes.reports import router as reports_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Sawlah-web", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects_router, prefix="/api/projects", tags=["projects"])
app.include_router(tools_router, prefix="/api/tools", tags=["tools"])
app.include_router(automation_router, prefix="/api/automation", tags=["automation"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])


@app.websocket("/ws/terminal/{task_id}")
async def ws_terminal(websocket: WebSocket, task_id: str):
    await websocket.accept()
    try:
        existing = tasks.get(task_id)
        if existing and existing["output"]:
            await websocket.send_text(existing["output"])

        while True:
            task = tasks.get(task_id)
            if not task:
                await asyncio.sleep(0.5)
                continue
            if task["status"] in ("completed", "error", "killed"):
                await websocket.send_text(f"\n[Task {task_id} finished with status: {task['status']}]\n")
                break
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass


@app.get("/api/health")
async def health():
    return {"status": "ok", "name": "Sawlah-web"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
