import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from tool_runner import runner, tasks, new_task_id
from notifications import subscribe, unsubscribe, get_notifications, mark_read, mark_all_read, unread_count
from routes.projects import router as projects_router
from routes.tools import router as tools_router
from routes.automation import router as automation_router
from routes.reports import router as reports_router
from routes.recon_map import router as recon_map_router
from routes.nikto import router as nikto_router
from auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Sawlah-web", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(projects_router, prefix="/api/projects", tags=["projects"])
app.include_router(tools_router, prefix="/api/tools", tags=["tools"])
app.include_router(automation_router, prefix="/api/automation", tags=["automation"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(recon_map_router, prefix="/api/map", tags=["recon-map"])
app.include_router(nikto_router, prefix="/api/nikto", tags=["nikto"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "name": "Sawlah-web", "version": "2.0.0"}


@app.get("/api/notifications")
async def get_notifs(limit: int = 50, unread_only: bool = False):
    return {"notifications": get_notifications(limit, unread_only), "unread": unread_count()}


@app.post("/api/notifications/{notif_id}/read")
async def read_notif(notif_id: int):
    mark_read(notif_id)
    return {"ok": True}


@app.post("/api/notifications/read-all")
async def read_all():
    mark_all_read()
    return {"ok": True}


@app.websocket("/ws/notifications")
async def ws_notifications(websocket: WebSocket):
    await websocket.accept()
    subscribe(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        unsubscribe(websocket)


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
