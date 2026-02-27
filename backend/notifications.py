import asyncio
from datetime import datetime, timezone
from typing import Optional
from fastapi import WebSocket

notifications: list[dict] = []
_subscribers: list[WebSocket] = []


def add_notification(
    title: str,
    message: str,
    severity: str = "info",
    tool_name: str = "",
    task_id: str = "",
):
    notif = {
        "id": len(notifications) + 1,
        "title": title,
        "message": message,
        "severity": severity,
        "tool_name": tool_name,
        "task_id": task_id,
        "read": False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    notifications.insert(0, notif)
    if len(notifications) > 200:
        notifications.pop()
    asyncio.ensure_future(_broadcast(notif))
    return notif


async def _broadcast(notif: dict):
    dead = []
    for ws in _subscribers:
        try:
            await ws.send_json({"type": "notification", "data": notif})
        except Exception:
            dead.append(ws)
    for ws in dead:
        _subscribers.remove(ws)


def subscribe(ws: WebSocket):
    _subscribers.append(ws)


def unsubscribe(ws: WebSocket):
    if ws in _subscribers:
        _subscribers.remove(ws)


def get_notifications(limit: int = 50, unread_only: bool = False):
    items = notifications
    if unread_only:
        items = [n for n in items if not n["read"]]
    return items[:limit]


def mark_read(notif_id: int):
    for n in notifications:
        if n["id"] == notif_id:
            n["read"] = True
            return True
    return False


def mark_all_read():
    for n in notifications:
        n["read"] = True


def unread_count():
    return sum(1 for n in notifications if not n["read"])
