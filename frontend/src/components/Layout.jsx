import { useState, useEffect, useCallback, useRef } from "react";
import { FolderOpen } from "lucide-react";
import Sidebar from "./Sidebar";
import { NotificationBell, ToastContainer } from "./Notifications";
import { projectsApi } from "../api/client";

export default function Layout({ children, user, onLogout, activeProject, setActiveProject }) {
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [toasts, setToasts] = useState([]);
  const [projects, setProjects] = useState([]);
  const wsRef = useRef(null);

  const loadNotifications = useCallback(async () => {
    try {
      const res = await fetch("/api/notifications?limit=50");
      const data = await res.json();
      setNotifications(data.notifications || []);
      setUnreadCount(data.unread || 0);
    } catch {}
  }, []);

  useEffect(() => {
    projectsApi.list().then((res) => setProjects(res.data || [])).catch(() => {});
  }, []);

  useEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 10000);
    return () => clearInterval(interval);
  }, [loadNotifications]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/notifications`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "notification") {
          const notif = msg.data;
          setNotifications((prev) => [notif, ...prev].slice(0, 100));
          setUnreadCount((c) => c + 1);
          setToasts((prev) => [...prev, notif].slice(-5));
        }
      } catch {}
    };

    ws.onerror = () => {};
    ws.onclose = () => {};

    return () => { ws.close(); };
  }, []);

  const markRead = async (id) => {
    try { await fetch(`/api/notifications/${id}/read`, { method: "POST" }); } catch {}
    setNotifications((prev) => prev.map((n) => n.id === id ? { ...n, read: true } : n));
    setUnreadCount((c) => Math.max(0, c - 1));
  };

  const markAllRead = async () => {
    try { await fetch("/api/notifications/read-all", { method: "POST" }); } catch {}
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);
  };

  const dismissToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const activeProj = projects.find((p) => p.id === activeProject);

  return (
    <div className="flex min-h-screen bg-sawlah-bg">
      <Sidebar user={user} onLogout={onLogout} />
      <div className="flex-1 ml-60 flex flex-col">
        <header className="flex items-center justify-between gap-3 px-6 py-2 border-b border-sawlah-border/50">
          <div className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-sawlah-red shrink-0" />
            <select
              value={activeProject || ""}
              onChange={(e) => setActiveProject(e.target.value)}
              className="bg-sawlah-surface border border-sawlah-border rounded-lg px-3 py-1.5 text-xs text-sawlah-text focus:outline-none focus:border-sawlah-red/50 min-w-[200px]"
            >
              <option value="">No project (scans not saved)</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.target})
                </option>
              ))}
            </select>
            {activeProj && (
              <span className="text-[10px] text-sawlah-dim ml-1">
                Scans auto-saved to this project
              </span>
            )}
          </div>
          <NotificationBell
            notifications={notifications}
            unreadCount={unreadCount}
            onMarkRead={markRead}
            onMarkAllRead={markAllRead}
            onRefresh={loadNotifications}
          />
        </header>
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
