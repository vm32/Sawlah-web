import { useState, useEffect, useCallback, useRef } from "react";
import { FolderOpen, Loader2, CheckCircle2, XCircle, ChevronDown, Activity } from "lucide-react";
import Sidebar from "./Sidebar";
import { NotificationBell, ToastContainer } from "./Notifications";
import { projectsApi, toolsApi } from "../api/client";

function BackgroundTasks() {
  const [tasks, setTasks] = useState({});
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await toolsApi.list();
        setTasks(res.data || {});
      } catch {}
    };
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const taskList = Object.entries(tasks);
  const running = taskList.filter(([, t]) => t.status === "running");
  const recent = taskList
    .filter(([, t]) => t.status !== "running")
    .sort((a, b) => (b[1].finished_at || "").localeCompare(a[1].finished_at || ""))
    .slice(0, 8);

  const elapsed = (started) => {
    if (!started) return "";
    const s = Math.floor((Date.now() - new Date(started).getTime()) / 1000);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
          running.length > 0
            ? "bg-sawlah-red/10 text-sawlah-red border border-sawlah-red/30 hover:bg-sawlah-red/20"
            : "text-sawlah-dim hover:text-sawlah-muted hover:bg-white/5"
        }`}
      >
        {running.length > 0 ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          <Activity className="w-3.5 h-3.5" />
        )}
        {running.length > 0 ? `${running.length} running` : "Tasks"}
        <ChevronDown className="w-3 h-3" />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-80 bg-sawlah-card border border-sawlah-border rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-sawlah-border/50">
            <p className="text-[10px] font-bold uppercase tracking-wider text-sawlah-muted">
              Background Tasks
            </p>
          </div>

          {running.length === 0 && recent.length === 0 && (
            <p className="text-xs text-sawlah-dim text-center py-6">No tasks</p>
          )}

          {running.length > 0 && (
            <div className="border-b border-sawlah-border/50">
              {running.map(([id, t]) => (
                <div key={id} className="px-4 py-2.5 flex items-center gap-3 hover:bg-white/[0.02]">
                  <Loader2 className="w-3.5 h-3.5 text-sawlah-red animate-spin shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-sawlah-text truncate">
                      {t.tool_name || "task"}
                    </p>
                    <p className="text-[10px] text-sawlah-dim truncate">{t.command?.slice(0, 50)}</p>
                  </div>
                  <span className="text-[10px] text-sawlah-red font-mono shrink-0">
                    {elapsed(t.started_at)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {recent.length > 0 && (
            <div className="max-h-[250px] overflow-y-auto">
              {recent.map(([id, t]) => (
                <div key={id} className="px-4 py-2 flex items-center gap-3 hover:bg-white/[0.02]">
                  {t.status === "completed" ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-red-500 shrink-0" />
                  )}
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] text-sawlah-muted truncate">{t.tool_name}</p>
                  </div>
                  <span className="text-[10px] text-sawlah-dim font-mono shrink-0">{t.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

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
          <div className="flex items-center gap-2">
            <BackgroundTasks />
            <NotificationBell
              notifications={notifications}
              unreadCount={unreadCount}
              onMarkRead={markRead}
              onMarkAllRead={markAllRead}
              onRefresh={loadNotifications}
            />
          </div>
        </header>
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
