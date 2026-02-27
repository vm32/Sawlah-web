import { useState, useEffect, useRef, useCallback } from "react";
import {
  Bell, CheckCircle2, XCircle, AlertTriangle, Info, X, Check, ExternalLink
} from "lucide-react";

const SEVERITY_CONFIG = {
  success: { icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  error: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  warning: { icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  info: { icon: Info, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30" },
};

function Toast({ notif, onDismiss }) {
  const cfg = SEVERITY_CONFIG[notif.severity] || SEVERITY_CONFIG.info;
  const Icon = cfg.icon;

  useEffect(() => {
    const timer = setTimeout(onDismiss, 5000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  return (
    <div className={`flex items-start gap-3 px-4 py-3 rounded-xl border ${cfg.bg} ${cfg.border} shadow-2xl shadow-black/50 backdrop-blur-sm animate-slide-in min-w-[320px] max-w-[400px]`}>
      <Icon className={`w-5 h-5 ${cfg.color} shrink-0 mt-0.5`} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-sawlah-text">{notif.title}</p>
        <p className="text-xs text-sawlah-muted mt-0.5">{notif.message}</p>
      </div>
      <button onClick={onDismiss} className="p-0.5 text-sawlah-dim hover:text-sawlah-text transition-colors shrink-0">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

export function ToastContainer({ toasts, onDismiss }) {
  return (
    <div className="fixed bottom-6 right-6 z-[100] space-y-2">
      {toasts.map((t) => (
        <Toast key={t.id} notif={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

export function NotificationBell({ notifications, unreadCount, onMarkRead, onMarkAllRead, onRefresh }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => { setOpen(!open); if (!open) onRefresh(); }}
        className="relative p-2 text-sawlah-dim hover:text-sawlah-text hover:bg-white/5 rounded-lg transition-colors"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4.5 h-4.5 min-w-[18px] px-1 text-[9px] font-bold bg-sawlah-red text-white rounded-full animate-pulse">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-[380px] bg-sawlah-card border border-sawlah-border rounded-xl shadow-2xl shadow-black/50 z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-sawlah-border">
            <h3 className="text-sm font-semibold text-sawlah-text">Notifications</h3>
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllRead}
                className="flex items-center gap-1 text-[10px] text-sawlah-red hover:text-sawlah-red-hover transition-colors"
              >
                <Check className="w-3 h-3" /> Mark all read
              </button>
            )}
          </div>
          <div className="max-h-[400px] overflow-y-auto">
            {notifications.length === 0 && (
              <div className="px-4 py-8 text-center text-sawlah-dim">
                <Bell className="w-8 h-8 mx-auto mb-2 opacity-20" />
                <p className="text-sm">No notifications yet</p>
              </div>
            )}
            {notifications.map((n) => {
              const cfg = SEVERITY_CONFIG[n.severity] || SEVERITY_CONFIG.info;
              const Icon = cfg.icon;
              return (
                <div
                  key={n.id}
                  onClick={() => onMarkRead(n.id)}
                  className={`flex items-start gap-3 px-4 py-3 border-b border-sawlah-border/50 cursor-pointer transition-colors ${
                    n.read ? "opacity-60" : "hover:bg-white/[0.02]"
                  }`}
                >
                  <Icon className={`w-4 h-4 ${cfg.color} shrink-0 mt-0.5`} />
                  <div className="flex-1 min-w-0">
                    <p className={`text-xs font-semibold ${n.read ? "text-sawlah-dim" : "text-sawlah-text"}`}>{n.title}</p>
                    <p className="text-[11px] text-sawlah-dim mt-0.5">{n.message}</p>
                    <p className="text-[9px] text-sawlah-dim/50 mt-1">
                      {n.timestamp ? new Date(n.timestamp).toLocaleString() : ""}
                    </p>
                  </div>
                  {!n.read && <span className="w-2 h-2 rounded-full bg-sawlah-red shrink-0 mt-1" />}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
