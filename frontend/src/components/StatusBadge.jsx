import { Loader2, CheckCircle2, XCircle, Clock, Skull } from "lucide-react";

const STATUS_CONFIG = {
  running: { icon: Loader2, color: "text-sawlah-yellow", bg: "bg-yellow-500/10", label: "Running", spin: true },
  completed: { icon: CheckCircle2, color: "text-sawlah-green", bg: "bg-green-500/10", label: "Completed", spin: false },
  error: { icon: XCircle, color: "text-sawlah-red", bg: "bg-red-500/10", label: "Error", spin: false },
  killed: { icon: Skull, color: "text-sawlah-orange", bg: "bg-orange-500/10", label: "Killed", spin: false },
  pending: { icon: Clock, color: "text-sawlah-dim", bg: "bg-zinc-500/10", label: "Pending", spin: false },
};

export default function StatusBadge({ status }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const Icon = config.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${config.color} ${config.bg}`}>
      <Icon className={`w-3.5 h-3.5 ${config.spin ? "animate-spin" : ""}`} />
      {config.label}
    </span>
  );
}
