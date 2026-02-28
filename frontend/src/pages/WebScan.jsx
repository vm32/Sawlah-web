import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  SearchCode, Globe, FolderOpen, Bug, Cpu, Map, Play, Loader2,
  Skull, CheckCircle2, XCircle, Clock, ChevronDown, ChevronRight,
  ExternalLink, RefreshCw, Zap,
} from "lucide-react";
import { toolsApi, webreconApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";

const MODES = [
  { value: "standard", label: "Standard — common wordlists, fast" },
  { value: "deep", label: "Deep — medium wordlists, thorough" },
];

const STATUS_ICON = {
  pending: <Clock className="w-4 h-4 text-sawlah-dim" />,
  running: <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />,
  completed: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
  error: <XCircle className="w-4 h-4 text-red-400" />,
  killed: <Skull className="w-4 h-4 text-red-400" />,
};

function TaskCard({ label, status, taskId, icon: Icon, count, color }) {
  const [expanded, setExpanded] = useState(false);
  const [output, setOutput] = useState("");
  const ws = useWebSocket();

  useEffect(() => {
    if (taskId && status === "running" && !ws.connected && !ws.done) {
      ws.connect(taskId);
    }
  }, [taskId, status]);

  useEffect(() => {
    if (ws.output) setOutput(ws.output);
  }, [ws.output]);

  return (
    <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors"
      >
        <Icon className={`w-5 h-5 ${color}`} />
        <div className="flex-1 text-left">
          <p className="text-sm font-semibold text-sawlah-text">{label}</p>
        </div>
        {count > 0 && (
          <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${color} bg-current/10`}>
            <span className="text-current">{count}</span>
          </span>
        )}
        {STATUS_ICON[status] || STATUS_ICON.pending}
        {expanded ? <ChevronDown className="w-4 h-4 text-sawlah-dim" /> : <ChevronRight className="w-4 h-4 text-sawlah-dim" />}
      </button>
      {expanded && (
        <div className="border-t border-sawlah-border px-4 py-3 max-h-[300px] overflow-y-auto">
          {output ? (
            <pre className="text-[11px] font-mono text-sawlah-muted whitespace-pre-wrap break-all leading-relaxed">{output}</pre>
          ) : (
            <p className="text-xs text-sawlah-dim">
              {status === "pending" ? "Waiting to start..." : status === "running" ? "Scanning..." : "No output"}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function ResultSection({ title, icon: Icon, color, children, count }) {
  const [open, setOpen] = useState(true);
  if (count === 0) return null;
  return (
    <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-white/[0.02] transition-colors"
      >
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs font-bold uppercase tracking-wider text-sawlah-muted flex-1 text-left">{title}</span>
        <span className={`text-xs font-bold ${color}`}>{count}</span>
        {open ? <ChevronDown className="w-3.5 h-3.5 text-sawlah-dim" /> : <ChevronRight className="w-3.5 h-3.5 text-sawlah-dim" />}
      </button>
      {open && <div className="border-t border-sawlah-border">{children}</div>}
    </div>
  );
}

export default function WebScan({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("standard");
  const [threads, setThreads] = useState("30");
  const [extensions, setExtensions] = useState("");
  const [sessionId, setSessionId] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const [taskStatuses, setTaskStatuses] = useState({});
  const [results, setResults] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const navigate = useNavigate();

  useEffect(() => { setTitle("Web Scanning"); }, [setTitle]);

  const loadSessions = useCallback(() => {
    webreconApi.sessions().then((res) => setSessions(res.data)).catch(() => {});
  }, []);
  useEffect(() => { loadSessions(); }, [loadSessions]);

  useEffect(() => {
    if (!sessionId) return;
    const interval = setInterval(async () => {
      try {
        const res = await webreconApi.status(sessionId);
        const d = res.data;
        setSessionStatus(d.status);
        setTaskStatuses(d.tasks || {});
        setResults(d.results || null);
        if (["completed", "error", "killed"].includes(d.status)) {
          clearInterval(interval);
          loadSessions();
        }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [sessionId, loadSessions]);

  const handleRun = async () => {
    const t = target.trim();
    if (!t) return;
    setOutput("");
    setResults(null);
    setTaskStatuses({});
    setSessionStatus(null);
    try {
      const res = await webreconApi.run({
        target: t,
        mode,
        threads: parseInt(threads) || 30,
        extensions,
      });
      if (res.data.error) {
        setOutput(`Error: ${res.data.error}\n`);
        return;
      }
      setSessionId(res.data.session_id);
      setSessionStatus("running");
      setTaskStatuses(
        Object.fromEntries(
          Object.entries(res.data.tasks || {}).map(([k, v]) => [k, { ...v, status: "pending" }])
        )
      );
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
    }
  };

  const handleStop = async () => {
    if (sessionId) {
      await webreconApi.kill(sessionId);
      setSessionStatus("killed");
    }
  };

  const loadSession = async (sid) => {
    try {
      const res = await webreconApi.status(sid);
      setSessionId(sid);
      setSessionStatus(res.data.status);
      setTaskStatuses(res.data.tasks || {});
      setResults(res.data.results || null);
      setTarget(res.data.target || "");
    } catch {}
  };

  const subs = results?.subdomains || [];
  const dirs = results?.directories || [];
  const techs = results?.technologies || [];
  const exploits = results?.exploits || [];
  const serverInfo = results?.server_info || {};
  const isRunning = sessionStatus === "running";

  return (
    <div>
      <PageHeader title="Web Scanning" description="Full automated web recon — subdomain fuzzing + directory brute-force + technology detection + exploit search" icon={SearchCode} />

      {/* Target Input */}
      <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 mb-4">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 items-end">
          <div className="lg:col-span-2">
            <FormField label="Target" hint="Domain or URL — e.g. example.com, http://10.10.10.10">
              <TextInput value={target} onChange={setTarget} placeholder="example.com" />
            </FormField>
          </div>
          <FormField label="Mode">
            <SelectInput value={mode} onChange={setMode} options={MODES} />
          </FormField>
          <div className="flex gap-2">
            <button
              onClick={handleRun}
              disabled={isRunning || !target.trim()}
              className={`flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm transition-all ${
                isRunning
                  ? "bg-sawlah-surface text-sawlah-dim cursor-not-allowed border border-sawlah-border"
                  : "bg-sawlah-red text-white hover:bg-sawlah-red-hover shadow-lg shadow-sawlah-red-glow"
              }`}
            >
              {isRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              {isRunning ? "Scanning..." : "Full Recon"}
            </button>
            {isRunning && (
              <button
                onClick={handleStop}
                className="flex items-center gap-2 px-4 py-2.5 bg-red-900/60 text-red-300 border border-red-700/50 rounded-lg font-semibold text-sm hover:bg-red-800/80 transition-all"
              >
                <Skull className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 mt-3">
          <FormField label="Threads" hint="1-100">
            <TextInput value={threads} onChange={setThreads} placeholder="30" />
          </FormField>
          <FormField label="Extensions" hint="For directory scan, e.g. .php,.html,.bak">
            <TextInput value={extensions} onChange={setExtensions} placeholder=".php,.html,.txt" />
          </FormField>
        </div>
      </div>

      {/* Scan Progress */}
      {Object.keys(taskStatuses).length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
          {taskStatuses.subdomain_fuzz && (
            <TaskCard
              label="Subdomain Fuzzing"
              status={taskStatuses.subdomain_fuzz.status}
              taskId={taskStatuses.subdomain_fuzz.task_id}
              icon={Globe}
              color="text-blue-400"
              count={subs.length}
            />
          )}
          {taskStatuses.dir_bruteforce && (
            <TaskCard
              label="Directory Brute-force"
              status={taskStatuses.dir_bruteforce.status}
              taskId={taskStatuses.dir_bruteforce.task_id}
              icon={FolderOpen}
              color="text-purple-400"
              count={dirs.length}
            />
          )}
          {taskStatuses.tech_detect && (
            <TaskCard
              label="Tech Detection"
              status={taskStatuses.tech_detect.status}
              taskId={taskStatuses.tech_detect.task_id}
              icon={Cpu}
              color="text-cyan-400"
              count={techs.length}
            />
          )}
          {taskStatuses.exploit_search && (
            <TaskCard
              label="Exploit Search"
              status={taskStatuses.exploit_search.status}
              taskId={taskStatuses.exploit_search.task_id}
              icon={Bug}
              color="text-red-400"
              count={exploits.length}
            />
          )}
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-3 mb-4">
          {/* Summary stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: "Subdomains", value: subs.length, color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20" },
              { label: "Directories", value: dirs.length, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
              { label: "Technologies", value: techs.length, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
              { label: "Exploits", value: exploits.length, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
              {
                label: "View Map", value: "→", color: "text-sawlah-red",
                bg: "bg-sawlah-red/10 border-sawlah-red/20 cursor-pointer hover:bg-sawlah-red/20 transition-colors",
                onClick: () => navigate("/recon-map"),
              },
            ].map((s) => (
              <div
                key={s.label}
                onClick={s.onClick}
                className={`border rounded-xl px-4 py-3 text-center ${s.bg} ${s.onClick ? "cursor-pointer" : ""}`}
              >
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-sawlah-dim uppercase tracking-wider mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Server info */}
          {Object.keys(serverInfo).length > 0 && (
            <div className="bg-sawlah-card border border-sawlah-border rounded-xl px-4 py-3">
              <p className="text-[10px] font-bold uppercase tracking-wider text-sawlah-dim mb-2">Server Information</p>
              <div className="flex flex-wrap gap-3">
                {Object.entries(serverInfo).map(([k, v]) => (
                  <div key={k} className="text-xs">
                    <span className="text-sawlah-dim">{k}: </span>
                    <span className="text-sawlah-text font-mono">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Subdomains */}
          <ResultSection title="Subdomains Found" icon={Globe} color="text-blue-400" count={subs.length}>
            <div className="p-3 flex flex-wrap gap-1.5 max-h-[250px] overflow-y-auto">
              {subs.map((s, i) => (
                <span key={i} className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {s.subdomain}
                  {s.status > 0 && <span className="text-blue-600 ml-1 text-[9px]">[{s.status}]</span>}
                </span>
              ))}
            </div>
          </ResultSection>

          {/* Directories */}
          <ResultSection title="Directories & Files" icon={FolderOpen} color="text-purple-400" count={dirs.length}>
            <div className="max-h-[300px] overflow-y-auto">
              {dirs.map((d, i) => (
                <div key={i} className="flex items-center gap-2 px-4 py-1.5 border-b border-sawlah-border/30 hover:bg-white/[0.02] text-xs font-mono">
                  <span className={`font-bold w-8 text-center ${
                    d.status < 300 ? "text-emerald-400" : d.status < 400 ? "text-yellow-400" : "text-red-400"
                  }`}>{d.status}</span>
                  <span className="text-purple-300 flex-1">{d.path}</span>
                  {d.size > 0 && <span className="text-sawlah-dim">{d.size}B</span>}
                </div>
              ))}
            </div>
          </ResultSection>

          {/* Technologies */}
          <ResultSection title="Technologies Detected" icon={Cpu} color="text-cyan-400" count={techs.length}>
            <div className="p-3 grid grid-cols-1 md:grid-cols-2 gap-2">
              {techs.map((t, i) => (
                <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyan-500/5 border border-cyan-500/15">
                  <Cpu className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-cyan-300">{t.name}</span>
                    {t.version && <span className="text-[10px] text-cyan-500 ml-1">v{t.version}</span>}
                    <span className="text-[9px] text-sawlah-dim ml-2">{t.category}</span>
                  </div>
                </div>
              ))}
            </div>
          </ResultSection>

          {/* Exploits */}
          <ResultSection title="Exploits Found" icon={Bug} color="text-red-400" count={exploits.length}>
            <div className="max-h-[350px] overflow-y-auto">
              {exploits.map((e, i) => (
                <div key={i} className="px-4 py-2 border-b border-sawlah-border/30 hover:bg-red-500/5 transition-colors">
                  <p className="text-xs font-semibold text-red-300">{e.title}</p>
                  <div className="flex items-center gap-3 mt-0.5">
                    <span className="text-[10px] font-mono text-sawlah-dim">{e.path}</span>
                    <span className="text-[9px] text-red-500">search: {e.search_term}</span>
                  </div>
                </div>
              ))}
            </div>
          </ResultSection>
        </div>
      )}

      {/* Previous Sessions */}
      <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
        <button
          onClick={() => { setShowHistory(!showHistory); if (!showHistory) loadSessions(); }}
          className="w-full flex items-center justify-between px-5 py-3 hover:bg-white/[0.02] transition-colors"
        >
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-sawlah-muted" />
            <span className="text-xs font-bold uppercase tracking-wider text-sawlah-muted">Previous Scans ({sessions.length})</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => { e.stopPropagation(); loadSessions(); }}
              className="p-1 text-sawlah-dim hover:text-sawlah-muted transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
            {showHistory ? <ChevronDown className="w-4 h-4 text-sawlah-dim" /> : <ChevronRight className="w-4 h-4 text-sawlah-dim" />}
          </div>
        </button>
        {showHistory && (
          <div className="border-t border-sawlah-border max-h-[300px] overflow-y-auto">
            {sessions.length === 0 && (
              <p className="text-sm text-sawlah-dim px-5 py-6 text-center">No previous web recon sessions</p>
            )}
            {sessions.map((s) => (
              <button
                key={s.session_id}
                onClick={() => loadSession(s.session_id)}
                className="w-full flex items-center gap-3 px-5 py-3 border-b border-sawlah-border/50 hover:bg-white/[0.02] transition-colors text-left"
              >
                {STATUS_ICON[s.status]}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-sawlah-text">{s.target}</p>
                  <p className="text-[10px] text-sawlah-dim">
                    {new Date(s.started_at).toLocaleString()} &middot;
                    {s.subdomain_count} subs &middot; {s.dir_count} dirs &middot; {s.exploit_count} exploits
                  </p>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-sawlah-dim" />
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
