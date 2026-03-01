import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Plus, Radar, Database, Globe, SearchCode,
  Network, Server, Bug, Key, Workflow, Activity, FolderOpen, Trash2,
  ChevronDown, ChevronRight, Copy, Check, ExternalLink, Clock,
  Fingerprint, Terminal, Zap, Shield, AlertTriangle, TrendingUp,
  Target, Cpu, Wifi, FileText, Hash, BookOpen
} from "lucide-react";
import { projectsApi, toolsApi } from "../api/client";
import StatusBadge from "../components/StatusBadge";

const QUICK_TOOLS = [
  { icon: Radar, label: "Nmap Scan", path: "/nmap", color: "text-red-400", desc: "Port & service scan" },
  { icon: Database, label: "SQLMap", path: "/sqlmap", color: "text-orange-400", desc: "SQL injection" },
  { icon: Globe, label: "Sub Enum", path: "/subenum", color: "text-blue-400", desc: "Subdomain discovery" },
  { icon: SearchCode, label: "Web Scan", path: "/webscan", color: "text-green-400", desc: "Dir & vuln scan" },
  { icon: Network, label: "NetExec", path: "/nxc", color: "text-purple-400", desc: "AD & network enum" },
  { icon: Server, label: "Enum", path: "/enum", color: "text-cyan-400", desc: "Service enumeration" },
  { icon: Bug, label: "Exploits", path: "/exploit", color: "text-yellow-400", desc: "Exploit search" },
  { icon: Key, label: "Passwords", path: "/password", color: "text-pink-400", desc: "Brute force attacks" },
  { icon: Fingerprint, label: "Hash Crack", path: "/hash", color: "text-amber-400", desc: "Identify & crack" },
  { icon: Workflow, label: "Pipeline", path: "/automation", color: "text-emerald-400", desc: "Auto workflow" },
];

const QUICK_ACTIONS = [
  { label: "Full TCP Scan", icon: Radar, color: "bg-red-500/10 text-red-400 border-red-500/20",
    tool: "nmap", params: { scan_type: "full_tcp", verbose: true } },
  { label: "Quick Vuln Scan", icon: AlertTriangle, color: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    tool: "nmap", params: { scan_type: "vuln" } },
  { label: "Dir Brute (common)", icon: BookOpen, color: "bg-green-500/10 text-green-400 border-green-500/20",
    tool: "gobuster_dir", params: { wordlist: "/usr/share/wordlists/dirb/common.txt" } },
  { label: "Identify Hash", icon: Hash, color: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    navigate: "/hash" },
  { label: "Crack w/ rockyou", icon: Zap, color: "bg-pink-500/10 text-pink-400 border-pink-500/20",
    navigate: "/hash" },
  { label: "SMB Enum", icon: Wifi, color: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    tool: "nxc", params: { protocol: "smb", shares: true, users: true } },
];

const TOOL_PAGES = {
  nmap: "/nmap", sqlmap: "/sqlmap", amass: "/subenum", gobuster_dns: "/subenum",
  dnsenum: "/subenum", nikto: "/webscan", dirb: "/webscan", gobuster_dir: "/webscan",
  ffuf: "/webscan", whatweb: "/webscan", wfuzz: "/webscan", nxc: "/nxc",
  enum4linux: "/enum", smbclient: "/enum", whois: "/enum", dig: "/enum",
  searchsploit: "/exploit", hydra: "/password", john: "/password", hashcat: "/password",
  hashid: "/hash", hashcat_crack: "/hash", john_crack: "/hash",
};

export default function Dashboard({ setOutput, setTitle, activeProject }) {
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [tasks, setTasks] = useState({});
  const [showNewProject, setShowNewProject] = useState(false);
  const [newName, setNewName] = useState("");
  const [newTarget, setNewTarget] = useState("");
  const [newScope, setNewScope] = useState("");
  const [expandedTask, setExpandedTask] = useState(null);
  const [copied, setCopied] = useState(false);
  const [quickTarget, setQuickTarget] = useState("");
  const [autoExploitResults, setAutoExploitResults] = useState(null);
  const [autoExploitLoading, setAutoExploitLoading] = useState(false);

  useEffect(() => { setTitle("Dashboard"); }, [setTitle]);

  const loadData = () => {
    projectsApi.list().then((res) => setProjects(res.data)).catch(() => {});
    toolsApi.list().then((res) => setTasks(res.data)).catch(() => {});
  };

  useEffect(() => { loadData(); const i = setInterval(loadData, 5000); return () => clearInterval(i); }, []);

  const createProject = async () => {
    if (!newName.trim() || !newTarget.trim()) return;
    await projectsApi.create({ name: newName, target: newTarget, scope: newScope });
    setNewName(""); setNewTarget(""); setNewScope(""); setShowNewProject(false); loadData();
  };

  const deleteProject = async (id) => { await projectsApi.delete(id); loadData(); };

  const copyOutput = (text) => {
    navigator.clipboard.writeText(text); setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const runQuickAction = async (action) => {
    if (action.navigate) { navigate(action.navigate); return; }
    if (!quickTarget.trim()) return;
    try {
      const params = { ...action.params, target: quickTarget.trim() };
      const res = await toolsApi.run(action.tool, params, activeProject);
      navigate(TOOL_PAGES[action.tool] || "/");
    } catch {}
  };

  const runAutoExploit = async (taskId) => {
    setAutoExploitLoading(true);
    try {
      const res = await toolsApi.autoExploit({ task_id: taskId });
      setAutoExploitResults(res.data);
    } catch (err) {
      setAutoExploitResults({ error: err.message });
    }
    setAutoExploitLoading(false);
  };

  const taskEntries = Object.entries(tasks).sort(
    ([, a], [, b]) => (b.started_at || "").localeCompare(a.started_at || "")
  );
  const runningTasks = taskEntries.filter(([, t]) => t.status === "running");
  const completedTasks = taskEntries.filter(([, t]) => t.status === "completed");
  const errorTasks = taskEntries.filter(([, t]) => t.status === "error");
  const nmapTasks = taskEntries.filter(([, t]) => t.tool_name === "nmap" && t.status === "completed");

  const openPorts = taskEntries.reduce((acc, [, t]) => {
    if (t.tool_name !== "nmap" || !t.output) return acc;
    const matches = t.output.match(/(\d+)\/(tcp|udp)\s+open/g);
    return acc + (matches ? matches.length : 0);
  }, 0);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-sawlah-red" />
          <div>
            <h1 className="text-2xl font-bold text-sawlah-text">Sawlah Dashboard</h1>
            <p className="text-sm text-sawlah-muted">Penetration Testing Command Center</p>
          </div>
        </div>
        <button onClick={() => setShowNewProject(true)}
          className="flex items-center gap-2 px-4 py-2 bg-sawlah-red text-white rounded-lg text-sm font-medium hover:bg-sawlah-red-hover transition-colors shadow-lg shadow-sawlah-red-glow">
          <Plus className="w-4 h-4" /> New Project
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        {[
          { label: "Projects", value: projects.length, icon: FolderOpen, color: "text-sawlah-red", bg: "bg-red-500/5 border-red-500/20" },
          { label: "Running", value: runningTasks.length, icon: Cpu, color: "text-sawlah-yellow", bg: "bg-yellow-500/5 border-yellow-500/20" },
          { label: "Completed", value: completedTasks.length, icon: Check, color: "text-sawlah-green", bg: "bg-green-500/5 border-green-500/20" },
          { label: "Failed", value: errorTasks.length, icon: AlertTriangle, color: "text-red-400", bg: "bg-red-500/5 border-red-500/20" },
          { label: "Open Ports", value: openPorts, icon: Target, color: "text-cyan-400", bg: "bg-cyan-500/5 border-cyan-500/20" },
          { label: "Total Scans", value: taskEntries.length, icon: TrendingUp, color: "text-sawlah-muted", bg: "bg-white/[0.02] border-sawlah-border" },
        ].map((stat) => (
          <div key={stat.label} className={`border rounded-xl p-3.5 ${stat.bg}`}>
            <div className="flex items-center justify-between mb-2">
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
              {stat.label === "Running" && runningTasks.length > 0 && (
                <span className="w-2 h-2 rounded-full bg-sawlah-yellow animate-pulse" />
              )}
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            <p className="text-[10px] text-sawlah-dim uppercase tracking-wider mt-0.5">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Quick Launch */}
      <div className="mb-6">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3">Quick Launch</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-2">
          {QUICK_TOOLS.map((tool) => (
            <button key={tool.path} onClick={() => navigate(tool.path)}
              className="flex flex-col items-center gap-1.5 p-3 bg-sawlah-card border border-sawlah-border rounded-xl hover:border-sawlah-red/40 hover:bg-sawlah-red/5 transition-all group">
              <tool.icon className={`w-5 h-5 ${tool.color} group-hover:scale-110 transition-transform`} />
              <span className="text-[11px] font-medium text-sawlah-muted group-hover:text-sawlah-text transition-colors">{tool.label}</span>
              <span className="text-[9px] text-sawlah-dim/60">{tool.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Quick Actions with target */}
      <div className="mb-6">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3">
          <Zap className="w-3.5 h-3.5 inline mr-1" />Quick Actions
        </h2>
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-4">
          <div className="flex gap-3 mb-3">
            <div className="flex-1 flex items-center bg-black/40 border border-sawlah-border rounded-lg overflow-hidden focus-within:border-sawlah-red transition-colors">
              <Target className="w-4 h-4 text-sawlah-red ml-3" />
              <input value={quickTarget} onChange={(e) => setQuickTarget(e.target.value)}
                placeholder="Enter target IP or URL for quick actions..."
                className="flex-1 bg-transparent border-0 font-mono text-sm px-2 py-2.5 text-sawlah-green placeholder:text-sawlah-dim/40 focus:outline-none" />
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
            {QUICK_ACTIONS.map((action, i) => (
              <button key={i} onClick={() => runQuickAction(action)}
                className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border text-xs font-medium transition-all hover:scale-[1.02] ${action.color}`}>
                <action.icon className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{action.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* New Project Modal */}
      {showNewProject && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-6 w-full max-w-md space-y-4">
            <h2 className="text-lg font-bold text-sawlah-text">New Project</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-1">Project Name</label>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Internal Pentest Q1" className="w-full" />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-1">Target</label>
                <input value={newTarget} onChange={(e) => setNewTarget(e.target.value)} placeholder="192.168.1.0/24" className="w-full" />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-1">Scope</label>
                <textarea value={newScope} onChange={(e) => setNewScope(e.target.value)} placeholder="Describe the scope..." className="w-full h-20 resize-none" />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowNewProject(false)} className="px-4 py-2 text-sm text-sawlah-muted hover:text-white transition-colors">Cancel</button>
              <button onClick={createProject} className="px-4 py-2 bg-sawlah-red text-white rounded-lg text-sm font-medium hover:bg-sawlah-red-hover transition-colors">Create</button>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Projects + Auto Exploit */}
        <div className="lg:col-span-4 space-y-4">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3 flex items-center gap-2">
              <FolderOpen className="w-4 h-4" /> Projects
            </h2>
            <div className="space-y-2">
              {projects.length === 0 && (
                <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-6 text-center">
                  <p className="text-sawlah-dim text-sm">No projects yet</p>
                </div>
              )}
              {projects.map((p) => (
                <div key={p.id} className="bg-sawlah-card border border-sawlah-border rounded-xl p-4 hover:border-sawlah-red/30 transition-colors">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-medium text-sawlah-text">{p.name}</h3>
                      <p className="text-sm text-sawlah-red font-mono mt-0.5">{p.target}</p>
                      {p.scope && <p className="text-xs text-sawlah-dim mt-1 line-clamp-2">{p.scope}</p>}
                    </div>
                    <button onClick={() => deleteProject(p.id)} className="p-1.5 hover:bg-red-500/20 rounded text-sawlah-dim hover:text-sawlah-red transition-colors">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Auto Exploit Lookup */}
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3 flex items-center gap-2">
              <Bug className="w-4 h-4" /> Auto Exploit Lookup
            </h2>
            <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-4">
              <p className="text-[11px] text-sawlah-dim mb-3">
                Select a completed Nmap scan to auto-search exploits for discovered services
              </p>
              {nmapTasks.length === 0 ? (
                <p className="text-xs text-sawlah-dim/60">No completed Nmap scans yet</p>
              ) : (
                <div className="space-y-1.5">
                  {nmapTasks.slice(0, 5).map(([id, t]) => (
                    <button key={id} onClick={() => runAutoExploit(id)}
                      disabled={autoExploitLoading}
                      className="w-full flex items-center gap-2 px-3 py-2 bg-black/20 border border-sawlah-border rounded-lg hover:border-sawlah-red/30 transition-colors text-left disabled:opacity-50">
                      <Radar className="w-3.5 h-3.5 text-sawlah-red shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-[10px] font-mono text-sawlah-dim truncate">{t.command}</p>
                        <p className="text-[9px] text-sawlah-dim/60">{t.started_at ? new Date(t.started_at).toLocaleString() : ""}</p>
                      </div>
                      <Zap className="w-3.5 h-3.5 text-sawlah-yellow shrink-0" />
                    </button>
                  ))}
                </div>
              )}

              {autoExploitResults && !autoExploitResults.error && (
                <div className="mt-3 space-y-2">
                  <p className="text-[10px] uppercase tracking-wider font-bold text-sawlah-green">
                    Found {autoExploitResults.services?.length || 0} services with versions
                  </p>
                  {autoExploitResults.exploit_searches?.map((es, i) => (
                    <div key={i} className="bg-black/30 rounded-lg p-2.5 border border-sawlah-border/50">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] font-mono text-sawlah-red">
                          {es.service.port}/{es.service.proto}
                        </span>
                        <StatusBadge status={es.status} />
                      </div>
                      <p className="text-[10px] font-mono text-sawlah-muted">{es.query}</p>
                      <button onClick={() => navigate("/exploit")}
                        className="text-[9px] text-sawlah-red hover:underline mt-1 flex items-center gap-1">
                        <ExternalLink className="w-2.5 h-2.5" /> View in Exploit Search
                      </button>
                    </div>
                  ))}
                </div>
              )}
              {autoExploitResults?.error && (
                <p className="text-xs text-sawlah-red mt-2">{autoExploitResults.error}</p>
              )}
            </div>
          </div>
        </div>

        {/* Scan Results */}
        <div className="lg:col-span-8">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4" /> Scan Results
            <span className="text-[10px] bg-sawlah-surface px-1.5 py-0.5 rounded-full ml-1">{taskEntries.length}</span>
            {runningTasks.length > 0 && (
              <span className="flex items-center gap-1 text-[10px] text-sawlah-yellow ml-auto">
                <span className="w-1.5 h-1.5 rounded-full bg-sawlah-yellow animate-pulse" />
                {runningTasks.length} running
              </span>
            )}
          </h2>
          <div className="space-y-1 max-h-[600px] overflow-y-auto">
            {taskEntries.length === 0 && (
              <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-8 text-center">
                <Terminal className="w-8 h-8 text-sawlah-dim/20 mx-auto mb-2" />
                <p className="text-sawlah-dim text-sm">No scans yet. Use Quick Launch or tool pages to start.</p>
              </div>
            )}
            {taskEntries.map(([id, t]) => {
              const isExpanded = expandedTask === id;
              const toolPage = TOOL_PAGES[t.tool_name];
              const isNmapDone = t.tool_name === "nmap" && t.status === "completed";
              return (
                <div key={id} className={`bg-sawlah-card border rounded-xl overflow-hidden transition-colors ${
                  t.status === "running" ? "border-sawlah-yellow/30" :
                  t.status === "error" ? "border-red-500/30" : "border-sawlah-border"
                }`}>
                  <button onClick={() => setExpandedTask(isExpanded ? null : id)}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors text-left">
                    {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-sawlah-dim shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-sawlah-dim shrink-0" />}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-xs font-mono text-sawlah-red">{id}</span>
                        {t.tool_name && (
                          <span className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted bg-sawlah-surface px-1.5 py-0.5 rounded">{t.tool_name}</span>
                        )}
                        <StatusBadge status={t.status} />
                      </div>
                      <p className="text-[11px] font-mono text-sawlah-dim truncate">{t.command}</p>
                      {t.started_at && (
                        <p className="text-[10px] text-sawlah-dim/60 flex items-center gap-1 mt-0.5">
                          <Clock className="w-2.5 h-2.5" />
                          {new Date(t.started_at).toLocaleString()}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {isNmapDone && (
                        <button onClick={(e) => { e.stopPropagation(); runAutoExploit(id); }}
                          className="p-1.5 hover:bg-yellow-500/20 rounded text-sawlah-dim hover:text-sawlah-yellow transition-colors" title="Auto-search exploits">
                          <Zap className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {toolPage && (
                        <button onClick={(e) => { e.stopPropagation(); navigate(toolPage); }}
                          className="p-1.5 hover:bg-sawlah-red/20 rounded text-sawlah-dim hover:text-sawlah-red transition-colors shrink-0" title="Open tool page">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </button>
                  {isExpanded && (
                    <div className="px-4 pb-3 border-t border-sawlah-border">
                      <div className="flex items-center justify-between py-2">
                        <span className="text-[10px] text-sawlah-dim font-mono">{(t.output || "").split("\n").length} lines</span>
                        <button onClick={() => copyOutput(t.output || "")}
                          className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors">
                          {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                          {copied ? "Copied" : "Copy"}
                        </button>
                      </div>
                      <div className="font-mono text-xs leading-relaxed p-3 rounded-lg overflow-y-auto" style={{ maxHeight: 300, background: "#050505" }}>
                        {(t.output || "No output").split("\n").map((line, i) => (
                          <div key={i} className="flex hover:bg-white/[0.02] -mx-1 px-1 rounded">
                            <span className="text-sawlah-dim/40 select-none w-8 text-right mr-3 shrink-0">{i + 1}</span>
                            <span className={`whitespace-pre-wrap break-all ${
                              /\[\+\]|open|SUCCESS/i.test(line) ? "text-sawlah-green" :
                              /\[-\]|ERROR|error|FAIL/i.test(line) ? "text-sawlah-red" :
                              /\[\*\]|\[!\]|WARNING/i.test(line) ? "text-sawlah-yellow" :
                              /VULNERABLE|CRITICAL/i.test(line) ? "text-sawlah-red font-bold" :
                              "text-zinc-300"
                            }`}>{line || "\u00A0"}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
