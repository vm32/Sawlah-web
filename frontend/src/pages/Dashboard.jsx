import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Plus, Radar, Database, Globe, SearchCode,
  Network, Server, Bug, Key, Workflow, Activity, FolderOpen, Trash2,
  ChevronDown, ChevronRight, Copy, Check, ExternalLink, Clock
} from "lucide-react";
import { projectsApi, toolsApi } from "../api/client";
import StatusBadge from "../components/StatusBadge";

const QUICK_TOOLS = [
  { icon: Radar, label: "Nmap", path: "/nmap", color: "text-red-400" },
  { icon: Database, label: "SQLMap", path: "/sqlmap", color: "text-orange-400" },
  { icon: Globe, label: "Sub Enum", path: "/subenum", color: "text-blue-400" },
  { icon: SearchCode, label: "Web Scan", path: "/webscan", color: "text-green-400" },
  { icon: Network, label: "NetExec", path: "/nxc", color: "text-purple-400" },
  { icon: Server, label: "Enum", path: "/enum", color: "text-cyan-400" },
  { icon: Bug, label: "Exploits", path: "/exploit", color: "text-yellow-400" },
  { icon: Key, label: "Passwords", path: "/password", color: "text-pink-400" },
  { icon: Workflow, label: "Automation", path: "/automation", color: "text-emerald-400" },
];

const TOOL_PAGES = {
  nmap: "/nmap", sqlmap: "/sqlmap", amass: "/subenum", gobuster_dns: "/subenum",
  dnsenum: "/subenum", nikto: "/webscan", dirb: "/webscan", gobuster_dir: "/webscan",
  ffuf: "/webscan", whatweb: "/webscan", wfuzz: "/webscan", nxc: "/nxc",
  enum4linux: "/enum", smbclient: "/enum", whois: "/enum", dig: "/enum",
  searchsploit: "/exploit", hydra: "/password", john: "/password", hashcat: "/password",
};

export default function Dashboard({ setOutput, setTitle }) {
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [tasks, setTasks] = useState({});
  const [showNewProject, setShowNewProject] = useState(false);
  const [newName, setNewName] = useState("");
  const [newTarget, setNewTarget] = useState("");
  const [newScope, setNewScope] = useState("");
  const [expandedTask, setExpandedTask] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => { setTitle("Dashboard"); }, [setTitle]);

  const loadData = () => {
    projectsApi.list().then((res) => setProjects(res.data)).catch(() => {});
    toolsApi.list().then((res) => setTasks(res.data)).catch(() => {});
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const createProject = async () => {
    if (!newName.trim() || !newTarget.trim()) return;
    await projectsApi.create({ name: newName, target: newTarget, scope: newScope });
    setNewName(""); setNewTarget(""); setNewScope("");
    setShowNewProject(false);
    loadData();
  };

  const deleteProject = async (id) => {
    await projectsApi.delete(id);
    loadData();
  };

  const copyOutput = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const taskEntries = Object.entries(tasks).sort(
    ([, a], [, b]) => (b.started_at || "").localeCompare(a.started_at || "")
  );
  const runningTasks = taskEntries.filter(([, t]) => t.status === "running");
  const completedTasks = taskEntries.filter(([, t]) => t.status === "completed");

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="w-6 h-6 text-sawlah-red" />
          <div>
            <h1 className="text-2xl font-bold text-sawlah-text">Dashboard</h1>
            <p className="text-sm text-sawlah-muted">Sawlah-web Penetration Testing Framework</p>
          </div>
        </div>
        <button
          onClick={() => setShowNewProject(true)}
          className="flex items-center gap-2 px-4 py-2 bg-sawlah-red text-white rounded-lg text-sm font-medium hover:bg-sawlah-red-hover transition-colors"
        >
          <Plus className="w-4 h-4" /> New Project
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Projects", value: projects.length, color: "text-sawlah-red" },
          { label: "Running", value: runningTasks.length, color: "text-sawlah-yellow" },
          { label: "Completed", value: completedTasks.length, color: "text-sawlah-green" },
          { label: "Total Tasks", value: taskEntries.length, color: "text-sawlah-muted" },
        ].map((stat) => (
          <div key={stat.label} className="bg-sawlah-card border border-sawlah-border rounded-xl p-4">
            <p className={`text-3xl font-bold ${stat.color}`}>{stat.value}</p>
            <p className="text-xs text-sawlah-dim uppercase tracking-wider mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Quick Launch */}
      <div className="mb-6">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-sawlah-muted mb-3">Quick Launch</h2>
        <div className="grid grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2">
          {QUICK_TOOLS.map((tool) => (
            <button
              key={tool.path}
              onClick={() => navigate(tool.path)}
              className="flex flex-col items-center gap-2 p-3 bg-sawlah-card border border-sawlah-border rounded-xl hover:border-sawlah-red/40 hover:bg-sawlah-red/5 transition-all group"
            >
              <tool.icon className={`w-5 h-5 ${tool.color} group-hover:scale-110 transition-transform`} />
              <span className="text-[11px] text-sawlah-muted group-hover:text-sawlah-text transition-colors">{tool.label}</span>
            </button>
          ))}
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Projects */}
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-sawlah-muted mb-3 flex items-center gap-2">
            <FolderOpen className="w-4 h-4" /> Projects
          </h2>
          <div className="space-y-2">
            {projects.length === 0 && (
              <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-8 text-center">
                <p className="text-sawlah-dim text-sm">No projects yet. Create one to get started.</p>
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

        {/* All Scan Results */}
        <div className="lg:col-span-2">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-sawlah-muted mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4" /> Scan Results
            <span className="text-[10px] bg-sawlah-surface px-1.5 py-0.5 rounded-full ml-1">{taskEntries.length}</span>
          </h2>
          <div className="space-y-1">
            {taskEntries.length === 0 && (
              <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-8 text-center">
                <p className="text-sawlah-dim text-sm">No tasks yet. Run a tool to see activity here.</p>
              </div>
            )}
            {taskEntries.map(([id, t]) => {
              const isExpanded = expandedTask === id;
              const toolPage = TOOL_PAGES[t.tool_name];
              return (
                <div key={id} className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
                  <button
                    onClick={() => setExpandedTask(isExpanded ? null : id)}
                    className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors text-left"
                  >
                    {isExpanded
                      ? <ChevronDown className="w-3.5 h-3.5 text-sawlah-dim shrink-0" />
                      : <ChevronRight className="w-3.5 h-3.5 text-sawlah-dim shrink-0" />
                    }
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-xs font-mono text-sawlah-red">{id}</span>
                        {t.tool_name && (
                          <span className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted bg-sawlah-surface px-1.5 py-0.5 rounded">
                            {t.tool_name}
                          </span>
                        )}
                        <StatusBadge status={t.status} />
                      </div>
                      <p className="text-[11px] font-mono text-sawlah-dim truncate">{t.command}</p>
                      {t.started_at && (
                        <p className="text-[10px] text-sawlah-dim/60 flex items-center gap-1 mt-0.5">
                          <Clock className="w-2.5 h-2.5" />
                          {new Date(t.started_at).toLocaleString()}
                          {t.finished_at && ` - ${new Date(t.finished_at).toLocaleString()}`}
                        </p>
                      )}
                    </div>
                    {toolPage && (
                      <button
                        onClick={(e) => { e.stopPropagation(); navigate(toolPage); }}
                        className="p-1.5 hover:bg-sawlah-red/20 rounded text-sawlah-dim hover:text-sawlah-red transition-colors shrink-0"
                        title="Open tool page"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </button>

                  {isExpanded && (
                    <div className="px-4 pb-3 border-t border-sawlah-border">
                      <div className="flex items-center justify-between py-2">
                        <span className="text-[10px] text-sawlah-dim font-mono">
                          {(t.output || "").split("\n").length} lines
                        </span>
                        <button
                          onClick={() => copyOutput(t.output || "")}
                          className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors"
                        >
                          {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                          {copied ? "Copied" : "Copy Output"}
                        </button>
                      </div>
                      <div
                        className="font-mono text-xs leading-relaxed p-3 rounded-lg overflow-y-auto"
                        style={{ maxHeight: 300, background: "#050505" }}
                      >
                        {(t.output || "No output").split("\n").map((line, i) => (
                          <div key={i} className="flex hover:bg-white/[0.02] -mx-1 px-1 rounded">
                            <span className="text-sawlah-dim/40 select-none w-8 text-right mr-3 shrink-0">{i + 1}</span>
                            <span className={`whitespace-pre-wrap break-all ${
                              line.includes("[+]") || line.includes("open") ? "text-sawlah-green" :
                              line.includes("[-]") || line.includes("ERROR") || line.includes("error") ? "text-sawlah-red" :
                              line.includes("[*]") || line.includes("[!]") ? "text-sawlah-yellow" :
                              line.includes("VULNERABLE") || line.includes("CRITICAL") ? "text-sawlah-red font-bold" :
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
