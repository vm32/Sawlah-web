import { useState, useEffect, useRef, useCallback } from "react";
import {
  Workflow, Play, Square, Plus, Trash2, GripVertical, ChevronDown,
  ChevronRight, ArrowDown, Zap, Settings2, Loader2, CheckCircle2,
  XCircle, Clock, Pencil, RotateCcw
} from "lucide-react";
import { automationApi, projectsApi, toolsApi } from "../api/client";
import { PageHeader, FormField, TextInput, SelectInput } from "../components/ToolForm";
import StatusBadge from "../components/StatusBadge";

const BLOCK_CATALOG = [
  { id: "nmap_quick", category: "Recon", label: "Nmap Quick Scan", tool: "nmap", icon: "radar", color: "#ef4444",
    params: { scan_type: "quick" }, cmdPreview: "nmap -T4 -F {target}" },
  { id: "nmap_full", category: "Recon", label: "Nmap Full TCP", tool: "nmap", icon: "radar", color: "#ef4444",
    params: { scan_type: "full_tcp" }, cmdPreview: "nmap -p- -T4 {target}" },
  { id: "nmap_service", category: "Recon", label: "Nmap Service Detect", tool: "nmap", icon: "radar", color: "#ef4444",
    params: { scan_type: "service" }, cmdPreview: "nmap -sV -T4 {target}" },
  { id: "nmap_vuln", category: "Recon", label: "Nmap Vuln Scripts", tool: "nmap", icon: "radar", color: "#ef4444",
    params: { scan_type: "vuln" }, cmdPreview: "nmap --script vuln -sV {target}" },
  { id: "nmap_os", category: "Recon", label: "Nmap OS Detection", tool: "nmap", icon: "radar", color: "#ef4444",
    params: { scan_type: "os" }, cmdPreview: "nmap -O -T4 {target}" },
  { id: "whatweb", category: "Web", label: "WhatWeb", tool: "whatweb", icon: "search", color: "#22c55e",
    params: {}, cmdPreview: "whatweb {target}" },
  { id: "nikto", category: "Web", label: "Nikto Scanner", tool: "nikto", icon: "search", color: "#22c55e",
    params: {}, cmdPreview: "nikto -h {target}" },
  { id: "gobuster_dir", category: "Web", label: "Gobuster Dir", tool: "gobuster_dir", icon: "search", color: "#22c55e",
    params: { wordlist: "/usr/share/wordlists/dirb/common.txt" }, cmdPreview: "gobuster dir -u {target} -w common.txt" },
  { id: "ffuf", category: "Web", label: "FFUF Fuzzer", tool: "ffuf", icon: "search", color: "#22c55e",
    params: { wordlist: "/usr/share/wordlists/dirb/common.txt" }, cmdPreview: "ffuf -u {target}/FUZZ -w common.txt" },
  { id: "nxc_smb", category: "Enum", label: "NXC SMB Enum", tool: "nxc", icon: "network", color: "#a855f7",
    params: { protocol: "smb", shares: true, users: true }, cmdPreview: "nxc smb {target} --shares --users" },
  { id: "nxc_ldap", category: "Enum", label: "NXC LDAP", tool: "nxc", icon: "network", color: "#a855f7",
    params: { protocol: "ldap" }, cmdPreview: "nxc ldap {target}" },
  { id: "enum4linux", category: "Enum", label: "Enum4linux", tool: "enum4linux", icon: "server", color: "#a855f7",
    params: { all: true }, cmdPreview: "enum4linux -a {target}" },
  { id: "sqlmap", category: "Exploit", label: "SQLMap", tool: "sqlmap", icon: "database", color: "#f97316",
    params: { level: 2, risk: 2 }, cmdPreview: "sqlmap -u {target} --batch --level 2" },
  { id: "searchsploit", category: "Exploit", label: "SearchSploit", tool: "searchsploit", icon: "bug", color: "#f97316",
    params: {}, cmdPreview: "searchsploit {query}" },
  { id: "hydra_ssh", category: "Brute", label: "Hydra SSH", tool: "hydra", icon: "key", color: "#ec4899",
    params: { service: "ssh", passlist: "/usr/share/wordlists/rockyou.txt" }, cmdPreview: "hydra -P rockyou.txt {target} ssh" },
  { id: "wafw00f", category: "WAF/SSL", label: "WAF Detection", tool: "wafw00f", icon: "shield", color: "#06b6d4",
    params: { all_waf: true }, cmdPreview: "wafw00f -a {target}" },
  { id: "sslscan", category: "WAF/SSL", label: "SSL/TLS Scan", tool: "sslscan", icon: "lock", color: "#06b6d4",
    params: {}, cmdPreview: "sslscan {target}" },
  { id: "whois", category: "Recon", label: "WHOIS Lookup", tool: "whois", icon: "info", color: "#ef4444",
    params: {}, cmdPreview: "whois {target}" },
  { id: "dig", category: "Recon", label: "DNS Records", tool: "dig", icon: "info", color: "#ef4444",
    params: { record_type: "ANY" }, cmdPreview: "dig {target} ANY" },
  { id: "dnsrecon", category: "Recon", label: "DNSRecon", tool: "dnsrecon", icon: "radar", color: "#ef4444",
    params: {}, cmdPreview: "dnsrecon -d {target}" },
  { id: "theHarvester", category: "Recon", label: "theHarvester", tool: "theHarvester", icon: "radar", color: "#ef4444",
    params: { source: "all", limit: 200 }, cmdPreview: "theHarvester -d {target} -b all" },
  { id: "fierce", category: "Recon", label: "Fierce DNS", tool: "fierce", icon: "radar", color: "#ef4444",
    params: {}, cmdPreview: "fierce --domain {target}" },
  { id: "gobuster_dns", category: "Recon", label: "Gobuster DNS", tool: "gobuster_dns", icon: "radar", color: "#ef4444",
    params: { wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" }, cmdPreview: "gobuster dns --do {target}" },
  { id: "wpscan", category: "Web", label: "WPScan", tool: "wpscan", icon: "search", color: "#22c55e",
    params: {}, cmdPreview: "wpscan --url {target}" },
  { id: "generate_report", category: "Report", label: "Generate Report", tool: "generate_report", icon: "file", color: "#64748b",
    params: {}, cmdPreview: "Generate pentest report from all scan data" },
];

const CATEGORIES = [...new Set(BLOCK_CATALOG.map((b) => b.category))];

const CATEGORY_COLORS = {
  Recon: "border-red-500/40 bg-red-500/5",
  Web: "border-green-500/40 bg-green-500/5",
  Enum: "border-purple-500/40 bg-purple-500/5",
  Exploit: "border-orange-500/40 bg-orange-500/5",
  Brute: "border-pink-500/40 bg-pink-500/5",
  "WAF/SSL": "border-cyan-500/40 bg-cyan-500/5",
  Report: "border-slate-500/40 bg-slate-500/5",
};

const STATUS_ICONS = {
  pending: Clock,
  running: Loader2,
  completed: CheckCircle2,
  error: XCircle,
};

export default function Automation({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [projects, setProjects] = useState([]);
  const [projectId, setProjectId] = useState("");
  const [pipeline, setPipeline] = useState([]);
  const [dragOver, setDragOver] = useState(null);
  const [editingBlock, setEditingBlock] = useState(null);
  const [pipelineId, setPipelineId] = useState(null);
  const [pipelineStatus, setPipelineStatus] = useState(null);
  const [running, setRunning] = useState(false);
  const [expandedOutput, setExpandedOutput] = useState(null);
  const [catalogFilter, setCatalogFilter] = useState("All");

  useEffect(() => { setTitle("Automation Pipeline"); }, [setTitle]);

  useEffect(() => {
    projectsApi.list().then((res) => setProjects(res.data)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!pipelineId) return;
    const interval = setInterval(async () => {
      try {
        const res = await automationApi.status(pipelineId);
        setPipelineStatus(res.data);
        if (["completed", "error"].includes(res.data.status)) {
          setRunning(false);
          clearInterval(interval);
        }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [pipelineId]);

  const addBlock = (catalogItem) => {
    setPipeline([
      ...pipeline,
      {
        uid: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        ...catalogItem,
        customCmd: "",
        status: "pending",
        output: "",
        taskId: null,
      },
    ]);
  };

  const removeBlock = (uid) => {
    setPipeline(pipeline.filter((b) => b.uid !== uid));
  };

  const moveBlock = (fromIdx, toIdx) => {
    const updated = [...pipeline];
    const [moved] = updated.splice(fromIdx, 1);
    updated.splice(toIdx, 0, moved);
    setPipeline(updated);
  };

  const updateBlockCmd = (uid, cmd) => {
    setPipeline(pipeline.map((b) => (b.uid === uid ? { ...b, customCmd: cmd } : b)));
  };

  const handleDragStart = (e, idx) => {
    e.dataTransfer.setData("pipeline-idx", String(idx));
    e.dataTransfer.effectAllowed = "move";
  };

  const handleCatalogDragStart = (e, item) => {
    e.dataTransfer.setData("catalog-item", JSON.stringify(item));
    e.dataTransfer.effectAllowed = "copy";
  };

  const handleDrop = (e, toIdx) => {
    e.preventDefault();
    setDragOver(null);

    const pipelineIdx = e.dataTransfer.getData("pipeline-idx");
    if (pipelineIdx !== "") {
      moveBlock(parseInt(pipelineIdx), toIdx);
      return;
    }

    const catalogData = e.dataTransfer.getData("catalog-item");
    if (catalogData) {
      const item = JSON.parse(catalogData);
      const newBlock = {
        uid: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        ...item,
        customCmd: "",
        status: "pending",
        output: "",
        taskId: null,
      };
      const updated = [...pipeline];
      updated.splice(toIdx, 0, newBlock);
      setPipeline(updated);
    }
  };

  const handleDropEnd = (e) => {
    e.preventDefault();
    setDragOver(null);
    const catalogData = e.dataTransfer.getData("catalog-item");
    if (catalogData) {
      addBlock(JSON.parse(catalogData));
    }
  };

  const handleRunPipeline = async () => {
    if (!target.trim() || pipeline.length === 0) return;
    setRunning(true);
    setOutput("");
    setPipeline(pipeline.map((b) => ({ ...b, status: "pending", output: "", taskId: null })));

    const stages = pipeline.map((b) => ({
      tool_name: b.tool,
      params: { ...b.params, target: target.trim() },
    }));

    try {
      const res = await automationApi.run({
        project_id: parseInt(projectId) || 0,
        target: target.trim(),
        stages,
      });
      setPipelineId(res.data.pipeline_id);
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
      setRunning(false);
    }
  };

  const resetPipeline = () => {
    setPipeline(pipeline.map((b) => ({ ...b, status: "pending", output: "", taskId: null })));
    setPipelineStatus(null);
    setPipelineId(null);
    setRunning(false);
  };

  useEffect(() => {
    if (!pipelineStatus?.stages) return;
    setPipeline((prev) =>
      prev.map((block, idx) => {
        const stage = pipelineStatus.stages[idx];
        if (!stage) return block;
        return { ...block, status: stage.status, taskId: stage.task_id };
      })
    );
  }, [pipelineStatus]);

  useEffect(() => {
    if (!pipelineStatus?.stages) return;
    const outputParts = [];
    pipelineStatus.stages.forEach((s, i) => {
      outputParts.push(`\n--- [Stage ${i + 1}: ${s.tool}] (${s.status}) ---\n`);
      if (s.task_id) {
        const task = pipelineStatus.stages[i];
        if (task) outputParts.push(`Task: ${s.task_id}\n`);
      }
    });
    setOutput(outputParts.join(""));
  }, [pipelineStatus, setOutput]);

  const filteredCatalog = catalogFilter === "All"
    ? BLOCK_CATALOG
    : BLOCK_CATALOG.filter((b) => b.category === catalogFilter);

  const completedCount = pipeline.filter((b) => b.status === "completed").length;
  const progress = pipeline.length > 0 ? (completedCount / pipeline.length) * 100 : 0;

  return (
    <div>
      <PageHeader title="Automation Pipeline" description="Drag and drop blocks to build your pentest workflow" icon={Workflow} />

      <div className="grid grid-cols-12 gap-4 mb-4">
        {/* Block Catalog */}
        <div className="col-span-3 bg-sawlah-card border border-sawlah-border rounded-xl p-4 max-h-[700px] overflow-y-auto">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3">Tool Blocks</h3>
          <div className="flex flex-wrap gap-1 mb-3">
            {["All", ...CATEGORIES].map((cat) => (
              <button
                key={cat}
                onClick={() => setCatalogFilter(cat)}
                className={`px-2 py-0.5 text-[10px] rounded-full font-medium transition-colors ${
                  catalogFilter === cat
                    ? "bg-sawlah-red text-white"
                    : "bg-sawlah-surface text-sawlah-dim hover:text-sawlah-muted"
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
          <div className="space-y-1.5">
            {filteredCatalog.map((item) => (
              <div
                key={item.id}
                draggable
                onDragStart={(e) => handleCatalogDragStart(e, item)}
                className={`flex items-center gap-2 p-2.5 rounded-lg border cursor-grab active:cursor-grabbing
                  hover:scale-[1.02] transition-all ${CATEGORY_COLORS[item.category] || "border-sawlah-border bg-sawlah-surface"}`}
              >
                <GripVertical className="w-3 h-3 text-sawlah-dim/50 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-sawlah-text truncate">{item.label}</p>
                  <p className="text-[9px] font-mono text-sawlah-dim truncate">{item.cmdPreview}</p>
                </div>
                <button
                  onClick={() => addBlock(item)}
                  className="p-1 hover:bg-white/10 rounded text-sawlah-dim hover:text-sawlah-green transition-colors shrink-0"
                >
                  <Plus className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Pipeline Builder */}
        <div className="col-span-6">
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 mb-4">
            <div className="grid grid-cols-2 gap-4 mb-4">
              <FormField label="Target">
                <TextInput value={target} onChange={setTarget} placeholder="192.168.1.1 or http://target.com" />
              </FormField>
              <FormField label="Project">
                <SelectInput value={projectId} onChange={setProjectId}
                  options={[{ value: "", label: "No Project" }, ...projects.map((p) => ({ value: String(p.id), label: p.name }))]} />
              </FormField>
            </div>
            <div className="flex items-center gap-2">
              {!running ? (
                <button
                  onClick={handleRunPipeline}
                  disabled={pipeline.length === 0 || !target.trim()}
                  className="flex items-center gap-2 px-5 py-2.5 bg-sawlah-red text-white rounded-lg font-semibold text-sm
                    hover:bg-sawlah-red-hover transition-colors shadow-lg shadow-sawlah-red-glow
                    disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
                >
                  <Zap className="w-4 h-4" /> Run Pipeline ({pipeline.length} stages)
                </button>
              ) : (
                <button
                  onClick={() => setRunning(false)}
                  className="flex items-center gap-2 px-5 py-2.5 bg-sawlah-red-hover text-white rounded-lg font-semibold text-sm"
                >
                  <Square className="w-4 h-4" /> Stop
                </button>
              )}
              <button
                onClick={resetPipeline}
                className="flex items-center gap-2 px-3 py-2.5 text-sawlah-dim hover:text-sawlah-muted transition-colors text-sm"
              >
                <RotateCcw className="w-4 h-4" /> Reset
              </button>
            </div>
          </div>

          {/* Progress bar */}
          {running && (
            <div className="mb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] uppercase tracking-wider text-sawlah-muted font-semibold">Progress</span>
                <span className="text-[10px] text-sawlah-dim">{completedCount}/{pipeline.length}</span>
              </div>
              <div className="h-2 bg-sawlah-surface rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-sawlah-red to-red-400 rounded-full transition-all duration-700 ease-out"
                  style={{ width: `${progress}%` }}
                >
                  <div className="h-full w-full bg-white/20 animate-pulse rounded-full" />
                </div>
              </div>
            </div>
          )}

          {/* Pipeline blocks */}
          <div
            className="space-y-0 min-h-[200px]"
            onDragOver={(e) => { e.preventDefault(); setDragOver("end"); }}
            onDragLeave={() => setDragOver(null)}
            onDrop={handleDropEnd}
          >
            {pipeline.length === 0 && (
              <div
                className={`flex flex-col items-center justify-center py-16 border-2 border-dashed rounded-xl transition-colors ${
                  dragOver === "end" ? "border-sawlah-red bg-sawlah-red/5" : "border-sawlah-border"
                }`}
              >
                <Workflow className="w-10 h-10 text-sawlah-dim/20 mb-3" />
                <p className="text-sm text-sawlah-dim">Drag blocks here to build your pipeline</p>
                <p className="text-[11px] text-sawlah-dim/60 mt-1">Or click + on any block in the catalog</p>
              </div>
            )}

            {pipeline.map((block, idx) => {
              const StatusIcon = STATUS_ICONS[block.status] || Clock;
              const isActive = block.status === "running";
              const isDone = block.status === "completed";
              const isErr = block.status === "error";

              return (
                <div key={block.uid}>
                  {/* Drop zone between blocks */}
                  <div
                    className={`h-2 -my-1 rounded transition-all ${
                      dragOver === idx ? "h-12 bg-sawlah-red/10 border-2 border-dashed border-sawlah-red my-1" : ""
                    }`}
                    onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); setDragOver(idx); }}
                    onDragLeave={(e) => { e.stopPropagation(); setDragOver(null); }}
                    onDrop={(e) => { e.stopPropagation(); handleDrop(e, idx); }}
                  />

                  {/* Connector arrow */}
                  {idx > 0 && (
                    <div className="flex justify-center -my-1 relative z-10">
                      <div className={`w-0.5 h-6 ${isDone || isActive ? "bg-sawlah-red" : "bg-sawlah-border"}`} />
                      <ArrowDown className={`w-4 h-4 absolute bottom-0 ${
                        isDone ? "text-sawlah-green" : isActive ? "text-sawlah-red animate-bounce" : "text-sawlah-border"
                      }`} />
                    </div>
                  )}

                  {/* Block */}
                  <div
                    draggable
                    onDragStart={(e) => handleDragStart(e, idx)}
                    className={`relative border rounded-xl overflow-hidden transition-all ${
                      isActive ? "border-sawlah-red shadow-lg shadow-sawlah-red-glow ring-1 ring-sawlah-red/30" :
                      isDone ? "border-green-500/40" :
                      isErr ? "border-red-500/40" :
                      "border-sawlah-border hover:border-sawlah-border/60"
                    } ${CATEGORY_COLORS[block.category] || "bg-sawlah-card"}`}
                  >
                    {/* Running shimmer */}
                    {isActive && (
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-sawlah-red/5 to-transparent animate-shimmer" />
                    )}

                    <div className="relative flex items-center gap-3 px-4 py-3">
                      <div className="cursor-grab active:cursor-grabbing">
                        <GripVertical className="w-4 h-4 text-sawlah-dim/40" />
                      </div>

                      <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-black/20">
                        <span className="text-sm font-bold text-sawlah-muted">{idx + 1}</span>
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-sawlah-text">{block.label}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-black/20 text-sawlah-dim uppercase tracking-wider">{block.category}</span>
                        </div>
                        <p className="text-[10px] font-mono text-sawlah-dim mt-0.5 truncate">
                          {block.customCmd || block.cmdPreview?.replace("{target}", target || "{target}")}
                        </p>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <StatusIcon className={`w-4 h-4 ${
                          isActive ? "text-sawlah-yellow animate-spin" :
                          isDone ? "text-sawlah-green" :
                          isErr ? "text-sawlah-red" :
                          "text-sawlah-dim"
                        }`} />
                        <button
                          onClick={() => setEditingBlock(editingBlock === block.uid ? null : block.uid)}
                          className="p-1 hover:bg-white/10 rounded text-sawlah-dim hover:text-sawlah-muted transition-colors"
                        >
                          <Settings2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => removeBlock(block.uid)}
                          className="p-1 hover:bg-red-500/20 rounded text-sawlah-dim hover:text-sawlah-red transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Edit panel */}
                    {editingBlock === block.uid && (
                      <div className="px-4 pb-3 border-t border-sawlah-border/50 bg-black/10">
                        <div className="pt-3">
                          <label className="block text-[10px] uppercase tracking-wider text-sawlah-dim font-semibold mb-1">
                            <Pencil className="w-3 h-3 inline mr-1" />Custom Command Override
                          </label>
                          <div className="flex items-center bg-black/30 border border-sawlah-border rounded-lg overflow-hidden">
                            <span className="text-sawlah-red font-mono text-xs pl-3 select-none">$</span>
                            <input
                              value={block.customCmd}
                              onChange={(e) => updateBlockCmd(block.uid, e.target.value)}
                              placeholder={block.cmdPreview?.replace("{target}", target || "TARGET")}
                              className="flex-1 bg-transparent border-0 font-mono text-xs px-2 py-2 text-sawlah-green placeholder:text-sawlah-dim/30 focus:outline-none"
                            />
                          </div>
                          <p className="text-[9px] text-sawlah-dim/60 mt-1">Leave empty to use default command with GUI params</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {/* Drop zone at end */}
            {pipeline.length > 0 && (
              <div
                className={`h-2 rounded transition-all ${
                  dragOver === "end" ? "h-12 bg-sawlah-red/10 border-2 border-dashed border-sawlah-red mt-2" : "mt-1"
                }`}
                onDragOver={(e) => { e.preventDefault(); setDragOver("end"); }}
                onDragLeave={() => setDragOver(null)}
                onDrop={handleDropEnd}
              />
            )}
          </div>
        </div>

        {/* Status Panel */}
        <div className="col-span-3 space-y-4">
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3">Pipeline Status</h3>
            {!pipelineStatus && !running && (
              <p className="text-xs text-sawlah-dim">Build your pipeline and click Run</p>
            )}
            {(pipelineStatus || running) && (
              <div className="space-y-2">
                <StatusBadge status={pipelineStatus?.status || "running"} />
                {pipelineStatus?.current_stage && (
                  <p className="text-xs text-sawlah-muted">
                    Stage {pipelineStatus.current_stage} / {pipelineStatus.total_stages}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Stage outputs */}
          {pipelineStatus?.stages?.length > 0 && (
            <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-3">Stage Results</h3>
              <div className="space-y-1.5">
                {pipelineStatus.stages.map((s, i) => (
                  <div key={i} className="border border-sawlah-border rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedOutput(expandedOutput === i ? null : i)}
                      className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.02] text-left text-xs"
                    >
                      {expandedOutput === i ? <ChevronDown className="w-3 h-3 text-sawlah-dim" /> : <ChevronRight className="w-3 h-3 text-sawlah-dim" />}
                      <span className="font-mono text-sawlah-red w-4">{i + 1}</span>
                      <span className="flex-1 text-sawlah-text truncate">{s.tool}</span>
                      <StatusBadge status={s.status} />
                    </button>
                    {expandedOutput === i && s.task_id && (
                      <StageOutput taskId={s.task_id} />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StageOutput({ taskId }) {
  const [output, setOutput] = useState("Loading...");

  useEffect(() => {
    toolsApi.status(taskId).then((res) => {
      setOutput(res.data.output || "No output");
    }).catch(() => setOutput("Failed to load output"));
  }, [taskId]);

  return (
    <div className="px-3 pb-2 border-t border-sawlah-border/50">
      <div className="font-mono text-[10px] leading-relaxed p-2 rounded bg-black/30 max-h-[150px] overflow-y-auto mt-2">
        {output.split("\n").slice(0, 50).map((line, i) => (
          <div key={i} className={`${
            /\[\+\]|open|SUCCESS/i.test(line) ? "text-sawlah-green" :
            /\[-\]|ERROR/i.test(line) ? "text-sawlah-red" :
            /\[\*\]|\[!\]/i.test(line) ? "text-sawlah-yellow" :
            "text-zinc-400"
          }`}>{line || "\u00A0"}</div>
        ))}
      </div>
    </div>
  );
}
