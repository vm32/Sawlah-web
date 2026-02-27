import { useState, useEffect } from "react";
import { Workflow, Play, Plus, Trash2, ChevronRight } from "lucide-react";
import { automationApi, projectsApi } from "../api/client";
import { PageHeader, FormField, TextInput, SelectInput, RunButton } from "../components/ToolForm";
import StatusBadge from "../components/StatusBadge";

const AVAILABLE_TOOLS = [
  { value: "nmap", label: "Nmap", defaultParams: { scan_type: "quick" } },
  { value: "nmap_service", label: "Nmap Service Detection", defaultParams: { scan_type: "service" } },
  { value: "nmap_vuln", label: "Nmap Vuln Scripts", defaultParams: { scan_type: "vuln" } },
  { value: "whatweb", label: "WhatWeb", defaultParams: {} },
  { value: "nikto", label: "Nikto", defaultParams: {} },
  { value: "gobuster_dir", label: "Gobuster Dir", defaultParams: { wordlist: "/usr/share/wordlists/dirb/common.txt" } },
  { value: "ffuf", label: "FFUF", defaultParams: { wordlist: "/usr/share/wordlists/dirb/common.txt" } },
  { value: "nxc", label: "NetExec SMB", defaultParams: { protocol: "smb", shares: true, users: true } },
  { value: "enum4linux", label: "Enum4linux", defaultParams: { all: true } },
  { value: "searchsploit", label: "SearchSploit", defaultParams: {} },
];

const QUICK_MODES = [
  { value: "full", label: "Full Auto (Recon → Enum → Web → Vuln)" },
  { value: "recon", label: "Recon Only (Nmap scans)" },
  { value: "enum", label: "Enum Only (NXC + Enum4linux)" },
  { value: "web", label: "Web Only (WhatWeb + Nikto)" },
  { value: "vuln", label: "Vuln Scan (Nmap vuln scripts)" },
];

export default function Automation({ setOutput, setTitle }) {
  const [mode, setMode] = useState("quick");
  const [target, setTarget] = useState("");
  const [quickMode, setQuickMode] = useState("full");
  const [stages, setStages] = useState([]);
  const [projects, setProjects] = useState([]);
  const [projectId, setProjectId] = useState("");
  const [pipelineId, setPipelineId] = useState(null);
  const [pipelineStatus, setPipelineStatus] = useState(null);
  const [running, setRunning] = useState(false);

  useEffect(() => { setTitle("Automation"); }, [setTitle]);

  useEffect(() => {
    projectsApi.list().then((res) => setProjects(res.data)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!pipelineId) return;
    const interval = setInterval(async () => {
      try {
        const res = await automationApi.status(pipelineId);
        setPipelineStatus(res.data);
        if (res.data.stages) {
          const output = res.data.stages
            .map((s, i) => `[Stage ${i + 1}] ${s.tool} - ${s.status}${s.task_id ? ` (${s.task_id})` : ""}`)
            .join("\n");
          setOutput(output + "\n");
        }
        if (["completed", "error"].includes(res.data.status)) {
          setRunning(false);
          clearInterval(interval);
        }
      } catch {}
    }, 3000);
    return () => clearInterval(interval);
  }, [pipelineId, setOutput]);

  const addStage = () => {
    setStages([...stages, { tool_name: "nmap", params: { scan_type: "quick" } }]);
  };

  const removeStage = (idx) => {
    setStages(stages.filter((_, i) => i !== idx));
  };

  const updateStage = (idx, toolValue) => {
    const toolConfig = AVAILABLE_TOOLS.find((t) => t.value === toolValue);
    const realName = toolValue === "nmap_service" || toolValue === "nmap_vuln" ? "nmap" : toolValue;
    const params = toolConfig?.defaultParams || {};
    if (toolValue === "nmap_service") params.scan_type = "service";
    if (toolValue === "nmap_vuln") params.scan_type = "vuln";
    const updated = [...stages];
    updated[idx] = { tool_name: realName, params };
    setStages(updated);
  };

  const handleRunQuick = async () => {
    if (!target.trim()) return;
    setRunning(true);
    setOutput("");
    try {
      const res = await automationApi.quick({
        project_id: parseInt(projectId) || 0,
        target: target.trim(),
        mode: quickMode,
      });
      setPipelineId(res.data.pipeline_id);
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
      setRunning(false);
    }
  };

  const handleRunCustom = async () => {
    if (!target.trim() || stages.length === 0) return;
    setRunning(true);
    setOutput("");
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

  return (
    <div>
      <PageHeader title="Automation Pipeline" description="Automate pentest workflows from scan to exploit" icon={Workflow} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="lg:col-span-2 bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Target">
            <TextInput value={target} onChange={setTarget} placeholder="192.168.1.1 or http://target.com" />
          </FormField>

          <div className="grid grid-cols-2 gap-4">
            <FormField label="Project (optional)">
              <SelectInput value={projectId} onChange={setProjectId}
                options={[{ value: "", label: "No Project" }, ...projects.map((p) => ({ value: String(p.id), label: p.name }))]} />
            </FormField>
            <FormField label="Mode">
              <SelectInput value={mode} onChange={setMode}
                options={[{ value: "quick", label: "Quick Auto" }, { value: "custom", label: "Custom Pipeline" }]} />
            </FormField>
          </div>

          {mode === "quick" && (
            <>
              <FormField label="Quick Mode">
                <SelectInput value={quickMode} onChange={setQuickMode} options={QUICK_MODES} />
              </FormField>
              <RunButton onClick={handleRunQuick} running={running} onStop={() => setRunning(false)} />
            </>
          )}

          {mode === "custom" && (
            <>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted">Pipeline Stages</p>
                  <button onClick={addStage} className="flex items-center gap-1 text-xs text-sawlah-red hover:text-sawlah-red-hover transition-colors">
                    <Plus className="w-3 h-3" /> Add Stage
                  </button>
                </div>
                {stages.length === 0 && (
                  <p className="text-sm text-sawlah-dim py-4 text-center">No stages added. Click "Add Stage" to build your pipeline.</p>
                )}
                {stages.map((stage, idx) => (
                  <div key={idx} className="flex items-center gap-2 bg-sawlah-surface border border-sawlah-border rounded-lg p-3">
                    <span className="text-xs font-mono text-sawlah-red font-bold w-6">{idx + 1}</span>
                    <ChevronRight className="w-3 h-3 text-sawlah-dim" />
                    <select
                      className="flex-1 bg-sawlah-bg border border-sawlah-border rounded px-2 py-1 text-sm text-white"
                      value={AVAILABLE_TOOLS.find((t) => {
                        if (stage.tool_name === "nmap" && stage.params?.scan_type === "service") return t.value === "nmap_service";
                        if (stage.tool_name === "nmap" && stage.params?.scan_type === "vuln") return t.value === "nmap_vuln";
                        return t.value === stage.tool_name;
                      })?.value || stage.tool_name}
                      onChange={(e) => updateStage(idx, e.target.value)}
                    >
                      {AVAILABLE_TOOLS.map((t) => (
                        <option key={t.value} value={t.value}>{t.label}</option>
                      ))}
                    </select>
                    <button onClick={() => removeStage(idx)} className="p-1 hover:bg-red-500/20 rounded text-sawlah-dim hover:text-sawlah-red transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
              <RunButton onClick={handleRunCustom} running={running} onStop={() => setRunning(false)} />
            </>
          )}
        </div>

        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted">Pipeline Status</p>
          {!pipelineStatus && <p className="text-sm text-sawlah-dim">No pipeline running</p>}
          {pipelineStatus && (
            <>
              <StatusBadge status={pipelineStatus.status} />
              <p className="text-xs text-sawlah-muted">
                Stage {pipelineStatus.current_stage} / {pipelineStatus.total_stages}
              </p>
              <div className="space-y-2 mt-3">
                {pipelineStatus.stages?.map((s, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-sawlah-red w-4">{i + 1}</span>
                    <span className="text-sawlah-text flex-1">{s.tool}</span>
                    <StatusBadge status={s.status} />
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
