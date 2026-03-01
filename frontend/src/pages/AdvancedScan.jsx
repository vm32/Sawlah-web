import { useState, useEffect, useCallback } from "react";
import { Crosshair } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "nuclei", label: "Nuclei - Template-based vuln scanner" },
  { value: "wafw00f", label: "wafw00f - WAF detection" },
  { value: "feroxbuster", label: "Feroxbuster - Fast content discovery" },
  { value: "wpscan", label: "WPScan - WordPress scanner" },
];

const NUCLEI_SEVERITY = [
  { value: "", label: "All severities" },
  { value: "info", label: "Info" },
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
  { value: "high,critical", label: "High + Critical" },
];

const WP_ENUM = [
  { value: "vp", label: "vp - Vulnerable plugins" },
  { value: "ap", label: "ap - All plugins" },
  { value: "vt", label: "vt - Vulnerable themes" },
  { value: "at", label: "at - All themes" },
  { value: "u", label: "u - Users" },
  { value: "vp,vt,u", label: "vp,vt,u - Common combo" },
];

export default function AdvancedScan({ setOutput, setTitle, activeProject }) {
  const [tool, setTool] = useState("nuclei");
  const [target, setTarget] = useState("");
  const [severity, setSeverity] = useState("");
  const [templates, setTemplates] = useState("");
  const [tags, setTags] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [concurrency, setConcurrency] = useState("");
  const [autoScan, setAutoScan] = useState(false);
  const [newTemplates, setNewTemplates] = useState(false);
  const [allWaf, setAllWaf] = useState(false);
  const [verbose, setVerbose] = useState(false);
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/dirb/common.txt");
  const [threads, setThreads] = useState("50");
  const [extensions, setExtensions] = useState("");
  const [depth, setDepth] = useState("2");
  const [noRecursion, setNoRecursion] = useState(false);
  const [wpEnum, setWpEnum] = useState("vp,vt,u");
  const [wpAggressive, setWpAggressive] = useState(false);
  const [wpStealthy, setWpStealthy] = useState(false);
  const [apiToken, setApiToken] = useState("");
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Advanced Scanning"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history(tool).then((res) => setHistory(res.data)).catch(() => {});
  }, [tool]);
  useEffect(() => { loadHistory(); }, [loadHistory]);

  useEffect(() => {
    if (!taskId) return;
    const interval = setInterval(async () => {
      try {
        const res = await toolsApi.status(taskId);
        setStatus(res.data.status);
        if (["completed", "error", "killed"].includes(res.data.status)) { clearInterval(interval); loadHistory(); }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [taskId, loadHistory]);

  const handleRun = async () => {
    if (!target.trim()) return;
    ws.reset(); setOutput(""); setStatus("running");
    const params = {
      target: target.trim(), severity, templates, tags,
      rate_limit: rateLimit, concurrency, automatic_scan: autoScan,
      new_templates: newTemplates, all_waf: allWaf, verbose,
      wordlist, threads, extensions, depth, no_recursion: noRecursion,
      enumerate: wpEnum, aggressive: wpAggressive, stealthy: wpStealthy,
      api_token: apiToken, extra_flags: extraFlags,
    };
    try {
      const res = await toolsApi.run(tool, params, activeProject);
      if (res.data.error) { setOutput(`Error: ${res.data.error}\n`); setStatus("error"); return; }
      setTaskId(res.data.task_id); setCommand(res.data.command);
      ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); setStatus("error"); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Advanced Scanning" description="Nuclei, WAF detection, Feroxbuster, WPScan" icon={Crosshair} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4 max-h-[700px] overflow-y-auto">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          <FormField label="Target URL / IP"><TextInput value={target} onChange={setTarget} placeholder="http://10.129.231.23 or https://target.com" /></FormField>

          {tool === "nuclei" && (
            <>
              <FormField label="Severity"><SelectInput value={severity} onChange={setSeverity} options={NUCLEI_SEVERITY} /></FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Templates" hint="Path or category"><TextInput value={templates} onChange={setTemplates} placeholder="cves/ or /path/to/template" /></FormField>
                <FormField label="Tags" hint="Comma separated"><TextInput value={tags} onChange={setTags} placeholder="cve,rce,lfi" /></FormField>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Rate Limit"><TextInput value={rateLimit} onChange={setRateLimit} placeholder="150" /></FormField>
                <FormField label="Concurrency"><TextInput value={concurrency} onChange={setConcurrency} placeholder="25" /></FormField>
              </div>
              <div className="flex gap-4">
                <CheckboxInput checked={autoScan} onChange={setAutoScan} label="Auto scan (-as)" />
                <CheckboxInput checked={newTemplates} onChange={setNewTemplates} label="New templates only (-nt)" />
              </div>
            </>
          )}

          {tool === "wafw00f" && (
            <div className="flex gap-4">
              <CheckboxInput checked={allWaf} onChange={setAllWaf} label="Test all WAFs (-a)" />
              <CheckboxInput checked={verbose} onChange={setVerbose} label="Verbose (-v)" />
            </div>
          )}

          {tool === "feroxbuster" && (
            <>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="50" /></FormField>
                <FormField label="Extensions"><TextInput value={extensions} onChange={setExtensions} placeholder="php,html,js" /></FormField>
              </div>
              <FormField label="Recursion Depth"><TextInput value={depth} onChange={setDepth} placeholder="2" /></FormField>
              <CheckboxInput checked={noRecursion} onChange={setNoRecursion} label="No recursion (-n)" />
            </>
          )}

          {tool === "wpscan" && (
            <>
              <FormField label="Enumerate"><SelectInput value={wpEnum} onChange={setWpEnum} options={WP_ENUM} /></FormField>
              <FormField label="API Token" hint="From wpscan.com for vuln data"><TextInput value={apiToken} onChange={setApiToken} placeholder="YOUR_API_TOKEN" /></FormField>
              <div className="flex gap-4">
                <CheckboxInput checked={wpAggressive} onChange={setWpAggressive} label="Aggressive detection" />
                <CheckboxInput checked={wpStealthy} onChange={setWpStealthy} label="Stealthy mode" />
              </div>
            </>
          )}

          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName={tool} />
      </div>
    </div>
  );
}
