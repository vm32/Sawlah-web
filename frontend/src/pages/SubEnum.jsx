import { useState, useEffect, useCallback } from "react";
import { Globe } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "amass", label: "Amass - Comprehensive subdomain enum" },
  { value: "gobuster_dns", label: "Gobuster DNS - Brute-force subdomains" },
  { value: "dnsenum", label: "DNSEnum - DNS enumeration" },
];

export default function SubEnum({ setOutput, setTitle }) {
  const [tool, setTool] = useState("amass");
  const [target, setTarget] = useState("");
  const [passive, setPassive] = useState(true);
  const [brute, setBrute] = useState(false);
  const [wordlist, setWordlist] = useState("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
  const [threads, setThreads] = useState("10");
  const [enumSubs, setEnumSubs] = useState(true);
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Subdomain Enumeration"); }, [setTitle]);
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
    ws.reset(); setOutput("");
    const params = {
      target: target.trim(), passive, brute, wordlist,
      threads: parseInt(threads) || 10, enum_subdomains: enumSubs, extra_flags: extraFlags,
    };
    try {
      const res = await toolsApi.run(tool, params);
      setTaskId(res.data.task_id); setCommand(res.data.command);
      setStatus("running"); ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Subdomain Enumeration" description="Discover subdomains of a target domain" icon={Globe} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          <FormField label="Target Domain"><TextInput value={target} onChange={setTarget} placeholder="example.com" /></FormField>
          {tool === "amass" && (
            <div className="flex gap-4">
              <CheckboxInput checked={passive} onChange={setPassive} label="Passive mode" />
              <CheckboxInput checked={brute} onChange={setBrute} label="Brute force" />
            </div>
          )}
          {(tool === "gobuster_dns" || tool === "dnsenum") && (
            <>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="10" /></FormField>
            </>
          )}
          {tool === "dnsenum" && <CheckboxInput checked={enumSubs} onChange={setEnumSubs} label="Enumerate subdomains (--enum)" />}
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName={tool} />
      </div>
    </div>
  );
}
