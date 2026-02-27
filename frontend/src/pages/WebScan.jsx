import { useState, useEffect, useCallback } from "react";
import { SearchCode } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "nikto", label: "Nikto - Web server scanner" },
  { value: "dirb", label: "Dirb - Directory brute-force" },
  { value: "gobuster_dir", label: "Gobuster Dir - Directory/file brute-force" },
  { value: "ffuf", label: "FFUF - Fast web fuzzer" },
  { value: "whatweb", label: "WhatWeb - Web technology identifier" },
  { value: "wfuzz", label: "Wfuzz - Web application fuzzer" },
];

export default function WebScan({ setOutput, setTitle }) {
  const [tool, setTool] = useState("nikto");
  const [target, setTarget] = useState("");
  const [ssl, setSsl] = useState(false);
  const [port, setPort] = useState("");
  const [tuning, setTuning] = useState("");
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/dirb/common.txt");
  const [extensions, setExtensions] = useState("");
  const [threads, setThreads] = useState("10");
  const [mc, setMc] = useState("200,301,302,403");
  const [fc, setFc] = useState("");
  const [fs, setFs] = useState("");
  const [hc, setHc] = useState("404");
  const [aggression, setAggression] = useState("1");
  const [verbose, setVerbose] = useState(false);
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Web Scanning"); }, [setTitle]);
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
      target: target.trim(), ssl, port, tuning, wordlist, extensions,
      threads: parseInt(threads) || 10, mc, fc, fs, hc,
      aggression: parseInt(aggression), verbose, extra_flags: extraFlags,
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
      <PageHeader title="Web Scanning" description="Scan web servers for vulnerabilities and directories" icon={SearchCode} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          <FormField label="Target URL"><TextInput value={target} onChange={setTarget} placeholder="http://target.com" /></FormField>
          {tool === "nikto" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Port"><TextInput value={port} onChange={setPort} placeholder="80" /></FormField>
                <FormField label="Tuning" hint="1-9,a-c"><TextInput value={tuning} onChange={setTuning} /></FormField>
              </div>
              <CheckboxInput checked={ssl} onChange={setSsl} label="Use SSL (-ssl)" />
            </>
          )}
          {(tool === "dirb" || tool === "gobuster_dir" || tool === "ffuf" || tool === "wfuzz") && (
            <>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Extensions" hint="e.g. .php,.html,.txt"><TextInput value={extensions} onChange={setExtensions} placeholder=".php,.html,.txt" /></FormField>
                <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="10" /></FormField>
              </div>
            </>
          )}
          {tool === "ffuf" && (
            <div className="grid grid-cols-3 gap-4">
              <FormField label="Match codes"><TextInput value={mc} onChange={setMc} placeholder="200,301" /></FormField>
              <FormField label="Filter codes"><TextInput value={fc} onChange={setFc} placeholder="404" /></FormField>
              <FormField label="Filter size"><TextInput value={fs} onChange={setFs} /></FormField>
            </div>
          )}
          {tool === "wfuzz" && <FormField label="Hide codes (--hc)"><TextInput value={hc} onChange={setHc} placeholder="404" /></FormField>}
          {tool === "whatweb" && (
            <div className="grid grid-cols-2 gap-4">
              <FormField label="Aggression (1-4)">
                <SelectInput value={aggression} onChange={setAggression} options={[{value:"1",label:"1 - Stealthy"},{value:"2",label:"2 - Passive"},{value:"3",label:"3 - Aggressive"},{value:"4",label:"4 - Heavy"}]} />
              </FormField>
              <div className="flex items-end pb-1"><CheckboxInput checked={verbose} onChange={setVerbose} label="Verbose" /></div>
            </div>
          )}
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} />
      </div>
    </div>
  );
}
