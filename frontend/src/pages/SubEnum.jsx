import { useState, useEffect, useCallback } from "react";
import { Globe } from "lucide-react";
import { toolsApi, subenumApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "all_in_one", label: "All-in-One (Subdomains + Directories)" },
  { value: "gobuster_dns", label: "Gobuster DNS - Brute-force subdomains" },
  { value: "dnsenum", label: "DNSEnum - DNS enumeration" },
];

export default function SubEnum({ setOutput, setTitle, activeProject }) {
  const [tool, setTool] = useState("all_in_one");
  const [target, setTarget] = useState("");
  const [wordlist, setWordlist] = useState("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
  const [dirWordlist, setDirWordlist] = useState("/usr/share/seclists/Discovery/Web-Content/common.txt");
  const [threads, setThreads] = useState("30");
  const [extensions, setExtensions] = useState("");
  const [enumSubs, setEnumSubs] = useState(true);
  const [extraFlags, setExtraFlags] = useState("");
  const [showCname, setShowCname] = useState(false);
  const [wildcardDetect, setWildcardDetect] = useState(false);
  const [noreverse, setNoreverse] = useState(true);
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Subdomain Enumeration"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    const name = tool === "all_in_one" ? "subenum_all" : tool;
    toolsApi.history(name).then((res) => setHistory(res.data)).catch(() => {});
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

    if (tool === "all_in_one") {
      try {
        const res = await subenumApi.runAll({
          target: target.trim(),
          threads: parseInt(threads) || 30,
          extensions,
          dns_wordlist: wordlist,
          dir_wordlist: dirWordlist,
          project_id: activeProject || null,
        });
        if (res.data.error) { setOutput(`Error: ${res.data.error}\n`); setStatus("error"); return; }
        setTaskId(res.data.task_id); setCommand(res.data.command);
        ws.connect(res.data.task_id);
      } catch (err) { setOutput(`Error: ${err.message}\n`); setStatus("error"); }
    } else {
      const params = {
        target: target.trim(), wordlist,
        threads: parseInt(threads) || 10, enum_subdomains: enumSubs,
        extra_flags: extraFlags, show_cname: showCname,
        wildcard: wildcardDetect, noreverse,
      };
      try {
        const res = await toolsApi.run(tool, params, activeProject || null);
        if (res.data.error) { setOutput(`Error: ${res.data.error}\n`); setStatus("error"); return; }
        setTaskId(res.data.task_id); setCommand(res.data.command);
        ws.connect(res.data.task_id);
      } catch (err) { setOutput(`Error: ${err.message}\n`); setStatus("error"); }
    }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Subdomain Enumeration" description="Discover subdomains and directories of a target domain" icon={Globe} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4 max-h-[700px] overflow-y-auto">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          <FormField label="Target Domain" hint="e.g. example.com or qassim.gov.sa">
            <TextInput value={target} onChange={setTarget} placeholder="example.com" />
          </FormField>

          {tool === "all_in_one" && (
            <>
              <FormField label="DNS Wordlist" hint="For subdomain brute-force">
                <TextInput value={wordlist} onChange={setWordlist} />
              </FormField>
              <FormField label="Directory Wordlist" hint="For directory discovery">
                <TextInput value={dirWordlist} onChange={setDirWordlist} />
              </FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="30" /></FormField>
                <FormField label="Extensions" hint="For dir scan, e.g. php,html"><TextInput value={extensions} onChange={setExtensions} placeholder="php,html,txt" /></FormField>
              </div>
            </>
          )}

          {tool === "gobuster_dns" && (
            <>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="10" /></FormField>
              <div className="flex gap-4">
                <CheckboxInput checked={showCname} onChange={setShowCname} label="Check CNAME (-c)" />
                <CheckboxInput checked={wildcardDetect} onChange={setWildcardDetect} label="Wildcard (--wc)" />
              </div>
            </>
          )}

          {tool === "dnsenum" && (
            <>
              <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="10" /></FormField>
              <div className="flex gap-4">
                <CheckboxInput checked={enumSubs} onChange={setEnumSubs} label="Enumerate subdomains (--enum)" />
                <CheckboxInput checked={noreverse} onChange={setNoreverse} label="No reverse (--noreverse)" />
              </div>
            </>
          )}

          {tool !== "all_in_one" && (
            <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
          )}
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName={tool === "all_in_one" ? "subenum_all" : tool} />
      </div>
    </div>
  );
}
