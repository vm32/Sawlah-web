import { useState, useEffect, useCallback } from "react";
import { Server } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "enum4linux", label: "Enum4linux - SMB/Samba enumeration" },
  { value: "smbclient", label: "SMBClient - SMB share browser" },
  { value: "whois", label: "Whois - Domain registration info" },
  { value: "dig", label: "Dig - DNS lookup" },
];

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "ANY"].map((r) => ({ value: r, label: r }));

export default function Enum({ setOutput, setTitle }) {
  const [tool, setTool] = useState("enum4linux");
  const [target, setTarget] = useState("");
  const [all, setAll] = useState(true);
  const [usersOpt, setUsersOpt] = useState(false);
  const [sharesOpt, setSharesOpt] = useState(false);
  const [passPol, setPassPol] = useState(false);
  const [groupsOpt, setGroupsOpt] = useState(false);
  const [osInfo, setOsInfo] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [share, setShare] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [shortOutput, setShortOutput] = useState(false);
  const [trace, setTrace] = useState(false);
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Enumeration Tools"); }, [setTitle]);
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
      target: target.trim(), all, users: usersOpt, shares: sharesOpt,
      password_policy: passPol, groups: groupsOpt, os_info: osInfo,
      username, password, share, record_type: recordType,
      short: shortOutput, trace, extra_flags: extraFlags,
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
      <PageHeader title="Enumeration Tools" description="Enumerate services, shares, DNS, and domain info" icon={Server} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          <FormField label="Target">
            <TextInput value={target} onChange={setTarget} placeholder={tool === "dig" || tool === "whois" ? "example.com" : "192.168.1.1"} />
          </FormField>
          {tool === "enum4linux" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Username"><TextInput value={username} onChange={setUsername} placeholder="optional" /></FormField>
                <FormField label="Password"><TextInput value={password} onChange={setPassword} placeholder="optional" /></FormField>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <CheckboxInput checked={all} onChange={setAll} label="All (-a)" />
                <CheckboxInput checked={usersOpt} onChange={setUsersOpt} label="Users (-U)" />
                <CheckboxInput checked={sharesOpt} onChange={setSharesOpt} label="Shares (-S)" />
                <CheckboxInput checked={passPol} onChange={setPassPol} label="Pass Policy (-P)" />
                <CheckboxInput checked={groupsOpt} onChange={setGroupsOpt} label="Groups (-G)" />
                <CheckboxInput checked={osInfo} onChange={setOsInfo} label="OS Info (-o)" />
              </div>
            </>
          )}
          {tool === "smbclient" && (
            <>
              <FormField label="Share Name" hint="Leave empty to list shares (-L)">
                <TextInput value={share} onChange={setShare} placeholder="share_name" />
              </FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Username"><TextInput value={username} onChange={setUsername} placeholder="optional" /></FormField>
                <FormField label="Password"><TextInput value={password} onChange={setPassword} placeholder="optional" /></FormField>
              </div>
            </>
          )}
          {tool === "dig" && (
            <div className="grid grid-cols-2 gap-4">
              <FormField label="Record Type"><SelectInput value={recordType} onChange={setRecordType} options={RECORD_TYPES} /></FormField>
              <div className="flex flex-col gap-2 justify-end">
                <CheckboxInput checked={shortOutput} onChange={setShortOutput} label="+short" />
                <CheckboxInput checked={trace} onChange={setTrace} label="+trace" />
              </div>
            </div>
          )}
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} />
      </div>
    </div>
  );
}
