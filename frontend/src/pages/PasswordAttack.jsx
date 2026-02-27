import { useState, useEffect, useCallback } from "react";
import { Key } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TOOLS = [
  { value: "hydra", label: "Hydra - Online brute-force" },
  { value: "john", label: "John the Ripper - Offline hash cracker" },
  { value: "hashcat", label: "Hashcat - GPU hash cracker" },
];

const SERVICES = [
  "ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "telnet",
  "mysql", "mssql", "postgres", "vnc", "pop3", "imap", "smtp",
].map((s) => ({ value: s, label: s.toUpperCase() }));

export default function PasswordAttack({ setOutput, setTitle }) {
  const [tool, setTool] = useState("hydra");
  const [target, setTarget] = useState("");
  const [service, setService] = useState("ssh");
  const [username, setUsername] = useState("");
  const [userlist, setUserlist] = useState("");
  const [password, setPassword] = useState("");
  const [passlist, setPasslist] = useState("/usr/share/wordlists/rockyou.txt");
  const [threads, setThreads] = useState("16");
  const [verbose, setVerbose] = useState(true);
  const [force, setForce] = useState(false);
  const [hashfile, setHashfile] = useState("");
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [format, setFormat] = useState("");
  const [showCracked, setShowCracked] = useState(false);
  const [hashMode, setHashMode] = useState("");
  const [attackMode, setAttackMode] = useState("0");
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Password Attacks"); }, [setTitle]);
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
    ws.reset(); setOutput("");
    const params = {
      target: target.trim(), service, username, userlist, password,
      passlist, threads: parseInt(threads) || 16, verbose, force,
      hashfile, wordlist, format, show: showCracked,
      mode: hashMode, attack_mode: attackMode, extra_flags: extraFlags,
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
      <PageHeader title="Password Attacks" description="Online and offline password cracking" icon={Key} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Tool"><SelectInput value={tool} onChange={setTool} options={TOOLS} /></FormField>
          {tool === "hydra" && (
            <>
              <FormField label="Target" hint="IP or hostname"><TextInput value={target} onChange={setTarget} placeholder="192.168.1.1" /></FormField>
              <FormField label="Service"><SelectInput value={service} onChange={setService} options={SERVICES} /></FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Username (-l)"><TextInput value={username} onChange={setUsername} placeholder="admin" /></FormField>
                <FormField label="User List (-L)"><TextInput value={userlist} onChange={setUserlist} placeholder="/path/to/users.txt" /></FormField>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Password (-p)"><TextInput value={password} onChange={setPassword} placeholder="password" /></FormField>
                <FormField label="Password List (-P)"><TextInput value={passlist} onChange={setPasslist} /></FormField>
              </div>
              <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="16" /></FormField>
              <div className="flex gap-4">
                <CheckboxInput checked={verbose} onChange={setVerbose} label="Verbose (-V)" />
                <CheckboxInput checked={force} onChange={setForce} label="Stop on first found (-f)" />
              </div>
            </>
          )}
          {tool === "john" && (
            <>
              <FormField label="Hash File"><TextInput value={hashfile} onChange={setHashfile} placeholder="/path/to/hashes.txt" /></FormField>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <FormField label="Format" hint="e.g. raw-md5, raw-sha256, bcrypt, ntlm"><TextInput value={format} onChange={setFormat} placeholder="auto-detect" /></FormField>
              <CheckboxInput checked={showCracked} onChange={setShowCracked} label="Show cracked (--show)" />
            </>
          )}
          {tool === "hashcat" && (
            <>
              <FormField label="Hash File"><TextInput value={hashfile} onChange={setHashfile} placeholder="/path/to/hashes.txt" /></FormField>
              <FormField label="Wordlist"><TextInput value={wordlist} onChange={setWordlist} /></FormField>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Hash Mode (-m)" hint="e.g. 0=MD5, 1000=NTLM"><TextInput value={hashMode} onChange={setHashMode} placeholder="0" /></FormField>
                <FormField label="Attack Mode (-a)">
                  <SelectInput value={attackMode} onChange={setAttackMode}
                    options={[{value:"0",label:"0 - Dictionary"},{value:"1",label:"1 - Combination"},{value:"3",label:"3 - Brute-force"},{value:"6",label:"6 - Hybrid"},{value:"7",label:"7 - Hybrid"}]} />
                </FormField>
              </div>
            </>
          )}
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} />
      </div>
    </div>
  );
}
