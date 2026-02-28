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
  const [tryNsr, setTryNsr] = useState(false);
  const [waitTime, setWaitTime] = useState("");
  const [exitFirst, setExitFirst] = useState(false);
  const [hydrProxy, setHydrProxy] = useState("");
  const [customPort, setCustomPort] = useState("");
  const [johnFork, setJohnFork] = useState("");
  const [johnSession, setJohnSession] = useState("");
  const [johnRestore, setJohnRestore] = useState(false);
  const [johnIncremental, setJohnIncremental] = useState(false);
  const [hcUsername, setHcUsername] = useState(false);
  const [hcOptimized, setHcOptimized] = useState(false);
  const [hcStatusTimer, setHcStatusTimer] = useState("");
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
      try_nsr: tryNsr, wait_time: waitTime, exit_first: exitFirst,
      proxy: hydrProxy, custom_port: customPort,
      fork: johnFork, session: johnSession, restore: johnRestore,
      incremental: johnIncremental,
      hc_username: hcUsername, optimized: hcOptimized, status_timer: hcStatusTimer,
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
          {tool === "hydra" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Custom Port"><TextInput value={customPort} onChange={setCustomPort} placeholder="22" /></FormField>
                <FormField label="Wait Time (s)" hint="Delay between attempts"><TextInput value={waitTime} onChange={setWaitTime} placeholder="0" /></FormField>
              </div>
              <FormField label="Proxy" hint="e.g. http://127.0.0.1:8080"><TextInput value={hydrProxy} onChange={setHydrProxy} placeholder="socks5://127.0.0.1:1080" /></FormField>
              <div className="grid grid-cols-2 gap-2">
                <CheckboxInput checked={tryNsr} onChange={setTryNsr} label="-e nsr (null/same/reverse)" />
                <CheckboxInput checked={exitFirst} onChange={setExitFirst} label="-f (exit on first found)" />
              </div>
            </>
          )}
          {tool === "john" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Fork (parallel)" hint="Number of processes"><TextInput value={johnFork} onChange={setJohnFork} placeholder="4" /></FormField>
                <FormField label="Session Name"><TextInput value={johnSession} onChange={setJohnSession} placeholder="my_session" /></FormField>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <CheckboxInput checked={johnRestore} onChange={setJohnRestore} label="--restore session" />
                <CheckboxInput checked={johnIncremental} onChange={setJohnIncremental} label="--incremental mode" />
              </div>
            </>
          )}
          {tool === "hashcat" && (
            <>
              <FormField label="Status Timer (s)" hint="Show status every N seconds"><TextInput value={hcStatusTimer} onChange={setHcStatusTimer} placeholder="60" /></FormField>
              <div className="grid grid-cols-2 gap-2">
                <CheckboxInput checked={hcUsername} onChange={setHcUsername} label="--username (hash:user format)" />
                <CheckboxInput checked={hcOptimized} onChange={setHcOptimized} label="-O (optimized kernels)" />
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
