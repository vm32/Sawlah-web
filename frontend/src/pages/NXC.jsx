import { useState, useEffect, useCallback } from "react";
import { Network } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const PROTOCOLS = [
  "smb", "ldap", "rdp", "winrm", "ssh", "ftp", "mssql", "wmi", "vnc", "nfs",
].map((p) => ({ value: p, label: p.toUpperCase() }));

export default function NXC({ setOutput, setTitle, activeProject }) {
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState("smb");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [hash, setHash] = useState("");
  const [shares, setShares] = useState(false);
  const [users, setUsers] = useState(false);
  const [groups, setGroups] = useState(false);
  const [sessions, setSessions] = useState(false);
  const [disks, setDisks] = useState(false);
  const [loggedon, setLoggedon] = useState(false);
  const [ridBrute, setRidBrute] = useState(false);
  const [passPol, setPassPol] = useState(false);
  const [sam, setSam] = useState(false);
  const [lsa, setLsa] = useState(false);
  const [ntds, setNtds] = useState(false);
  const [localAuth, setLocalAuth] = useState(false);
  const [module, setModule] = useState("");
  const [extraFlags, setExtraFlags] = useState("");
  const [laps, setLaps] = useState(false);
  const [kerberoast, setKerberoast] = useState(false);
  const [ntdsMethod, setNtdsMethod] = useState("");
  const [spiderPlus, setSpiderPlus] = useState(false);
  const [putFile, setPutFile] = useState("");
  const [getFile, setGetFile] = useState("");
  const [execMethod, setExecMethod] = useState("");
  const [execCmd, setExecCmd] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("NetExec (NXC)"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history("nxc").then((res) => setHistory(res.data)).catch(() => {});
  }, []);
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
      target: target.trim(), protocol, username, password, hash,
      shares, users, groups, sessions, disks, loggedon,
      rid_brute: ridBrute, pass_pol: passPol, sam, lsa, ntds,
      local_auth: localAuth, module, extra_flags: extraFlags,
      laps, kerberoast, ntds_method: ntdsMethod, spider_plus: spiderPlus,
      put_file: putFile, get_file: getFile, exec_method: execMethod, exec_cmd: execCmd,
    };
    try {
      const res = await toolsApi.run("nxc", params, activeProject);
      setTaskId(res.data.task_id); setCommand(res.data.command);
      setStatus("running"); ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="NetExec (NXC)" description="Network service enumeration and exploitation" icon={Network} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Target" hint="IP address, hostname, or CIDR range">
            <TextInput value={target} onChange={setTarget} placeholder="192.168.1.0/24" />
          </FormField>
          <FormField label="Protocol"><SelectInput value={protocol} onChange={setProtocol} options={PROTOCOLS} /></FormField>
          <div className="grid grid-cols-3 gap-4">
            <FormField label="Username"><TextInput value={username} onChange={setUsername} placeholder="admin" /></FormField>
            <FormField label="Password"><TextInput value={password} onChange={setPassword} placeholder="password" /></FormField>
            <FormField label="NT Hash"><TextInput value={hash} onChange={setHash} placeholder="aad3b435..." /></FormField>
          </div>
          <FormField label="Module (-M)"><TextInput value={module} onChange={setModule} placeholder="e.g. spider_plus, petitpotam" /></FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Exec Method" hint="smbexec, wmiexec, atexec"><TextInput value={execMethod} onChange={setExecMethod} placeholder="smbexec" /></FormField>
            <FormField label="Exec Command"><TextInput value={execCmd} onChange={setExecCmd} placeholder="whoami" /></FormField>
          </div>
          <FormField label="NTDS Method" hint="vss or drsuapi"><TextInput value={ntdsMethod} onChange={setNtdsMethod} placeholder="drsuapi" /></FormField>
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted">Enumeration Options</p>
            <div className="grid grid-cols-3 gap-2">
              <CheckboxInput checked={shares} onChange={setShares} label="Shares" />
              <CheckboxInput checked={users} onChange={setUsers} label="Users" />
              <CheckboxInput checked={groups} onChange={setGroups} label="Groups" />
              <CheckboxInput checked={sessions} onChange={setSessions} label="Sessions" />
              <CheckboxInput checked={disks} onChange={setDisks} label="Disks" />
              <CheckboxInput checked={loggedon} onChange={setLoggedon} label="Logged-on" />
              <CheckboxInput checked={ridBrute} onChange={setRidBrute} label="RID Brute" />
              <CheckboxInput checked={passPol} onChange={setPassPol} label="Pass Policy" />
              <CheckboxInput checked={localAuth} onChange={setLocalAuth} label="Local Auth" />
            </div>
            <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mt-3">Credential Dumping</p>
            <div className="grid grid-cols-3 gap-2">
              <CheckboxInput checked={sam} onChange={setSam} label="SAM" />
              <CheckboxInput checked={lsa} onChange={setLsa} label="LSA" />
              <CheckboxInput checked={ntds} onChange={setNtds} label="NTDS" />
            </div>
            <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted mt-3">Advanced</p>
            <div className="grid grid-cols-3 gap-2">
              <CheckboxInput checked={laps} onChange={setLaps} label="LAPS" />
              <CheckboxInput checked={kerberoast} onChange={setKerberoast} label="Kerberoast" />
              <CheckboxInput checked={spiderPlus} onChange={setSpiderPlus} label="Spider Plus" />
            </div>
          </div>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName="nxc" />
      </div>
    </div>
  );
}
