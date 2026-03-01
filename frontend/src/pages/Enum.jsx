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
  { value: "rpcclient", label: "RPCClient - RPC enumeration" },
  { value: "ldapsearch", label: "LDAPSearch - LDAP queries" },
  { value: "snmpwalk", label: "SNMPWalk - SNMP enumeration" },
  { value: "nbtscan", label: "NBTScan - NetBIOS scanning" },
];

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR", "ANY"].map((r) => ({ value: r, label: r }));

export default function Enum({ setOutput, setTitle, activeProject }) {
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
  const [ridRange, setRidRange] = useState("");
  const [workgroup, setWorkgroup] = useState("");
  const [smbCommand, setSmbCommand] = useState("");
  const [smbPort, setSmbPort] = useState("");
  const [rpcCommand, setRpcCommand] = useState("");
  const [baseDn, setBaseDn] = useState("");
  const [bindDn, setBindDn] = useState("");
  const [bindPassword, setBindPassword] = useState("");
  const [searchFilter, setSearchFilter] = useState("");
  const [ldapAttrs, setLdapAttrs] = useState("");
  const [snmpVersion, setSnmpVersion] = useState("2c");
  const [community, setCommunity] = useState("public");
  const [snmpOid, setSnmpOid] = useState("");
  const [nbVerbose, setNbVerbose] = useState(false);
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
      rid_range: ridRange, workgroup, smb_command: smbCommand, port: smbPort,
      rpc_command: rpcCommand, base_dn: baseDn, bind_dn: bindDn,
      bind_password: bindPassword, search_filter: searchFilter, attributes: ldapAttrs,
      version: snmpVersion, community, oid: snmpOid, verbose: nbVerbose,
    };
    try {
      const res = await toolsApi.run(tool, params, activeProject);
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
          {tool === "enum4linux" && (
            <div className="grid grid-cols-2 gap-4">
              <FormField label="RID Range" hint="e.g. 500-550"><TextInput value={ridRange} onChange={setRidRange} placeholder="500-550" /></FormField>
              <FormField label="Workgroup"><TextInput value={workgroup} onChange={setWorkgroup} placeholder="WORKGROUP" /></FormField>
            </div>
          )}
          {tool === "smbclient" && (
            <>
              <FormField label="Port"><TextInput value={smbPort} onChange={setSmbPort} placeholder="445" /></FormField>
              <FormField label="SMB Command" hint="e.g. ls, recurse ON; mget *"><TextInput value={smbCommand} onChange={setSmbCommand} placeholder="ls" /></FormField>
            </>
          )}
          {tool === "rpcclient" && (
            <FormField label="RPC Command" hint="e.g. enumdomusers, lookupnames admin">
              <TextInput value={rpcCommand} onChange={setRpcCommand} placeholder="enumdomusers" />
            </FormField>
          )}
          {tool === "ldapsearch" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Base DN"><TextInput value={baseDn} onChange={setBaseDn} placeholder="DC=domain,DC=local" /></FormField>
                <FormField label="Bind DN"><TextInput value={bindDn} onChange={setBindDn} placeholder="CN=user,DC=domain,DC=local" /></FormField>
              </div>
              <FormField label="Bind Password"><TextInput value={bindPassword} onChange={setBindPassword} placeholder="password" /></FormField>
              <FormField label="Search Filter"><TextInput value={searchFilter} onChange={setSearchFilter} placeholder="(objectClass=user)" /></FormField>
              <FormField label="Attributes" hint="Comma separated"><TextInput value={ldapAttrs} onChange={setLdapAttrs} placeholder="cn,sAMAccountName,memberOf" /></FormField>
            </>
          )}
          {tool === "snmpwalk" && (
            <>
              <div className="grid grid-cols-3 gap-4">
                <FormField label="Version">
                  <SelectInput value={snmpVersion} onChange={setSnmpVersion} options={[{value:"1",label:"v1"},{value:"2c",label:"v2c"},{value:"3",label:"v3"}]} />
                </FormField>
                <FormField label="Community"><TextInput value={community} onChange={setCommunity} placeholder="public" /></FormField>
                <FormField label="OID"><TextInput value={snmpOid} onChange={setSnmpOid} placeholder="1.3.6.1.2.1.1" /></FormField>
              </div>
            </>
          )}
          {tool === "nbtscan" && (
            <CheckboxInput checked={nbVerbose} onChange={setNbVerbose} label="Verbose output" />
          )}
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName={tool} />
      </div>
    </div>
  );
}
