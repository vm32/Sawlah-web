import { useState, useEffect, useCallback } from "react";
import { Radar } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const SCAN_TYPES = [
  { value: "quick", label: "Quick Scan (-T4 -F)" },
  { value: "full_tcp", label: "Full TCP (-p- -T4)" },
  { value: "syn", label: "SYN Stealth (-sS)" },
  { value: "udp", label: "UDP Scan (-sU)" },
  { value: "service", label: "Service Detection (-sV)" },
  { value: "os", label: "OS Detection (-O)" },
  { value: "aggressive", label: "Aggressive (-A)" },
  { value: "vuln", label: "Vuln Scripts (--script vuln)" },
  { value: "stealth", label: "Stealth (-sS -T2 -f)" },
];

const PORT_OPTIONS = [
  { value: "", label: "Default" },
  { value: "top100", label: "Top 100 Ports" },
  { value: "top1000", label: "Top 1000 Ports" },
  { value: "all", label: "All Ports (1-65535)" },
];

const TIMING = [
  { value: "", label: "Default" },
  { value: "T0", label: "T0 - Paranoid" },
  { value: "T1", label: "T1 - Sneaky" },
  { value: "T2", label: "T2 - Polite" },
  { value: "T3", label: "T3 - Normal" },
  { value: "T4", label: "T4 - Aggressive" },
  { value: "T5", label: "T5 - Insane" },
];

const SCRIPT_PRESETS = [
  "vuln", "default", "safe", "auth", "broadcast", "brute", "discovery",
  "exploit", "external", "fuzzer", "intrusive", "malware",
  "http-enum", "smb-enum-shares", "ssl-enum-ciphers", "dns-brute",
];

export default function Nmap({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [ports, setPorts] = useState("");
  const [customPorts, setCustomPorts] = useState("");
  const [timing, setTiming] = useState("");
  const [scripts, setScripts] = useState("");
  const [versionDetect, setVersionDetect] = useState(false);
  const [osDetect, setOsDetect] = useState(false);
  const [verbose, setVerbose] = useState(true);
  const [noHostDiscovery, setNoHostDiscovery] = useState(false);
  const [noPing, setNoPing] = useState(false);
  const [openOnly, setOpenOnly] = useState(false);
  const [showReason, setShowReason] = useState(false);
  const [traceroute, setTraceroute] = useState(false);
  const [fragment, setFragment] = useState(false);
  const [minRate, setMinRate] = useState("");
  const [maxRetries, setMaxRetries] = useState("");
  const [excludeHosts, setExcludeHosts] = useState("");
  const [extraFlags, setExtraFlags] = useState("");
  const [decoy, setDecoy] = useState("");
  const [sourcePort, setSourcePort] = useState("");
  const [dataLength, setDataLength] = useState("");
  const [macSpoof, setMacSpoof] = useState("");
  const [spoofIp, setSpoofIp] = useState("");
  const [ifaceOpt, setIfaceOpt] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Nmap Scanner"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history("nmap").then((res) => setHistory(res.data)).catch(() => {});
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
    const extra = [
      noHostDiscovery ? "-Pn" : "",
      noPing ? "-sn" : "",
      openOnly ? "--open" : "",
      showReason ? "--reason" : "",
      traceroute ? "--traceroute" : "",
      fragment ? "-f" : "",
      minRate ? `--min-rate ${minRate}` : "",
      maxRetries ? `--max-retries ${maxRetries}` : "",
      excludeHosts ? `--exclude ${excludeHosts}` : "",
      decoy ? `-D ${decoy}` : "",
      sourcePort ? `--source-port ${sourcePort}` : "",
      dataLength ? `--data-length ${dataLength}` : "",
      macSpoof ? `--spoof-mac ${macSpoof}` : "",
      spoofIp ? `-S ${spoofIp}` : "",
      ifaceOpt ? `-e ${ifaceOpt}` : "",
      extraFlags,
    ].filter(Boolean).join(" ");

    const params = {
      target: target.trim(), scan_type: scanType,
      ports: customPorts || ports, timing, scripts,
      version_detect: versionDetect, os_detect: osDetect,
      verbose, extra_flags: extra,
    };
    try {
      const res = await toolsApi.run("nmap", params);
      setTaskId(res.data.task_id); setCommand(res.data.command);
      setStatus("running"); ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Nmap Scanner" description="Network exploration and security auditing" icon={Radar} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4 max-h-[700px] overflow-y-auto">
          <FormField label="Target" hint="IP, hostname, CIDR, or space-separated list">
            <TextInput value={target} onChange={setTarget} placeholder="192.168.1.1 or 10.0.0.0/24" />
          </FormField>
          <FormField label="Scan Type">
            <SelectInput value={scanType} onChange={setScanType} options={SCAN_TYPES} />
          </FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Port Range">
              <SelectInput value={ports} onChange={setPorts} options={PORT_OPTIONS} />
            </FormField>
            <FormField label="Custom Ports" hint="e.g. 22,80,443 or 1-1024">
              <TextInput value={customPorts} onChange={setCustomPorts} placeholder="80,443,8080" />
            </FormField>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Timing">
              <SelectInput value={timing} onChange={setTiming} options={TIMING} />
            </FormField>
            <FormField label="NSE Scripts">
              <TextInput value={scripts} onChange={setScripts} placeholder="vuln,default" />
            </FormField>
          </div>

          <div>
            <p className="text-[10px] uppercase tracking-wider font-bold text-sawlah-dim mb-2">Script Presets (click to add)</p>
            <div className="flex flex-wrap gap-1">
              {SCRIPT_PRESETS.map((s) => (
                <button key={s} onClick={() => setScripts((prev) => prev ? `${prev},${s}` : s)}
                  className="px-2 py-0.5 text-[10px] bg-sawlah-surface border border-sawlah-border rounded
                    hover:border-sawlah-red hover:text-sawlah-red transition-colors text-sawlah-dim"
                >{s}</button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <FormField label="Min Rate (pps)" hint="Packets per second">
              <TextInput value={minRate} onChange={setMinRate} placeholder="1000" />
            </FormField>
            <FormField label="Max Retries">
              <TextInput value={maxRetries} onChange={setMaxRetries} placeholder="3" />
            </FormField>
          </div>

          <FormField label="Exclude Hosts" hint="Comma-separated IPs to skip">
            <TextInput value={excludeHosts} onChange={setExcludeHosts} placeholder="192.168.1.254" />
          </FormField>

          <div className="grid grid-cols-2 gap-4">
            <FormField label="Decoy Scan (-D)" hint="Comma-separated IPs or RND"><TextInput value={decoy} onChange={setDecoy} placeholder="RND:5 or 10.0.0.1,10.0.0.2" /></FormField>
            <FormField label="Source Port" hint="Spoof source port"><TextInput value={sourcePort} onChange={setSourcePort} placeholder="53" /></FormField>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Data Length" hint="Append random data to packets"><TextInput value={dataLength} onChange={setDataLength} placeholder="40" /></FormField>
            <FormField label="MAC Spoof" hint="Spoof MAC address"><TextInput value={macSpoof} onChange={setMacSpoof} placeholder="00:11:22:33:44:55 or Apple" /></FormField>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Spoof IP (-S)" hint="Source IP spoof"><TextInput value={spoofIp} onChange={setSpoofIp} placeholder="10.0.0.1" /></FormField>
            <FormField label="Interface (-e)" hint="Network interface"><TextInput value={ifaceOpt} onChange={setIfaceOpt} placeholder="eth0" /></FormField>
          </div>

          <FormField label="Extra Flags" hint="Any additional nmap flags">
            <TextInput value={extraFlags} onChange={setExtraFlags} placeholder="--script-args=unsafe=1" />
          </FormField>

          <div className="grid grid-cols-3 gap-2">
            <CheckboxInput checked={versionDetect} onChange={setVersionDetect} label="-sV (versions)" />
            <CheckboxInput checked={osDetect} onChange={setOsDetect} label="-O (OS detect)" />
            <CheckboxInput checked={verbose} onChange={setVerbose} label="-v (verbose)" />
            <CheckboxInput checked={noHostDiscovery} onChange={setNoHostDiscovery} label="-Pn (no ping)" />
            <CheckboxInput checked={openOnly} onChange={setOpenOnly} label="--open only" />
            <CheckboxInput checked={showReason} onChange={setShowReason} label="--reason" />
            <CheckboxInput checked={traceroute} onChange={setTraceroute} label="--traceroute" />
            <CheckboxInput checked={fragment} onChange={setFragment} label="-f (fragment)" />
            <CheckboxInput checked={noPing} onChange={setNoPing} label="-sn (ping scan)" />
          </div>
        </div>

        <OutputPanel
          onRun={handleRun} onStop={handleStop} status={status}
          command={command} output={ws.output} history={history}
          toolName="nmap"
        />
      </div>
    </div>
  );
}
