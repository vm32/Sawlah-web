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
  const [extraFlags, setExtraFlags] = useState("");
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
        if (["completed", "error", "killed"].includes(res.data.status)) {
          clearInterval(interval);
          loadHistory();
        }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [taskId, loadHistory]);

  const handleRun = async () => {
    if (!target.trim()) return;
    ws.reset();
    setOutput("");
    const params = {
      target: target.trim(), scan_type: scanType,
      ports: customPorts || ports, timing, scripts,
      version_detect: versionDetect, os_detect: osDetect,
      verbose, extra_flags: extraFlags,
    };
    try {
      const res = await toolsApi.run("nmap", params);
      setTaskId(res.data.task_id);
      setCommand(res.data.command);
      setStatus("running");
      ws.connect(res.data.task_id);
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
    }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Nmap Scanner" description="Network exploration and security auditing" icon={Radar} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Target" hint="IP, hostname, CIDR range, or space-separated list">
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
            <FormField label="NSE Scripts" hint="e.g. vuln, default, http-*">
              <TextInput value={scripts} onChange={setScripts} placeholder="vuln" />
            </FormField>
          </div>
          <FormField label="Extra Flags" hint="Additional nmap flags">
            <TextInput value={extraFlags} onChange={setExtraFlags} placeholder="--open --reason" />
          </FormField>
          <div className="flex flex-wrap gap-4">
            <CheckboxInput checked={versionDetect} onChange={setVersionDetect} label="Service Version (-sV)" />
            <CheckboxInput checked={osDetect} onChange={setOsDetect} label="OS Detection (-O)" />
            <CheckboxInput checked={verbose} onChange={setVerbose} label="Verbose (-v)" />
          </div>
        </div>

        <OutputPanel
          onRun={handleRun}
          onStop={handleStop}
          status={status}
          command={command}
          output={ws.output}
          history={history}
        />
      </div>
    </div>
  );
}
