import { useState, useEffect, useCallback } from "react";
import {
  Shield, Globe, FileText, Download, Eye, Trash2,
  ChevronDown, ChevronRight, ExternalLink, RefreshCw,
} from "lucide-react";
import { toolsApi, niktoApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import {
  PageHeader, FormField, TextInput, SelectInput, CheckboxInput,
} from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const TUNING_OPTIONS = [
  { value: "", label: "All (default)" },
  { value: "1", label: "1 - Interesting Files" },
  { value: "2", label: "2 - Misconfigurations" },
  { value: "3", label: "3 - Information Disclosure" },
  { value: "4", label: "4 - XSS / Script Injection" },
  { value: "5", label: "5 - Remote File Retrieval (Web Root)" },
  { value: "6", label: "6 - Denial of Service" },
  { value: "7", label: "7 - Remote File Retrieval (Server)" },
  { value: "8", label: "8 - Command Execution" },
  { value: "9", label: "9 - SQL Injection" },
  { value: "0", label: "0 - File Upload" },
  { value: "a", label: "a - Authentication Bypass" },
  { value: "b", label: "b - Software Identification" },
  { value: "c", label: "c - Remote Source Inclusion" },
  { value: "123489abc", label: "Full Comprehensive Scan" },
];

const MUTATE_OPTIONS = [
  { value: "", label: "None" },
  { value: "1", label: "1 - Test all files with all root dirs" },
  { value: "2", label: "2 - Guess password file names" },
  { value: "3", label: "3 - Enumerate users via Apache (~user)" },
  { value: "4", label: "4 - Enumerate users via cgiwrap" },
  { value: "5", label: "5 - Brute force sub-domain names" },
  { value: "6", label: "6 - Guess directory names from dict" },
  { value: "123456", label: "All mutation techniques" },
];

const EVASION_OPTIONS = [
  { value: "", label: "None" },
  { value: "1", label: "1 - Random URI encoding" },
  { value: "2", label: "2 - Directory self-reference (/./)" },
  { value: "3", label: "3 - Premature URL ending" },
  { value: "4", label: "4 - Prepend long random string" },
  { value: "5", label: "5 - Fake parameter" },
  { value: "6", label: "6 - TAB as request spacer" },
  { value: "7", label: "7 - Change URL case" },
  { value: "8", label: "8 - Use Windows directory separator" },
  { value: "A", label: "A - Use carriage return" },
  { value: "B", label: "B - Use binary value 0x0b" },
];

const DISPLAY_OPTIONS = [
  { value: "V", label: "Verbose (show all requests)" },
  { value: "E", label: "Errors only" },
  { value: "P", label: "Print progress" },
  { value: "D", label: "Debug" },
  { value: "1", label: "Show redirects" },
  { value: "2", label: "Show cookies" },
  { value: "3", label: "Show 200/OK responses" },
  { value: "4", label: "Show URLs requiring auth" },
  { value: "V1234", label: "Everything (max verbosity)" },
];

const CGIDIRS_OPTIONS = [
  { value: "", label: "Default" },
  { value: "all", label: "All possible CGI dirs" },
  { value: "none", label: "Skip CGI scanning" },
];

const SCAN_PROFILES = [
  {
    id: "quick",
    name: "Quick Scan",
    desc: "Fast check of common vulnerabilities",
    settings: { tuning: "b", mutate: "", evasion: "", display: "", cgidirs: "", maxtime: "120" },
  },
  {
    id: "standard",
    name: "Standard Scan",
    desc: "Balanced scan for most web applications",
    settings: { tuning: "", mutate: "", evasion: "", display: "", cgidirs: "", maxtime: "" },
  },
  {
    id: "comprehensive",
    name: "Comprehensive",
    desc: "Full scan with all tuning and mutation",
    settings: { tuning: "123489abc", mutate: "123456", evasion: "", display: "", cgidirs: "all", maxtime: "" },
  },
  {
    id: "stealth",
    name: "Stealth Mode",
    desc: "Evasion-enabled scan for IDS bypass",
    settings: { tuning: "", mutate: "", evasion: "1", display: "", cgidirs: "", maxtime: "" },
  },
];

export default function Nikto({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [ssl, setSsl] = useState(false);
  const [tuning, setTuning] = useState("");
  const [mutate, setMutate] = useState("");
  const [evasion, setEvasion] = useState("");
  const [cgidirs, setCgidirs] = useState("");
  const [display, setDisplay] = useState("");
  const [timeout, setTimeout_] = useState("");
  const [maxtime, setMaxtime] = useState("");
  const [useragent, setUseragent] = useState("");
  const [plugins, setPlugins] = useState("");
  const [followRedirects, setFollowRedirects] = useState(false);
  const [no404, setNo404] = useState(false);
  const [saveReport, setSaveReport] = useState(true);
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);
  const [reports, setReports] = useState([]);
  const [showReports, setShowReports] = useState(false);
  const [previewReport, setPreviewReport] = useState(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Nikto Scanner"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history("nikto").then((res) => setHistory(res.data)).catch(() => {});
  }, []);

  const loadReports = useCallback(() => {
    niktoApi.reports().then((res) => setReports(res.data)).catch(() => {});
  }, []);

  useEffect(() => { loadHistory(); loadReports(); }, [loadHistory, loadReports]);

  useEffect(() => {
    if (!taskId) return;
    const interval = setInterval(async () => {
      try {
        const res = await toolsApi.status(taskId);
        setStatus(res.data.status);
        if (["completed", "error", "killed"].includes(res.data.status)) {
          clearInterval(interval);
          loadHistory();
          loadReports();
        }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [taskId, loadHistory, loadReports]);

  const applyProfile = (profile) => {
    const s = profile.settings;
    setTuning(s.tuning);
    setMutate(s.mutate);
    setEvasion(s.evasion);
    setDisplay(s.display);
    setCgidirs(s.cgidirs);
    setMaxtime(s.maxtime);
  };

  const handleRun = async () => {
    const t = target.trim();
    if (!t) return;
    ws.reset();
    setOutput("");

    try {
      const res = await niktoApi.run({
        target: t,
        port,
        ssl: ssl || t.startsWith("https://"),
        tuning,
        mutate,
        evasion,
        cgidirs,
        display,
        timeout,
        maxtime,
        useragent,
        plugins,
        followredirects: followRedirects,
        no404,
        save_report: saveReport,
        extra_flags: extraFlags,
      });
      if (res.data.error) {
        setOutput(`Error: ${res.data.error}\n`);
        return;
      }
      setTaskId(res.data.task_id);
      setCommand(res.data.command);
      setStatus("running");
      ws.connect(res.data.task_id);
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
    }
  };

  const handleStop = async () => {
    if (taskId) {
      await toolsApi.kill(taskId);
      setStatus("killed");
    }
  };

  return (
    <div>
      <PageHeader
        title="Nikto Web Scanner"
        description="Comprehensive web server vulnerability scanner — accepts http:// and https:// targets"
        icon={Shield}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* Left: Configuration */}
        <div className="space-y-4">
          {/* Scan Profiles */}
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-sawlah-muted mb-3">Scan Profiles</h3>
            <div className="grid grid-cols-2 gap-2">
              {SCAN_PROFILES.map((p) => (
                <button
                  key={p.id}
                  onClick={() => applyProfile(p)}
                  className="text-left px-3 py-2.5 rounded-lg border border-sawlah-border hover:border-sawlah-red/40 hover:bg-sawlah-red/5 transition-all group"
                >
                  <span className="text-sm font-semibold text-sawlah-text group-hover:text-sawlah-red transition-colors">
                    {p.name}
                  </span>
                  <p className="text-[11px] text-sawlah-dim mt-0.5">{p.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Target Configuration */}
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-sawlah-muted mb-1">Target Configuration</h3>

            <FormField label="Target" hint="Hostname, IP, or full URL — examples: example.com, https://example.com, 10.10.10.10">
              <TextInput value={target} onChange={setTarget} placeholder="example.com" />
            </FormField>

            <div className="grid grid-cols-2 gap-4">
              <FormField label="Port(s)" hint="Only for bare hostnames/IPs, not full URLs">
                <TextInput value={port} onChange={setPort} placeholder="80" />
              </FormField>
              <FormField label="Scan Tuning">
                <SelectInput value={tuning} onChange={setTuning} options={TUNING_OPTIONS} />
              </FormField>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField label="Mutation Techniques">
                <SelectInput value={mutate} onChange={setMutate} options={MUTATE_OPTIONS} />
              </FormField>
              <FormField label="CGI Directories">
                <SelectInput value={cgidirs} onChange={setCgidirs} options={CGIDIRS_OPTIONS} />
              </FormField>
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-2">
              <CheckboxInput checked={ssl} onChange={setSsl} label="Force SSL (-ssl)" />
              <CheckboxInput checked={followRedirects} onChange={setFollowRedirects} label="Follow Redirects" />
              <CheckboxInput checked={saveReport} onChange={setSaveReport} label="Save HTML Report" />
              <CheckboxInput checked={no404} onChange={setNo404} label="Disable 404 guessing" />
            </div>
          </div>

          {/* Advanced Options */}
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full flex items-center justify-between px-5 py-3 hover:bg-white/[0.02] transition-colors"
            >
              <span className="text-xs font-bold uppercase tracking-wider text-sawlah-muted">Advanced Options</span>
              {showAdvanced ? <ChevronDown className="w-4 h-4 text-sawlah-dim" /> : <ChevronRight className="w-4 h-4 text-sawlah-dim" />}
            </button>
            {showAdvanced && (
              <div className="px-5 pb-5 space-y-4 border-t border-sawlah-border pt-4">
                <div className="grid grid-cols-2 gap-4">
                  <FormField label="IDS Evasion">
                    <SelectInput value={evasion} onChange={setEvasion} options={EVASION_OPTIONS} />
                  </FormField>
                  <FormField label="Display / Verbosity">
                    <SelectInput value={display} onChange={(v) => setDisplay(v)} options={[{ value: "", label: "Default" }, ...DISPLAY_OPTIONS]} />
                  </FormField>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <FormField label="Request Timeout (sec)">
                    <TextInput value={timeout} onChange={setTimeout_} placeholder="10" />
                  </FormField>
                  <FormField label="Max Scan Time (sec)">
                    <TextInput value={maxtime} onChange={setMaxtime} placeholder="No limit" />
                  </FormField>
                </div>
                <FormField label="Custom User-Agent">
                  <TextInput value={useragent} onChange={setUseragent} placeholder="Mozilla/5.0 ..." />
                </FormField>
                <FormField label="Plugins" hint="Comma-separated: apacheusers,dictionary,etc.">
                  <TextInput value={plugins} onChange={setPlugins} placeholder="All by default" />
                </FormField>
                <FormField label="Extra Flags">
                  <TextInput value={extraFlags} onChange={setExtraFlags} placeholder="-C all -404code 404,301" />
                </FormField>
              </div>
            )}
          </div>

          {/* Reports Section */}
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
            <button
              onClick={() => { setShowReports(!showReports); if (!showReports) loadReports(); }}
              className="w-full flex items-center justify-between px-5 py-3 hover:bg-white/[0.02] transition-colors"
            >
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-sawlah-red" />
                <span className="text-xs font-bold uppercase tracking-wider text-sawlah-muted">
                  Scan Reports ({reports.length})
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={(e) => { e.stopPropagation(); loadReports(); }}
                  className="p-1 text-sawlah-dim hover:text-sawlah-muted transition-colors"
                  title="Refresh"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
                {showReports ? <ChevronDown className="w-4 h-4 text-sawlah-dim" /> : <ChevronRight className="w-4 h-4 text-sawlah-dim" />}
              </div>
            </button>
            {showReports && (
              <div className="border-t border-sawlah-border">
                {reports.length === 0 && (
                  <p className="text-sm text-sawlah-dim px-5 py-6 text-center">
                    No Nikto reports yet. Run a scan with "Save HTML Report" enabled.
                  </p>
                )}
                <div className="max-h-[300px] overflow-y-auto">
                  {reports.map((r) => (
                    <div
                      key={r.filename}
                      className="flex items-center justify-between px-5 py-2.5 border-b border-sawlah-border/50 hover:bg-white/[0.02] transition-colors"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-mono text-sawlah-text truncate">{r.filename}</p>
                        <p className="text-[10px] text-sawlah-dim">
                          {new Date(r.created).toLocaleString()} &middot; {(r.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                      <div className="flex items-center gap-1 shrink-0 ml-2">
                        <button
                          onClick={() => setPreviewReport(previewReport === r.filename ? null : r.filename)}
                          className="p-1.5 text-sawlah-dim hover:text-sawlah-red transition-colors"
                          title="Preview"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <a
                          href={niktoApi.downloadReport(r.filename)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 text-sawlah-dim hover:text-emerald-400 transition-colors"
                          title="Download"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={niktoApi.getReport(r.filename)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 text-sawlah-dim hover:text-blue-400 transition-colors"
                          title="Open in new tab"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Report Preview */}
          {previewReport && (
            <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3 border-b border-sawlah-border">
                <span className="text-xs font-bold uppercase tracking-wider text-sawlah-muted">Report Preview</span>
                <button
                  onClick={() => setPreviewReport(null)}
                  className="text-xs text-sawlah-dim hover:text-sawlah-red transition-colors"
                >
                  Close
                </button>
              </div>
              <iframe
                src={niktoApi.getReport(previewReport)}
                className="w-full bg-white"
                style={{ height: 600 }}
                title="Nikto Report Preview"
              />
            </div>
          )}
        </div>

        {/* Right: Output */}
        <OutputPanel
          onRun={handleRun}
          onStop={handleStop}
          status={status}
          command={command}
          output={ws.output}
          history={history}
          toolName="nikto"
        />
      </div>
    </div>
  );
}
