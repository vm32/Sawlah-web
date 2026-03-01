import { useState, useEffect, useCallback } from "react";
import {
  ShieldAlert, FileText, Download, Eye, ChevronDown, ChevronRight,
  ExternalLink, RefreshCw, Play, Square, Loader2,
} from "lucide-react";
import { toolsApi, wafw00fApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

export default function WafDetect({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [allWaf, setAllWaf] = useState(false);
  const [verbose, setVerbose] = useState(false);
  const [doubleCheck, setDoubleCheck] = useState(true);
  const [extraFlags, setExtraFlags] = useState("");
  const [saveReport, setSaveReport] = useState(true);
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);
  const [reports, setReports] = useState([]);
  const [showReports, setShowReports] = useState(false);
  const [previewReport, setPreviewReport] = useState(null);

  const ws = useWebSocket();

  useEffect(() => { setTitle("WAF Detection"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history("wafw00f").then((res) => setHistory(res.data)).catch(() => {});
  }, []);

  const loadReports = useCallback(() => {
    wafw00fApi.reports().then((res) => setReports(res.data)).catch(() => {});
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

  const handleRun = async () => {
    const t = target.trim();
    if (!t) return;
    ws.reset();
    setOutput("");

    try {
      const res = await wafw00fApi.run({
        target: t,
        all_waf: allWaf,
        verbose,
        double_check: doubleCheck,
        extra_flags: extraFlags,
        save_report: saveReport,
      });
      if (res.data.error) {
        setOutput(`Error: ${res.data.error}\n`);
        setStatus("error");
        return;
      }
      setTaskId(res.data.task_id);
      setCommand(res.data.command);
      setStatus("running");
      ws.connect(res.data.task_id);
    } catch (err) {
      setOutput(`Error: ${err.message}\n`);
      setStatus("error");
    }
  };

  const handleStop = async () => {
    if (taskId) {
      await toolsApi.kill(taskId);
      setStatus("killed");
    }
  };

  const urlCount = target.trim()
    ? target.split(/[,\n\r]+/).filter((u) => u.trim()).length
    : 0;

  return (
    <div>
      <PageHeader
        title="WAF Detection"
        description="Detect Web Application Firewalls with double-check verification — supports single URL or list of URLs"
        icon={ShieldAlert}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="space-y-4">
          {/* Target Configuration */}
          <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-sawlah-muted mb-1">
              Target Configuration
            </h3>

            <FormField
              label="Target URL(s)"
              hint="Enter one URL or multiple URLs separated by commas or newlines"
            >
              <textarea
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={"https://example.com\nhttps://another-site.com\nhttps://third-target.org"}
                rows={4}
                className="w-full bg-sawlah-surface border border-sawlah-border rounded-lg px-3 py-2 text-sm text-sawlah-text placeholder:text-sawlah-dim/50 focus:outline-none focus:border-sawlah-red/50 focus:ring-1 focus:ring-sawlah-red/30 font-mono resize-y"
              />
            </FormField>

            {urlCount > 0 && (
              <p className="text-xs text-sawlah-dim">
                <span className="text-sawlah-red font-bold">{urlCount}</span>{" "}
                URL{urlCount !== 1 ? "s" : ""} detected
                {doubleCheck ? " — each will be scanned twice (double-check)" : ""}
              </p>
            )}

            <div className="flex flex-wrap gap-x-6 gap-y-2">
              <CheckboxInput
                checked={doubleCheck}
                onChange={setDoubleCheck}
                label="Double Check (scan each URL twice)"
              />
              <CheckboxInput
                checked={allWaf}
                onChange={setAllWaf}
                label="Test all WAFs (-a)"
              />
              <CheckboxInput
                checked={verbose}
                onChange={setVerbose}
                label="Verbose (-v)"
              />
              <CheckboxInput
                checked={saveReport}
                onChange={setSaveReport}
                label="Save HTML Report"
              />
            </div>

            <FormField label="Extra Flags">
              <TextInput
                value={extraFlags}
                onChange={setExtraFlags}
                placeholder="Additional wafw00f flags"
              />
            </FormField>
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
                  WAF Reports ({reports.length})
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
                {showReports
                  ? <ChevronDown className="w-4 h-4 text-sawlah-dim" />
                  : <ChevronRight className="w-4 h-4 text-sawlah-dim" />}
              </div>
            </button>
            {showReports && (
              <div className="border-t border-sawlah-border">
                {reports.length === 0 && (
                  <p className="text-sm text-sawlah-dim px-5 py-6 text-center">
                    No wafw00f reports yet. Run a scan with &quot;Save HTML Report&quot; enabled.
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
                          href={wafw00fApi.downloadReport(r.filename)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 text-sawlah-dim hover:text-emerald-400 transition-colors"
                          title="Download"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={wafw00fApi.getReport(r.filename)}
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
                src={wafw00fApi.getReport(previewReport)}
                className="w-full bg-white"
                style={{ height: 600 }}
                title="wafw00f Report Preview"
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
          toolName="wafw00f"
        />
      </div>
    </div>
  );
}
