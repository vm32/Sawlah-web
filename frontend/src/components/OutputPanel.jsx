import { useEffect, useRef, useState } from "react";
import { Clock, Terminal, Copy, Check, ChevronDown, ChevronRight, Trash2, ScrollText } from "lucide-react";
import StatusBadge from "./StatusBadge";
import { CommandPreview, RunButton } from "./ToolForm";

export default function OutputPanel({
  onRun,
  onStop,
  status,
  command,
  output,
  history,
}) {
  const [tab, setTab] = useState("live");
  const [expandedHistory, setExpandedHistory] = useState(null);
  const [copied, setCopied] = useState(false);
  const outputRef = useRef(null);

  useEffect(() => {
    if (outputRef.current && tab === "live") {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output, tab]);

  useEffect(() => {
    if (status === "running") setTab("live");
  }, [status]);

  const copyOutput = () => {
    const text = tab === "live" ? output : (expandedHistory !== null ? history[expandedHistory]?.output : "");
    if (text) {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const liveLines = (output || "").split("\n");
  const historyItems = history || [];

  return (
    <div className="bg-sawlah-card border border-sawlah-border rounded-xl flex flex-col overflow-hidden" style={{ minHeight: 420 }}>
      {/* Top bar: Run + Status */}
      <div className="flex items-center justify-between px-5 pt-5 pb-3">
        <RunButton onClick={onRun} running={status === "running"} onStop={onStop} />
        {status && <StatusBadge status={status} />}
      </div>

      {command && <div className="px-5 pb-3"><CommandPreview command={command} /></div>}

      {/* Tabs */}
      <div className="flex border-b border-sawlah-border px-5">
        <button
          onClick={() => setTab("live")}
          className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            tab === "live"
              ? "border-sawlah-red text-sawlah-red"
              : "border-transparent text-sawlah-dim hover:text-sawlah-muted"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Live Output
          {status === "running" && <span className="w-1.5 h-1.5 rounded-full bg-sawlah-green animate-pulse" />}
        </button>
        <button
          onClick={() => setTab("history")}
          className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            tab === "history"
              ? "border-sawlah-red text-sawlah-red"
              : "border-transparent text-sawlah-dim hover:text-sawlah-muted"
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          History
          {historyItems.length > 0 && (
            <span className="text-[10px] bg-sawlah-surface px-1.5 py-0.5 rounded-full">{historyItems.length}</span>
          )}
        </button>
      </div>

      {/* Content area */}
      <div className="flex-1 flex flex-col min-h-0">
        {tab === "live" && (
          <>
            {/* Toolbar */}
            {output && (
              <div className="flex items-center justify-between px-4 py-1.5 bg-sawlah-surface/50 border-b border-sawlah-border">
                <span className="text-[10px] text-sawlah-dim font-mono">{liveLines.length} lines</span>
                <button onClick={copyOutput} className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors">
                  {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
            )}
            {/* Output area */}
            <div
              ref={outputRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed"
              style={{ maxHeight: 400, background: "#050505" }}
            >
              {!output && !status && (
                <div className="flex flex-col items-center justify-center h-full text-sawlah-dim py-12">
                  <ScrollText className="w-10 h-10 mb-3 opacity-20" />
                  <p className="text-sm">Configure options and click Run</p>
                  <p className="text-[11px] mt-1">Output will appear here in real-time</p>
                </div>
              )}
              {!output && status === "running" && (
                <div className="flex items-center gap-2 text-sawlah-yellow">
                  <span className="w-2 h-2 rounded-full bg-sawlah-yellow animate-pulse" />
                  Waiting for output...
                </div>
              )}
              {output && output.split("\n").map((line, i) => (
                <div key={i} className="flex hover:bg-white/[0.02] -mx-1 px-1 rounded">
                  <span className="text-sawlah-dim/40 select-none w-8 text-right mr-3 shrink-0">{i + 1}</span>
                  <span className={`whitespace-pre-wrap break-all ${
                    line.includes("[+]") || line.includes("open") ? "text-sawlah-green" :
                    line.includes("[-]") || line.includes("ERROR") || line.includes("error") ? "text-sawlah-red" :
                    line.includes("[*]") || line.includes("[!]") ? "text-sawlah-yellow" :
                    line.includes("VULNERABLE") || line.includes("CRITICAL") ? "text-sawlah-red font-bold" :
                    "text-zinc-300"
                  }`}>{line || "\u00A0"}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {tab === "history" && (
          <div className="flex-1 overflow-y-auto" style={{ maxHeight: 400 }}>
            {historyItems.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-sawlah-dim py-12">
                <Clock className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">No scan history yet</p>
                <p className="text-[11px] mt-1">Previous runs will appear here</p>
              </div>
            )}
            {historyItems.map((item, idx) => (
              <div key={item.id || idx} className="border-b border-sawlah-border last:border-0">
                <button
                  onClick={() => setExpandedHistory(expandedHistory === idx ? null : idx)}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors text-left"
                >
                  {expandedHistory === idx
                    ? <ChevronDown className="w-3.5 h-3.5 text-sawlah-dim shrink-0" />
                    : <ChevronRight className="w-3.5 h-3.5 text-sawlah-dim shrink-0" />
                  }
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-mono text-sawlah-red">{item.id || `#${idx + 1}`}</span>
                      <StatusBadge status={item.status} />
                    </div>
                    <p className="text-[11px] font-mono text-sawlah-dim truncate">{item.command}</p>
                    {item.started_at && (
                      <p className="text-[10px] text-sawlah-dim/60 mt-0.5">{new Date(item.started_at).toLocaleString()}</p>
                    )}
                  </div>
                </button>
                {expandedHistory === idx && (
                  <div className="px-4 pb-3">
                    <div className="relative">
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(item.output || "");
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        }}
                        className="absolute top-2 right-2 flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors bg-black/50 px-2 py-1 rounded"
                      >
                        {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                        {copied ? "Copied" : "Copy"}
                      </button>
                      <div
                        className="font-mono text-xs leading-relaxed p-3 rounded-lg overflow-y-auto"
                        style={{ maxHeight: 250, background: "#050505" }}
                      >
                        {(item.output || "No output recorded").split("\n").map((line, i) => (
                          <div key={i} className="flex hover:bg-white/[0.02] -mx-1 px-1 rounded">
                            <span className="text-sawlah-dim/40 select-none w-8 text-right mr-3 shrink-0">{i + 1}</span>
                            <span className={`whitespace-pre-wrap break-all ${
                              line.includes("[+]") || line.includes("open") ? "text-sawlah-green" :
                              line.includes("[-]") || line.includes("ERROR") ? "text-sawlah-red" :
                              line.includes("[*]") || line.includes("[!]") ? "text-sawlah-yellow" :
                              "text-zinc-300"
                            }`}>{line || "\u00A0"}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
