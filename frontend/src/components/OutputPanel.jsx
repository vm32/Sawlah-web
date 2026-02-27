import { useEffect, useRef, useState } from "react";
import { Terminal as XTerminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import {
  Clock, Terminal, Copy, Check, ChevronDown, ChevronRight,
  ScrollText, TerminalSquare, Pencil, Maximize2, Minimize2
} from "lucide-react";
import StatusBadge from "./StatusBadge";
import { CommandPreview, RunButton } from "./ToolForm";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";

function LiveTerminal({ output }) {
  const termRef = useRef(null);
  const xtermRef = useRef(null);
  const fitRef = useRef(null);
  const writtenRef = useRef(0);

  useEffect(() => {
    if (!termRef.current) return;
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }

    const xterm = new XTerminal({
      theme: {
        background: "#050505",
        foreground: "#e5e5e5",
        cursor: "#dc2626",
        selectionBackground: "#dc262644",
        black: "#0a0a0a", red: "#dc2626", green: "#4ade80",
        yellow: "#facc15", blue: "#60a5fa", magenta: "#c084fc",
        cyan: "#22d3ee", white: "#e5e5e5",
      },
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 12, lineHeight: 1.3, cursorBlink: true,
      scrollback: 50000, convertEol: true, disableStdin: true,
    });
    const fit = new FitAddon();
    xterm.loadAddon(fit);
    xterm.open(termRef.current);
    setTimeout(() => fit.fit(), 50);
    xtermRef.current = xterm;
    fitRef.current = fit;
    writtenRef.current = 0;

    const obs = new ResizeObserver(() => { try { fit.fit(); } catch {} });
    obs.observe(termRef.current);
    return () => { obs.disconnect(); xterm.dispose(); xtermRef.current = null; };
  }, []);

  useEffect(() => {
    if (!xtermRef.current) return;
    if (!output) {
      xtermRef.current.clear();
      xtermRef.current.write("\x1b[2J\x1b[H");
      writtenRef.current = 0;
      return;
    }
    const newData = output.slice(writtenRef.current);
    if (newData) {
      xtermRef.current.write(newData);
      writtenRef.current = output.length;
    }
  }, [output]);

  return <div ref={termRef} className="flex-1 min-h-0" />;
}

function StructuredOutput({ output, command }) {
  if (!output) return null;
  const lines = output.split("\n").filter((l) => l.trim());

  const portLines = lines.filter((l) => /\d+\/(tcp|udp)\s+\w+/.test(l));
  const hasPortTable = portLines.length > 0;

  const findings = lines.filter((l) =>
    /\[\+\]|\[!\]|VULNERABLE|found|open|SUCCESS|valid/i.test(l)
  );

  return (
    <div className="space-y-3">
      {hasPortTable && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">Open Ports</h4>
          <div className="bg-black/30 rounded-lg overflow-hidden">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-sawlah-border">
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Port</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">State</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Service</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Version</th>
                </tr>
              </thead>
              <tbody>
                {portLines.map((line, i) => {
                  const parts = line.trim().split(/\s+/);
                  return (
                    <tr key={i} className="border-b border-sawlah-border/30 hover:bg-white/[0.02]">
                      <td className="px-3 py-1 text-sawlah-red">{parts[0]}</td>
                      <td className="px-3 py-1 text-sawlah-green">{parts[1]}</td>
                      <td className="px-3 py-1 text-sawlah-text">{parts[2] || ""}</td>
                      <td className="px-3 py-1 text-sawlah-muted">{parts.slice(3).join(" ")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {findings.length > 0 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">
            Key Findings ({findings.length})
          </h4>
          <div className="space-y-1">
            {findings.slice(0, 50).map((f, i) => (
              <div key={i} className={`text-xs font-mono px-3 py-1.5 rounded ${
                /VULNERABLE|CRITICAL/i.test(f) ? "bg-red-500/10 text-sawlah-red border-l-2 border-sawlah-red" :
                /\[\+\]|SUCCESS|found|open/i.test(f) ? "bg-green-500/10 text-sawlah-green" :
                "bg-yellow-500/10 text-sawlah-yellow"
              }`}>
                {f.trim()}
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-dim mb-2">
          Raw Output ({lines.length} lines)
        </h4>
        <div className="bg-black/30 rounded-lg p-3 max-h-[250px] overflow-y-auto font-mono text-xs leading-relaxed">
          {output.split("\n").map((line, i) => (
            <div key={i} className="flex hover:bg-white/[0.02]">
              <span className="text-sawlah-dim/30 select-none w-7 text-right mr-2 shrink-0">{i + 1}</span>
              <span className={`whitespace-pre-wrap break-all ${
                /\[\+\]|open|SUCCESS/i.test(line) ? "text-sawlah-green" :
                /\[-\]|ERROR|FAIL|error/i.test(line) ? "text-sawlah-red" :
                /\[\*\]|\[!\]|WARNING/i.test(line) ? "text-sawlah-yellow" :
                /VULNERABLE|CRITICAL/i.test(line) ? "text-sawlah-red font-bold" :
                "text-zinc-400"
              }`}>{line || "\u00A0"}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function OutputPanel({
  onRun, onStop, status, command, output, history,
  toolName, showManual = true,
}) {
  const [tab, setTab] = useState("live");
  const [expandedHistory, setExpandedHistory] = useState(null);
  const [copied, setCopied] = useState(false);
  const [manualMode, setManualMode] = useState(false);
  const [manualCmd, setManualCmd] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [manualTaskId, setManualTaskId] = useState(null);
  const [manualStatus, setManualStatus] = useState(null);
  const [manualOutput, setManualOutput] = useState("");

  const manualWs = useWebSocket();

  useEffect(() => {
    if (status === "running") setTab("live");
  }, [status]);

  useEffect(() => {
    if (manualWs.output) setManualOutput(manualWs.output);
  }, [manualWs.output]);

  useEffect(() => {
    if (!manualTaskId) return;
    const interval = setInterval(async () => {
      try {
        const res = await toolsApi.status(manualTaskId);
        setManualStatus(res.data.status);
        if (["completed", "error", "killed"].includes(res.data.status)) clearInterval(interval);
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [manualTaskId]);

  const handleManualRun = async () => {
    if (!manualCmd.trim()) return;
    manualWs.reset();
    setManualOutput("");
    setManualStatus("running");
    setTab("live");
    try {
      const res = await toolsApi.runRaw(manualCmd.trim(), toolName || "manual");
      if (res.data.error) {
        setManualOutput(`Error: ${res.data.error}\n`);
        setManualStatus("error");
        return;
      }
      setManualTaskId(res.data.task_id);
      manualWs.connect(res.data.task_id);
    } catch (err) {
      setManualOutput(`Error: ${err.message}\n`);
      setManualStatus("error");
    }
  };

  const handleManualStop = async () => {
    if (manualTaskId) {
      await toolsApi.kill(manualTaskId);
      setManualStatus("killed");
    }
  };

  const copyText = (text) => {
    navigator.clipboard.writeText(text || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const activeOutput = manualMode ? manualOutput : output;
  const activeStatus = manualMode ? manualStatus : status;
  const historyItems = history || [];

  return (
    <div
      className={`bg-sawlah-card border border-sawlah-border rounded-xl flex flex-col overflow-hidden transition-all ${
        expanded ? "fixed inset-4 z-50" : ""
      }`}
      style={{ minHeight: expanded ? undefined : 480 }}
    >
      {expanded && <div className="fixed inset-0 bg-black/60 -z-10" onClick={() => setExpanded(false)} />}

      {/* Top bar */}
      <div className="flex items-center justify-between px-5 pt-4 pb-2">
        <div className="flex items-center gap-2">
          {!manualMode ? (
            <RunButton onClick={onRun} running={status === "running"} onStop={onStop} />
          ) : (
            <RunButton onClick={handleManualRun} running={manualStatus === "running"} onStop={handleManualStop} />
          )}
          {activeStatus && <StatusBadge status={activeStatus} />}
        </div>
        <div className="flex items-center gap-1">
          {showManual && (
            <button
              onClick={() => setManualMode(!manualMode)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all ${
                manualMode
                  ? "bg-sawlah-red/15 text-sawlah-red border border-sawlah-red/30"
                  : "text-sawlah-dim hover:text-sawlah-muted hover:bg-white/5 border border-transparent"
              }`}
            >
              {manualMode ? <TerminalSquare className="w-3.5 h-3.5" /> : <Pencil className="w-3.5 h-3.5" />}
              {manualMode ? "Manual" : "Manual"}
            </button>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1.5 text-sawlah-dim hover:text-sawlah-muted hover:bg-white/5 rounded transition-colors"
          >
            {expanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Manual command input */}
      {manualMode && (
        <div className="px-5 pb-2">
          <div className="flex gap-2">
            <div className="flex-1 flex items-center bg-black/50 border border-sawlah-border rounded-lg overflow-hidden focus-within:border-sawlah-red transition-colors">
              <span className="text-sawlah-red font-mono text-sm pl-3 select-none">$</span>
              <input
                value={manualCmd}
                onChange={(e) => setManualCmd(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleManualRun(); }}
                placeholder="nmap -sV -T4 192.168.1.1"
                className="flex-1 bg-transparent border-0 font-mono text-sm px-2 py-2 text-sawlah-green placeholder:text-sawlah-dim/40 focus:outline-none"
              />
            </div>
          </div>
          <p className="text-[10px] text-sawlah-dim mt-1">
            Enter any pentesting command. Allowed tools: nmap, sqlmap, gobuster, ffuf, nikto, nxc, hydra, etc.
          </p>
        </div>
      )}

      {!manualMode && command && <div className="px-5 pb-2"><CommandPreview command={command} /></div>}

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
          Live Terminal
          {activeStatus === "running" && <span className="w-1.5 h-1.5 rounded-full bg-sawlah-green animate-pulse" />}
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

      {/* Content */}
      <div className="flex-1 flex flex-col min-h-0" style={{ height: expanded ? "calc(100vh - 250px)" : 300 }}>
        {tab === "live" && (
          <>
            {activeOutput && (
              <div className="flex items-center justify-between px-4 py-1 bg-sawlah-surface/30 border-b border-sawlah-border">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] text-sawlah-dim font-mono">{(activeOutput || "").split("\n").length} lines</span>
                  {activeStatus === "running" && (
                    <span className="flex items-center gap-1 text-[10px] text-sawlah-green">
                      <span className="w-1.5 h-1.5 rounded-full bg-sawlah-green animate-pulse" />
                      streaming
                    </span>
                  )}
                </div>
                <button onClick={() => copyText(activeOutput)} className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors">
                  {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
            )}
            {!activeOutput && !activeStatus && (
              <div className="flex-1 flex flex-col items-center justify-center text-sawlah-dim">
                <ScrollText className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">{manualMode ? "Type a command and press Enter" : "Configure options and click Run"}</p>
                <p className="text-[11px] mt-1">Real-time terminal output appears here</p>
              </div>
            )}
            {(activeOutput || activeStatus === "running") && (
              <LiveTerminal output={activeOutput || ""} />
            )}
          </>
        )}

        {tab === "history" && (
          <div className="flex-1 overflow-y-auto">
            {historyItems.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-sawlah-dim py-12">
                <Clock className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">No scan history yet</p>
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
                    <div className="flex justify-end mb-2">
                      <button
                        onClick={() => copyText(item.output)}
                        className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors"
                      >
                        {copied ? <Check className="w-3 h-3 text-sawlah-green" /> : <Copy className="w-3 h-3" />}
                        Copy
                      </button>
                    </div>
                    <StructuredOutput output={item.output} command={item.command} />
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
