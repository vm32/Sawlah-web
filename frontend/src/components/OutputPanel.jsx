import { useEffect, useRef, useState, useCallback } from "react";
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

function LiveTerminal({ output, runKey }) {
  const termRef = useRef(null);
  const xtermRef = useRef(null);
  const writtenRef = useRef(0);

  useEffect(() => {
    if (!termRef.current) return;
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }
    const xterm = new XTerminal({
      theme: {
        background: "#050505", foreground: "#e5e5e5", cursor: "#dc2626",
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
    fit.fit();
    xtermRef.current = xterm;
    writtenRef.current = 0;

    const obs = new ResizeObserver(() => { try { fit.fit(); } catch {} });
    obs.observe(termRef.current);
    return () => { obs.disconnect(); xterm.dispose(); xtermRef.current = null; };
  }, [runKey]);

  useEffect(() => {
    const xterm = xtermRef.current;
    if (!xterm) return;
    const text = output || "";
    const newData = text.slice(writtenRef.current);
    if (newData) {
      xterm.write(newData);
      writtenRef.current = text.length;
    }
  }, [output]);

  return <div ref={termRef} className="flex-1 min-h-0" />;
}

function colorLine(line) {
  if (/VULNERABLE|CRITICAL/i.test(line)) return "text-red-400 font-bold";
  if (/\[\+\]|open\s|SUCCESS|FOUND|\bvalid\b|Pwn3d/i.test(line)) return "text-emerald-400";
  if (/\[-\]|ERROR|FAIL|denied|refused|timeout/i.test(line)) return "text-red-400";
  if (/\[\*\]|\[!\]|WARNING|WARN/i.test(line)) return "text-yellow-400";
  if (/\d+\/(tcp|udp)\s+open/i.test(line)) return "text-emerald-400";
  if (/\d+\/(tcp|udp)\s+(closed|filtered)/i.test(line)) return "text-zinc-500";
  if (/^\|/i.test(line)) return "text-cyan-300";
  if (/^Nmap scan report|^Starting Nmap|^Host is up/i.test(line)) return "text-blue-400";
  return "text-zinc-400";
}

function StructuredOutput({ output }) {
  if (!output) return null;
  const allLines = output.split("\n");
  const lines = allLines.filter((l) => l.trim());

  const portLines = lines.filter((l) => /\d+\/(tcp|udp)\s+(open|closed|filtered)\s+\S+/.test(l));
  const findings = lines.filter((l) =>
    /\[\+\]|\[!\]|VULNERABLE|Pwn3d|SUCCESS|FOUND/i.test(l)
  );
  const subdomains = lines.filter((l) =>
    /^\s*[\w.-]+\.\w{2,}\s*$/i.test(l) || /\bfound:\s/i.test(l)
  );
  const hashMatches = lines.filter((l) => /\[Hashcat Mode:|Analyzing/i.test(l));
  const exploitLines = lines.filter((l) => /Exploit Title|Shellcodes|exploits\//i.test(l));

  return (
    <div className="space-y-3">
      {/* Nmap port table */}
      {portLines.length > 0 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">
            Ports ({portLines.length})
          </h4>
          <div className="bg-black/40 rounded-lg overflow-hidden border border-sawlah-border/30">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-sawlah-border/50">
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Port</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">State</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Service</th>
                  <th className="text-left px-3 py-1.5 text-sawlah-dim">Version</th>
                </tr>
              </thead>
              <tbody>
                {portLines.map((line, i) => {
                  const m = line.trim().match(/^(\d+\/\w+)\s+(\w+)\s+(\S+)\s*(.*)/);
                  if (!m) return null;
                  const stateColor = m[2] === "open" ? "text-emerald-400" : m[2] === "filtered" ? "text-yellow-400" : "text-zinc-500";
                  return (
                    <tr key={i} className="border-b border-sawlah-border/20 hover:bg-white/[0.02]">
                      <td className="px-3 py-1 text-sawlah-red font-semibold">{m[1]}</td>
                      <td className={`px-3 py-1 ${stateColor}`}>{m[2]}</td>
                      <td className="px-3 py-1 text-sawlah-text">{m[3]}</td>
                      <td className="px-3 py-1 text-sawlah-muted">{m[4]}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Hash identification results */}
      {hashMatches.length > 0 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">Hash Identification</h4>
          <div className="space-y-1">
            {lines.filter((l) => /^\[\+\]/.test(l)).map((l, i) => (
              <div key={i} className="text-xs font-mono px-3 py-1.5 rounded bg-emerald-500/10 text-emerald-400 border-l-2 border-emerald-500/50">
                {l.trim()}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Exploit search results */}
      {exploitLines.length > 0 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">
            Exploit Results ({exploitLines.filter((l) => /exploits\//i.test(l)).length})
          </h4>
          <div className="space-y-1">
            {exploitLines.filter((l) => /exploits\//i.test(l)).slice(0, 30).map((l, i) => (
              <div key={i} className="text-xs font-mono px-3 py-1.5 rounded bg-red-500/10 text-red-400 border-l-2 border-red-500/50">
                {l.trim()}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Key findings */}
      {findings.length > 0 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">
            Key Findings ({findings.length})
          </h4>
          <div className="space-y-1">
            {findings.slice(0, 50).map((f, i) => (
              <div key={i} className={`text-xs font-mono px-3 py-1.5 rounded ${
                /VULNERABLE|CRITICAL|Pwn3d/i.test(f) ? "bg-red-500/10 text-red-400 border-l-2 border-red-500" :
                /\[\+\]|SUCCESS|FOUND/i.test(f) ? "bg-emerald-500/10 text-emerald-400" :
                "bg-yellow-500/10 text-yellow-400"
              }`}>
                {f.trim()}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subdomains found */}
      {subdomains.length > 3 && (
        <div>
          <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-muted mb-2">
            Subdomains ({subdomains.length})
          </h4>
          <div className="bg-black/40 rounded-lg p-2 max-h-[150px] overflow-y-auto border border-sawlah-border/30">
            <div className="flex flex-wrap gap-1">
              {subdomains.slice(0, 100).map((s, i) => (
                <span key={i} className="text-[10px] font-mono px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">
                  {s.trim()}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Full raw output */}
      <div>
        <h4 className="text-[10px] uppercase tracking-wider font-bold text-sawlah-dim mb-2">
          Raw Output ({allLines.length} lines)
        </h4>
        <div className="bg-black/40 rounded-lg p-3 max-h-[300px] overflow-y-auto font-mono text-xs leading-relaxed border border-sawlah-border/30">
          {allLines.map((line, i) => (
            <div key={i} className="flex hover:bg-white/[0.03] -mx-1 px-1 rounded">
              <span className="text-sawlah-dim/25 select-none w-7 text-right mr-2 shrink-0">{i + 1}</span>
              <span className={`whitespace-pre-wrap break-all ${colorLine(line)}`}>{line || "\u00A0"}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function OutputPanel({
  onRun, onStop, status, command, output, history, toolName, showManual = true,
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
  const [runKey, setRunKey] = useState(0);

  const manualWs = useWebSocket();

  useEffect(() => {
    if (status === "running") {
      setTab("live");
      setRunKey((k) => k + 1);
    }
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
    setRunKey((k) => k + 1);
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
  const lineCount = (activeOutput || "").split("\n").length;

  return (
    <div
      className={`bg-sawlah-card border border-sawlah-border rounded-xl flex flex-col overflow-hidden transition-all ${
        expanded ? "fixed inset-4 z-50" : ""
      }`}
      style={{ minHeight: expanded ? undefined : 480 }}
    >
      {expanded && <div className="fixed inset-0 bg-black/60 -z-10" onClick={() => setExpanded(false)} />}

      {/* Top bar with Run + Kill */}
      <div className="flex items-center justify-between px-5 pt-4 pb-2">
        <div className="flex items-center gap-2">
          {!manualMode ? (
            <RunButton onClick={onRun} running={status === "running"} onStop={onStop} />
          ) : (
            <RunButton onClick={handleManualRun} running={manualStatus === "running"} onStop={handleManualStop} />
          )}
          {activeStatus && activeStatus !== "running" && <StatusBadge status={activeStatus} />}
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
              Manual
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
          <div className="flex items-center bg-black/50 border border-sawlah-border rounded-lg overflow-hidden focus-within:border-sawlah-red transition-colors">
            <span className="text-sawlah-red font-mono text-sm pl-3 select-none">$</span>
            <input
              value={manualCmd}
              onChange={(e) => setManualCmd(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleManualRun(); }}
              placeholder="nmap -sV -T4 10.129.231.23"
              className="flex-1 bg-transparent border-0 font-mono text-sm px-2 py-2 text-sawlah-green placeholder:text-sawlah-dim/40 focus:outline-none"
            />
          </div>
          <p className="text-[10px] text-sawlah-dim mt-1">
            Allowed: nmap, sqlmap, gobuster, ffuf, nikto, nxc, hydra, hashcat, hashid, searchsploit, etc.
          </p>
        </div>
      )}

      {!manualMode && command && <div className="px-5 pb-2"><CommandPreview command={command} /></div>}

      {/* Tabs */}
      <div className="flex border-b border-sawlah-border px-5">
        <button
          onClick={() => setTab("live")}
          className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            tab === "live" ? "border-sawlah-red text-sawlah-red" : "border-transparent text-sawlah-dim hover:text-sawlah-muted"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Live Terminal
          {activeStatus === "running" && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
        </button>
        <button
          onClick={() => setTab("history")}
          className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            tab === "history" ? "border-sawlah-red text-sawlah-red" : "border-transparent text-sawlah-dim hover:text-sawlah-muted"
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
                  <span className="text-[10px] text-sawlah-dim font-mono">{lineCount} lines</span>
                  {activeStatus === "running" && (
                    <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      streaming
                    </span>
                  )}
                </div>
                <button onClick={() => copyText(activeOutput)} className="flex items-center gap-1 text-[10px] text-sawlah-dim hover:text-sawlah-text transition-colors">
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
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
              <LiveTerminal output={activeOutput || ""} runKey={runKey} />
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
                        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        Copy
                      </button>
                    </div>
                    <StructuredOutput output={item.output} />
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
