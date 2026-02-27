import { useEffect, useRef } from "react";
import { Terminal as XTerminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { ChevronDown, ChevronUp, Trash2 } from "lucide-react";

export default function Terminal({ output, title = "Terminal Output", collapsed, onToggle }) {
  const termRef = useRef(null);
  const xtermRef = useRef(null);
  const fitRef = useRef(null);
  const writtenRef = useRef(0);

  useEffect(() => {
    if (!termRef.current || xtermRef.current) return;

    const xterm = new XTerminal({
      theme: {
        background: "#0a0a0a",
        foreground: "#e5e5e5",
        cursor: "#dc2626",
        cursorAccent: "#0a0a0a",
        selectionBackground: "#dc262644",
        black: "#0a0a0a",
        red: "#dc2626",
        green: "#4ade80",
        yellow: "#facc15",
        blue: "#60a5fa",
        magenta: "#c084fc",
        cyan: "#22d3ee",
        white: "#e5e5e5",
      },
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 13,
      lineHeight: 1.4,
      cursorBlink: true,
      scrollback: 10000,
      convertEol: true,
      disableStdin: true,
    });

    const fit = new FitAddon();
    xterm.loadAddon(fit);
    xterm.open(termRef.current);
    fit.fit();

    xtermRef.current = xterm;
    fitRef.current = fit;

    const resizeObs = new ResizeObserver(() => fit.fit());
    resizeObs.observe(termRef.current);

    return () => {
      resizeObs.disconnect();
      xterm.dispose();
      xtermRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!xtermRef.current || !output) return;
    const newData = output.slice(writtenRef.current);
    if (newData) {
      xtermRef.current.write(newData);
      writtenRef.current = output.length;
    }
  }, [output]);

  const clearTerminal = () => {
    if (xtermRef.current) {
      xtermRef.current.clear();
      writtenRef.current = 0;
    }
  };

  return (
    <div className="border-t border-sawlah-border bg-sawlah-bg flex flex-col">
      <div
        className="flex items-center justify-between px-4 py-2 bg-sawlah-surface cursor-pointer select-none border-b border-sawlah-border"
        onClick={onToggle}
      >
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-sawlah-red animate-pulse" />
          <span className="text-xs font-mono font-medium text-sawlah-muted uppercase tracking-wider">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); clearTerminal(); }}
            className="p-1 hover:bg-white/10 rounded text-sawlah-dim hover:text-sawlah-text transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          {collapsed ? <ChevronUp className="w-4 h-4 text-sawlah-dim" /> : <ChevronDown className="w-4 h-4 text-sawlah-dim" />}
        </div>
      </div>
      <div
        ref={termRef}
        className="transition-all duration-200"
        style={{ height: collapsed ? 0 : 280, overflow: "hidden" }}
      />
    </div>
  );
}
