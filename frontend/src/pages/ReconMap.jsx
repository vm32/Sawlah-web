import { useState, useEffect, useCallback, memo } from "react";
import { ReactFlow, Background, Controls, MiniMap, Handle, Position, useNodesState, useEdgesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Map, Target, Wifi, Server, AlertTriangle, Globe, FolderOpen,
  RefreshCw, Cpu, Bug, Shield, Lock, FileText, Loader2, Zap,
  X, Terminal, ChevronDown, ChevronRight,
} from "lucide-react";
import { PageHeader, SelectInput } from "../components/ToolForm";
import useWebSocket from "../hooks/useWebSocket";
import { toolsApi } from "../api/client";

/* ---------- Node components ---------- */

const TargetNode = memo(({ data }) => (
  <div className="relative group cursor-pointer">
    <Handle type="source" position={Position.Right} className="!bg-sawlah-red !w-2 !h-2" />
    <Handle type="source" position={Position.Bottom} className="!bg-sawlah-red !w-2 !h-2" id="b" />
    <Handle type="source" position={Position.Left} className="!bg-sawlah-red !w-2 !h-2" id="l" />
    <Handle type="source" position={Position.Top} className="!bg-sawlah-red !w-2 !h-2" id="t" />
    <div className="px-5 py-4 rounded-2xl bg-gradient-to-br from-red-900/80 to-red-950/80 border-2 border-sawlah-red shadow-xl shadow-sawlah-red-glow text-center min-w-[140px]">
      <Target className="w-6 h-6 text-sawlah-red mx-auto mb-1" />
      <p className="text-sm font-bold text-white">{data.label}</p>
      <p className="text-[9px] text-red-300 mt-0.5">{data.scans} scans</p>
    </div>
  </div>
));
const PortNode = memo(({ data }) => (
  <div className="group cursor-pointer">
    <Handle type="target" position={Position.Left} className="!bg-emerald-500 !w-2 !h-2" />
    <Handle type="source" position={Position.Right} className="!bg-emerald-500 !w-2 !h-2" />
    <div className={`px-3 py-2 rounded-xl border text-center min-w-[100px] ${data.state === "open" ? "bg-emerald-500/10 border-emerald-500/40" : data.state === "filtered" ? "bg-yellow-500/10 border-yellow-500/40" : "bg-zinc-800/50 border-zinc-600/40"}`}>
      <Wifi className={`w-4 h-4 mx-auto mb-0.5 ${data.state === "open" ? "text-emerald-400" : data.state === "filtered" ? "text-yellow-400" : "text-zinc-500"}`} />
      <p className="text-xs font-bold text-white">{data.port}/{data.proto}</p>
      <p className="text-[9px] text-sawlah-muted">{data.service}</p>
      {data.version && <p className="text-[8px] text-emerald-600 truncate max-w-[120px]">{data.version}</p>}
    </div>
  </div>
));
const ServiceNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Left} className="!bg-cyan-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 min-w-[120px] max-w-[200px]">
      <Server className="w-3.5 h-3.5 text-cyan-400 mb-0.5" /><p className="text-[10px] font-mono text-cyan-300 break-all">{data.label}</p>
    </div></div>
));
const SubdomainNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Left} className="!bg-blue-500 !w-2 !h-2" />
    <div className="px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30">
      <Globe className="w-3 h-3 text-blue-400 inline mr-1" /><span className="text-[10px] font-mono text-blue-300">{data.label}</span>
    </div></div>
));
const VulnNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Top} className="!bg-red-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/40 max-w-[220px]">
      <AlertTriangle className="w-3.5 h-3.5 text-red-400 mb-0.5" /><p className="text-[9px] font-mono text-red-300 break-all">{data.label}</p>
    </div></div>
));
const DirectoryNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Top} className="!bg-purple-500 !w-2 !h-2" />
    <div className="px-3 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30">
      <FolderOpen className="w-3 h-3 text-purple-400 inline mr-1" /><span className="text-[10px] font-mono text-purple-300">{data.url}</span>
      {data.status > 0 && <span className={`text-[9px] ml-1 ${data.status < 400 ? "text-emerald-400" : "text-yellow-400"}`}>({data.status})</span>}
    </div></div>
));
const TechnologyNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Bottom} className="!bg-cyan-500 !w-2 !h-2" /><Handle type="source" position={Position.Left} className="!bg-cyan-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-xl bg-gradient-to-br from-cyan-500/15 to-cyan-900/15 border border-cyan-500/30 min-w-[100px] text-center">
      <Cpu className="w-4 h-4 text-cyan-400 mx-auto mb-0.5" /><p className="text-[11px] font-bold text-cyan-300">{data.name}</p>
      {data.version && <p className="text-[9px] text-cyan-500">v{data.version}</p>}
      <p className="text-[8px] text-cyan-700 uppercase tracking-wider mt-0.5">{data.category}</p>
    </div></div>
));
const ExploitNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Top} className="!bg-orange-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-xl bg-gradient-to-br from-orange-500/15 to-red-900/15 border border-orange-500/40 max-w-[240px]">
      <Bug className="w-3.5 h-3.5 text-orange-400 mb-0.5" /><p className="text-[10px] font-bold text-orange-300 break-all leading-snug">{data.title}</p>
      <p className="text-[8px] font-mono text-orange-600 mt-0.5">{data.path}</p>
    </div></div>
));
const WafNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Right} className="!w-2 !h-2" style={{ background: data.detected ? "#4ade80" : "#ef4444" }} />
    <div className={`px-4 py-3 rounded-xl border-2 min-w-[140px] text-center ${data.detected ? "bg-emerald-500/10 border-emerald-500/40" : "bg-red-500/10 border-red-500/40"}`}>
      <Shield className={`w-5 h-5 mx-auto mb-1 ${data.detected ? "text-emerald-400" : "text-red-400"}`} />
      <p className="text-[11px] font-bold text-white">{data.detected ? "WAF Active" : "No WAF"}</p>
      <p className="text-[9px] text-sawlah-muted mt-0.5">{data.name || "Unknown"}</p>
    </div></div>
));
const WhoisNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Left} className="!bg-amber-500 !w-2 !h-2" />
    <div className="px-4 py-3 rounded-xl bg-amber-500/10 border border-amber-500/30 min-w-[160px] max-w-[220px]">
      <FileText className="w-4 h-4 text-amber-400 mb-1" /><p className="text-[11px] font-bold text-amber-300">WHOIS</p>
      {data.registrar && <p className="text-[9px] text-amber-500 truncate">{data.registrar}</p>}
      {data.org && <p className="text-[9px] text-amber-600 truncate">{data.org}</p>}
      {data.country && <p className="text-[9px] text-amber-700">{data.country}</p>}
    </div></div>
));
const SslNode = memo(({ data }) => (
  <div className="cursor-pointer"><Handle type="target" position={Position.Bottom} className="!bg-green-500 !w-2 !h-2" />
    <div className="px-4 py-3 rounded-xl bg-green-500/10 border border-green-500/30 min-w-[160px] max-w-[240px]">
      <Lock className="w-4 h-4 text-green-400 mb-1" /><p className="text-[11px] font-bold text-green-300">SSL/TLS</p>
      {data.cert_subject && <p className="text-[9px] text-green-500 truncate">{data.cert_subject}</p>}
      {data.cert_issuer && <p className="text-[9px] text-green-600 truncate">{data.cert_issuer}</p>}
      {data.cert_expiry && <p className="text-[8px] text-green-700 mt-0.5">Expires: {data.cert_expiry}</p>}
    </div></div>
));

const nodeTypes = {
  target: TargetNode, port: PortNode, service: ServiceNode, subdomain: SubdomainNode,
  vuln: VulnNode, directory: DirectoryNode, technology: TechnologyNode, exploit: ExploitNode,
  waf: WafNode, whois: WhoisNode, ssl: SslNode,
};
const defaultEdgeOptions = { animated: true, style: { stroke: "#dc2626", strokeWidth: 1.5 } };

/* ---------- Detail panel for clicked nodes ---------- */

function NodeDetailPanel({ node, onClose, scanDetails }) {
  if (!node) return null;
  const { type, data } = node;

  const relatedScans = (scanDetails || []).filter((s) => {
    if (type === "port" || type === "service") return s.tool === "nmap";
    if (type === "waf") return s.tool === "wafw00f";
    if (type === "whois") return s.tool === "whois";
    if (type === "ssl") return s.tool === "sslscan";
    if (type === "technology") return s.tool === "whatweb";
    if (type === "subdomain") return ["gobuster_dns", "dnsenum", "fierce", "dnsrecon", "subenum_all"].includes(s.tool);
    if (type === "directory") return ["gobuster_dir", "ffuf", "dirb", "subenum_all"].includes(s.tool);
    if (type === "exploit") return s.tool === "searchsploit";
    if (type === "vuln") return s.tool === "nmap";
    return false;
  });

  const typeLabels = {
    target: "Target", port: "Open Port", service: "Service", subdomain: "Subdomain",
    vuln: "Vulnerability", directory: "Directory", technology: "Technology",
    exploit: "Exploit", waf: "WAF Status", whois: "WHOIS Info", ssl: "SSL/TLS",
  };
  const typeColors = {
    target: "text-sawlah-red", port: "text-emerald-400", service: "text-cyan-400",
    subdomain: "text-blue-400", vuln: "text-red-400", directory: "text-purple-400",
    technology: "text-cyan-400", exploit: "text-orange-400", waf: "text-emerald-400",
    whois: "text-amber-400", ssl: "text-green-400",
  };

  return (
    <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-sawlah-border/50 bg-sawlah-surface/50">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold uppercase tracking-wider ${typeColors[type] || "text-sawlah-muted"}`}>{typeLabels[type] || type}</span>
        </div>
        <button onClick={onClose} className="p-1 text-sawlah-dim hover:text-sawlah-red transition-colors"><X className="w-4 h-4" /></button>
      </div>
      <div className="p-4 space-y-3 max-h-[350px] overflow-y-auto">
        {/* Node-specific detail */}
        <div className="space-y-1.5">
          {type === "port" && (<>
            <DetailRow label="Port" value={`${data.port}/${data.proto}`} />
            <DetailRow label="State" value={data.state} valueClass={data.state === "open" ? "text-emerald-400" : "text-yellow-400"} />
            <DetailRow label="Service" value={data.service} />
            {data.version && <DetailRow label="Version" value={data.version} />}
          </>)}
          {type === "waf" && (<>
            <DetailRow label="Status" value={data.detected ? "WAF Detected" : "No WAF"} valueClass={data.detected ? "text-emerald-400" : "text-red-400"} />
            <DetailRow label="WAF Name" value={data.name || "N/A"} />
            {data.details && <DetailRow label="Details" value={data.details} />}
          </>)}
          {type === "whois" && (<>
            {data.registrar && <DetailRow label="Registrar" value={data.registrar} />}
            {data.org && <DetailRow label="Organization" value={data.org} />}
            {data.country && <DetailRow label="Country" value={data.country} />}
            {data.created && <DetailRow label="Created" value={data.created} />}
            {data.expires && <DetailRow label="Expires" value={data.expires} />}
            {data.nameservers && <DetailRow label="Nameservers" value={data.nameservers.join(", ")} />}
          </>)}
          {type === "ssl" && (<>
            {data.cert_subject && <DetailRow label="Subject" value={data.cert_subject} />}
            {data.cert_issuer && <DetailRow label="Issuer" value={data.cert_issuer} />}
            {data.cert_expiry && <DetailRow label="Expires" value={data.cert_expiry} />}
            {data.protocols?.length > 0 && <DetailRow label="Protocols" value={data.protocols.join("; ")} />}
          </>)}
          {type === "technology" && (<>
            <DetailRow label="Name" value={data.name} />
            {data.version && <DetailRow label="Version" value={data.version} />}
            <DetailRow label="Category" value={data.category} />
          </>)}
          {type === "subdomain" && <DetailRow label="FQDN" value={data.label} />}
          {type === "directory" && (<>
            <DetailRow label="Path" value={data.url} />
            {data.status > 0 && <DetailRow label="HTTP Status" value={String(data.status)} valueClass={data.status < 400 ? "text-emerald-400" : "text-yellow-400"} />}
          </>)}
          {type === "vuln" && <DetailRow label="Finding" value={data.label} valueClass="text-red-400" />}
          {type === "exploit" && (<>
            <DetailRow label="Title" value={data.title} />
            <DetailRow label="Path" value={data.path} />
          </>)}
          {type === "target" && (<>
            <DetailRow label="Target" value={data.label} />
            <DetailRow label="Total Scans" value={String(data.scans)} />
          </>)}
        </div>

        {relatedScans.length > 0 && (
          <div className="pt-2 border-t border-sawlah-border/50">
            <p className="text-[10px] font-bold uppercase tracking-wider text-sawlah-muted mb-2 flex items-center gap-1">
              <Terminal className="w-3 h-3" /> Related Scan Output
            </p>
            {relatedScans.map((s, i) => (
              <ScanOutputBlock key={i} scan={s} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, valueClass = "text-sawlah-text" }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-[10px] text-sawlah-dim uppercase tracking-wider w-24 shrink-0 pt-0.5">{label}</span>
      <span className={`text-xs font-mono break-all ${valueClass}`}>{value}</span>
    </div>
  );
}

function ScanOutputBlock({ scan }) {
  const [expanded, setExpanded] = useState(false);
  const [fullOutput, setFullOutput] = useState(null);

  const loadFull = async () => {
    if (fullOutput !== null || !scan.task_id) return;
    try {
      const res = await toolsApi.status(scan.task_id);
      setFullOutput(res.data.output || "No output available");
    } catch { setFullOutput("Failed to load output"); }
  };

  return (
    <div className="border border-sawlah-border/50 rounded-lg mb-2 overflow-hidden">
      <button
        onClick={() => { setExpanded(!expanded); if (!expanded) loadFull(); }}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.02] text-left"
      >
        {expanded ? <ChevronDown className="w-3 h-3 text-sawlah-dim" /> : <ChevronRight className="w-3 h-3 text-sawlah-dim" />}
        <span className="text-[10px] font-bold text-sawlah-red">{scan.tool}</span>
        <span className={`text-[9px] ml-auto ${scan.status === "completed" ? "text-emerald-500" : "text-sawlah-dim"}`}>{scan.status}</span>
      </button>
      {expanded && (
        <div className="border-t border-sawlah-border/50 bg-black/20">
          {scan.command && (
            <div className="px-3 py-1.5 border-b border-sawlah-border/30">
              <p className="text-[9px] text-sawlah-dim">Command:</p>
              <p className="text-[10px] font-mono text-sawlah-red break-all">$ {scan.command}</p>
            </div>
          )}
          <div className="px-3 py-2 font-mono text-[9px] leading-relaxed max-h-[200px] overflow-y-auto whitespace-pre-wrap text-zinc-400">
            {fullOutput || scan.output_preview || "Loading..."}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------- Info table sections below the map ---------- */

function InfoTabs({ summary }) {
  const [tab, setTab] = useState("ports");
  if (!summary) return null;

  const tabs = [
    { id: "ports", label: "Ports", count: summary.ports?.length || 0, color: "text-emerald-400" },
    { id: "vulns", label: "Vulnerabilities", count: summary.vulns?.length || 0, color: "text-red-400" },
    { id: "subdomains", label: "Subdomains", count: summary.subdomains?.length || 0, color: "text-blue-400" },
    { id: "technologies", label: "Technologies", count: summary.technologies?.length || 0, color: "text-cyan-400" },
    { id: "directories", label: "Directories", count: summary.directories?.length || 0, color: "text-purple-400" },
    { id: "exploits", label: "Exploits", count: summary.exploits?.length || 0, color: "text-orange-400" },
  ];

  return (
    <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
      <div className="flex border-b border-sawlah-border/50 overflow-x-auto">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors border-b-2 ${
              tab === t.id ? `${t.color} border-current` : "text-sawlah-dim border-transparent hover:text-sawlah-muted"}`}>
            {t.label}
            {t.count > 0 && <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${tab === t.id ? "bg-white/10" : "bg-white/5"}`}>{t.count}</span>}
          </button>
        ))}
      </div>
      <div className="p-4 max-h-[300px] overflow-y-auto">
        {tab === "ports" && <PortsTable ports={summary.ports || []} />}
        {tab === "vulns" && <VulnsTable vulns={summary.vulns || []} />}
        {tab === "subdomains" && <SubdomainsTable subs={summary.subdomains || []} />}
        {tab === "technologies" && <TechTable techs={summary.technologies || []} />}
        {tab === "directories" && <DirsTable dirs={summary.directories || []} />}
        {tab === "exploits" && <ExploitsTable exploits={summary.exploits || []} />}
      </div>
    </div>
  );
}

function PortsTable({ ports }) {
  if (ports.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No open ports discovered</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr className="text-[9px] text-sawlah-dim uppercase tracking-wider border-b border-sawlah-border/50">
        <th className="text-left py-2 px-2">Port</th><th className="text-left py-2 px-2">Proto</th>
        <th className="text-left py-2 px-2">State</th><th className="text-left py-2 px-2">Service</th><th className="text-left py-2 px-2">Version</th>
      </tr></thead>
      <tbody>{ports.map((p, i) => (
        <tr key={i} className="border-b border-sawlah-border/30 hover:bg-white/[0.02]">
          <td className="py-1.5 px-2 font-mono font-bold text-emerald-400">{p.port}</td>
          <td className="py-1.5 px-2 text-sawlah-muted">{p.proto}</td>
          <td className="py-1.5 px-2"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${p.state === "open" ? "bg-emerald-500/20 text-emerald-400" : "bg-yellow-500/20 text-yellow-400"}`}>{p.state}</span></td>
          <td className="py-1.5 px-2 text-sawlah-text">{p.service}</td>
          <td className="py-1.5 px-2 text-sawlah-dim font-mono text-[10px]">{p.version || "-"}</td>
        </tr>
      ))}</tbody>
    </table>
  );
}
function VulnsTable({ vulns }) {
  if (vulns.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No vulnerabilities detected</p>;
  return (
    <div className="space-y-2">{vulns.map((v, i) => (
      <div key={i} className="flex items-start gap-2 px-2 py-2 bg-red-500/5 border border-red-500/20 rounded-lg">
        <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
        <p className="text-[10px] font-mono text-red-300 break-all">{v}</p>
      </div>
    ))}</div>
  );
}
function SubdomainsTable({ subs }) {
  if (subs.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No subdomains discovered</p>;
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-1.5">{subs.map((s, i) => (
      <div key={i} className="flex items-center gap-1.5 px-2 py-1.5 bg-blue-500/5 border border-blue-500/20 rounded-lg">
        <Globe className="w-3 h-3 text-blue-400 shrink-0" /><span className="text-[10px] font-mono text-blue-300 truncate">{s}</span>
      </div>
    ))}</div>
  );
}
function TechTable({ techs }) {
  if (techs.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No technologies detected</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr className="text-[9px] text-sawlah-dim uppercase tracking-wider border-b border-sawlah-border/50">
        <th className="text-left py-2 px-2">Name</th><th className="text-left py-2 px-2">Version</th><th className="text-left py-2 px-2">Category</th>
      </tr></thead>
      <tbody>{techs.map((t, i) => (
        <tr key={i} className="border-b border-sawlah-border/30 hover:bg-white/[0.02]">
          <td className="py-1.5 px-2 font-bold text-cyan-300">{t.name}</td>
          <td className="py-1.5 px-2 font-mono text-cyan-500">{t.version || "-"}</td>
          <td className="py-1.5 px-2"><span className="px-1.5 py-0.5 rounded text-[9px] bg-cyan-500/10 text-cyan-400">{t.category}</span></td>
        </tr>
      ))}</tbody>
    </table>
  );
}
function DirsTable({ dirs }) {
  if (dirs.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No directories found</p>;
  return (
    <table className="w-full text-xs">
      <thead><tr className="text-[9px] text-sawlah-dim uppercase tracking-wider border-b border-sawlah-border/50">
        <th className="text-left py-2 px-2">Path</th><th className="text-left py-2 px-2">Status</th>
      </tr></thead>
      <tbody>{dirs.map((d, i) => (
        <tr key={i} className="border-b border-sawlah-border/30 hover:bg-white/[0.02]">
          <td className="py-1.5 px-2 font-mono text-purple-300">{d.url || d.path}</td>
          <td className="py-1.5 px-2"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${d.status < 400 ? "bg-emerald-500/20 text-emerald-400" : "bg-yellow-500/20 text-yellow-400"}`}>{d.status}</span></td>
        </tr>
      ))}</tbody>
    </table>
  );
}
function ExploitsTable({ exploits }) {
  if (exploits.length === 0) return <p className="text-xs text-sawlah-dim text-center py-4">No exploits found</p>;
  return (
    <div className="space-y-1.5">{exploits.map((e, i) => (
      <div key={i} className="px-3 py-2 bg-orange-500/5 border border-orange-500/20 rounded-lg">
        <p className="text-[10px] font-bold text-orange-300">{e.title}</p>
        <p className="text-[9px] font-mono text-orange-600">{e.path}</p>
      </div>
    ))}</div>
  );
}

/* ---------- Main component ---------- */

export default function ReconMap({ setOutput, setTitle, activeProject }) {
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [customTarget, setCustomTarget] = useState("");
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanTaskId, setScanTaskId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Recon Map"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadTargets = useCallback(async () => {
    try {
      const res = await fetch("/api/map/targets");
      const data = await res.json();
      setTargets(data);
      if (data.length > 0 && !selectedTarget) setSelectedTarget(data[0].target);
    } catch {}
  }, [selectedTarget]);

  useEffect(() => { loadTargets(); }, []);

  const loadMap = useCallback(async () => {
    if (!selectedTarget) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/map/targets/${encodeURIComponent(selectedTarget)}`);
      const data = await res.json();
      setNodes(data.nodes || []);
      setEdges((data.edges || []).map((e) => ({ ...e, ...defaultEdgeOptions })));
      setSummary(data.summary || null);
    } catch {}
    setLoading(false);
  }, [selectedTarget, setNodes, setEdges]);

  useEffect(() => { loadMap(); }, [loadMap]);

  useEffect(() => {
    if (!scanTaskId) return;
    const interval = setInterval(async () => {
      try {
        const res = await toolsApi.status(scanTaskId);
        if (["completed", "error", "killed"].includes(res.data.status)) {
          setScanning(false);
          clearInterval(interval);
          await loadTargets();
          const t = customTarget.trim() || selectedTarget;
          if (t) setSelectedTarget(t.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);
          setTimeout(() => loadMap(), 500);
        }
      } catch {}
    }, 3000);
    return () => clearInterval(interval);
  }, [scanTaskId, loadTargets, loadMap, customTarget, selectedTarget]);

  const handleAutoScan = async () => {
    const t = customTarget.trim() || selectedTarget;
    if (!t) return;
    setScanning(true); ws.reset(); setOutput("");
    try {
      const res = await fetch("/api/map/auto-scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t, project_id: activeProject || null }),
      });
      const data = await res.json();
      if (data.error) { setOutput(`Error: ${data.error}\n`); setScanning(false); return; }
      setScanTaskId(data.task_id); ws.connect(data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); setScanning(false); }
  };

  const onNodeClick = useCallback((_, node) => { setSelectedNode(node); }, []);

  const targetOptions = targets.map((t) => ({
    value: t.target,
    label: `${t.target} (${t.ports?.length || 0} ports, ${t.scans?.length || 0} scans)`,
  }));

  return (
    <div>
      <PageHeader title="Recon Map" description="Visual target topology and attack surface" icon={Map} />

      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="flex-1 min-w-[200px] max-w-md">
          <SelectInput value={selectedTarget} onChange={(v) => { setSelectedTarget(v); setSelectedNode(null); }}
            options={targetOptions.length > 0 ? targetOptions : [{ value: "", label: "No targets scanned yet" }]} />
        </div>
        <div className="flex items-center gap-2">
          <input value={customTarget} onChange={(e) => setCustomTarget(e.target.value)}
            placeholder="New target (e.g. example.com)"
            className="bg-sawlah-surface border border-sawlah-border rounded-lg px-3 py-2 text-xs text-sawlah-text placeholder:text-sawlah-dim/50 focus:outline-none focus:border-sawlah-red/50 w-56" />
          <button onClick={handleAutoScan} disabled={scanning || (!customTarget.trim() && !selectedTarget)}
            className="flex items-center gap-2 px-4 py-2 bg-sawlah-red text-white rounded-lg text-xs font-semibold hover:bg-sawlah-red-hover transition-colors shadow-lg shadow-sawlah-red-glow disabled:opacity-40 disabled:shadow-none">
            {scanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            {scanning ? "Scanning..." : "Run Full Recon"}
          </button>
          <button onClick={() => { loadTargets(); loadMap(); }}
            className="flex items-center gap-2 px-3 py-2 text-sawlah-dim hover:text-sawlah-text hover:bg-white/5 rounded-lg transition-colors text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {scanning && (
        <div className="mb-4 bg-sawlah-card border border-sawlah-red/30 rounded-xl p-3">
          <div className="flex items-center gap-2 mb-2">
            <Loader2 className="w-4 h-4 text-sawlah-red animate-spin" />
            <span className="text-xs font-semibold text-sawlah-text">Auto-Recon in progress...</span>
            <span className="text-[10px] text-sawlah-dim">nmap + whatweb + whois + wafw00f + sslscan + gobuster_dns</span>
          </div>
          <div className="h-1.5 bg-sawlah-surface rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-sawlah-red to-red-400 rounded-full animate-pulse" style={{ width: "100%" }} />
          </div>
        </div>
      )}

      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-4 md:grid-cols-8 gap-2 mb-4">
          {[
            { label: "Ports", value: summary.ports?.length || 0, color: "text-emerald-400" },
            { label: "Services", value: summary.services?.length || 0, color: "text-cyan-400" },
            { label: "Subdomains", value: summary.subdomains?.length || 0, color: "text-blue-400" },
            { label: "Directories", value: summary.directories?.length || 0, color: "text-purple-400" },
            { label: "Technologies", value: summary.technologies?.length || 0, color: "text-cyan-400" },
            { label: "Exploits", value: summary.exploits?.length || 0, color: "text-orange-400" },
            { label: "Vulns", value: summary.vulns?.length || 0, color: "text-red-400" },
            { label: "WAF", value: summary.waf_status?.detected ? "Yes" : (summary.waf_status ? "No" : "N/A"), color: summary.waf_status?.detected ? "text-emerald-400" : "text-red-400" },
          ].map((s) => (
            <div key={s.label} className="bg-sawlah-card border border-sawlah-border rounded-xl px-3 py-2 text-center">
              <p className={`text-lg font-bold ${s.color}`}>{s.value}</p>
              <p className="text-[8px] text-sawlah-dim uppercase tracking-wider">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Map + Detail panel side by side */}
      <div className={`grid gap-4 mb-4 ${selectedNode ? "grid-cols-1 lg:grid-cols-3" : "grid-cols-1"}`}>
        <div className={`${selectedNode ? "lg:col-span-2" : ""} bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden`} style={{ height: 550 }}>
          {nodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-sawlah-dim">
              <Map className="w-16 h-16 mb-4 opacity-10" />
              <p className="text-lg font-semibold">No map data yet</p>
              <p className="text-sm mt-1">Enter a target and click "Run Full Recon" to populate the map</p>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes} edges={edges}
              onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes} fitView
              minZoom={0.15} maxZoom={3}
              defaultEdgeOptions={defaultEdgeOptions}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#1a1a1a" gap={20} />
              <Controls className="!bg-sawlah-surface !border-sawlah-border !rounded-lg [&>button]:!bg-sawlah-surface [&>button]:!border-sawlah-border [&>button]:!text-sawlah-muted [&>button:hover]:!bg-white/5" />
              <MiniMap
                nodeColor={(n) => ({ target:"#dc2626",port:"#4ade80",service:"#22d3ee",subdomain:"#60a5fa",technology:"#06b6d4",exploit:"#f97316",vuln:"#ef4444",directory:"#a855f7",waf:"#4ade80",whois:"#f59e0b",ssl:"#22c55e" }[n.type] || "#71717a")}
                style={{ background: "#0a0a0a", border: "1px solid #2a2a2a", borderRadius: 8 }}
              />
            </ReactFlow>
          )}
        </div>

        {selectedNode && (
          <NodeDetailPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            scanDetails={summary?.scan_details || []}
          />
        )}
      </div>

      {/* Detailed info tables below the map */}
      {summary && <InfoTabs summary={summary} />}
    </div>
  );
}
