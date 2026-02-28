import { useState, useEffect, useCallback, memo } from "react";
import { ReactFlow, Background, Controls, MiniMap, Handle, Position, useNodesState, useEdgesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Map, Target, Wifi, Server, AlertTriangle, Globe, FolderOpen, RefreshCw, Cpu, Bug } from "lucide-react";
import { PageHeader, SelectInput } from "../components/ToolForm";

const TargetNode = memo(({ data }) => (
  <div className="relative group">
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
  <div className="group">
    <Handle type="target" position={Position.Left} className="!bg-emerald-500 !w-2 !h-2" />
    <Handle type="source" position={Position.Right} className="!bg-emerald-500 !w-2 !h-2" />
    <div className={`px-3 py-2 rounded-xl border text-center min-w-[100px] ${
      data.state === "open" ? "bg-emerald-500/10 border-emerald-500/40" :
      data.state === "filtered" ? "bg-yellow-500/10 border-yellow-500/40" :
      "bg-zinc-800/50 border-zinc-600/40"
    }`}>
      <Wifi className={`w-4 h-4 mx-auto mb-0.5 ${
        data.state === "open" ? "text-emerald-400" : data.state === "filtered" ? "text-yellow-400" : "text-zinc-500"
      }`} />
      <p className="text-xs font-bold text-white">{data.port}/{data.proto}</p>
      <p className="text-[9px] text-sawlah-muted">{data.service}</p>
    </div>
  </div>
));

const ServiceNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Left} className="!bg-cyan-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 min-w-[120px] max-w-[200px]">
      <Server className="w-3.5 h-3.5 text-cyan-400 mb-0.5" />
      <p className="text-[10px] font-mono text-cyan-300 break-all">{data.label}</p>
    </div>
  </div>
));

const SubdomainNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Left} className="!bg-blue-500 !w-2 !h-2" />
    <div className="px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/30">
      <Globe className="w-3 h-3 text-blue-400 inline mr-1" />
      <span className="text-[10px] font-mono text-blue-300">{data.label}</span>
    </div>
  </div>
));

const VulnNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Top} className="!bg-red-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/40 max-w-[220px]">
      <AlertTriangle className="w-3.5 h-3.5 text-red-400 mb-0.5" />
      <p className="text-[9px] font-mono text-red-300 break-all">{data.label}</p>
    </div>
  </div>
));

const DirectoryNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Top} className="!bg-purple-500 !w-2 !h-2" />
    <div className="px-3 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30">
      <FolderOpen className="w-3 h-3 text-purple-400 inline mr-1" />
      <span className="text-[10px] font-mono text-purple-300">{data.url}</span>
      {data.status > 0 && <span className={`text-[9px] ml-1 ${data.status < 400 ? "text-emerald-400" : "text-yellow-400"}`}>({data.status})</span>}
    </div>
  </div>
));

const TechnologyNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Bottom} className="!bg-cyan-500 !w-2 !h-2" />
    <Handle type="source" position={Position.Left} className="!bg-cyan-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-xl bg-gradient-to-br from-cyan-500/15 to-cyan-900/15 border border-cyan-500/30 min-w-[100px] text-center">
      <Cpu className="w-4 h-4 text-cyan-400 mx-auto mb-0.5" />
      <p className="text-[11px] font-bold text-cyan-300">{data.name}</p>
      {data.version && <p className="text-[9px] text-cyan-500">v{data.version}</p>}
      <p className="text-[8px] text-cyan-700 uppercase tracking-wider mt-0.5">{data.category}</p>
    </div>
  </div>
));

const ExploitNode = memo(({ data }) => (
  <div>
    <Handle type="target" position={Position.Top} className="!bg-orange-500 !w-2 !h-2" />
    <div className="px-3 py-2 rounded-xl bg-gradient-to-br from-orange-500/15 to-red-900/15 border border-orange-500/40 max-w-[240px]">
      <Bug className="w-3.5 h-3.5 text-orange-400 mb-0.5" />
      <p className="text-[10px] font-bold text-orange-300 break-all leading-snug">{data.title}</p>
      <p className="text-[8px] font-mono text-orange-600 mt-0.5">{data.path}</p>
    </div>
  </div>
));

const nodeTypes = {
  target: TargetNode,
  port: PortNode,
  service: ServiceNode,
  subdomain: SubdomainNode,
  vuln: VulnNode,
  directory: DirectoryNode,
  technology: TechnologyNode,
  exploit: ExploitNode,
};

const defaultEdgeOptions = {
  animated: true,
  style: { stroke: "#dc2626", strokeWidth: 1.5 },
};

export default function ReconMap({ setOutput, setTitle }) {
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);

  useEffect(() => { setTitle("Recon Map"); }, [setTitle]);

  const loadTargets = useCallback(async () => {
    try {
      const res = await fetch("/api/map/targets");
      const data = await res.json();
      setTargets(data);
      if (data.length > 0 && !selectedTarget) {
        setSelectedTarget(data[0].target);
      }
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

  const targetOptions = targets.map((t) => ({
    value: t.target,
    label: `${t.target} (${t.ports?.length || 0} ports, ${t.scans?.length || 0} scans)`,
  }));

  return (
    <div>
      <PageHeader title="Recon Map" description="Visual target topology and attack surface" icon={Map} />

      <div className="flex items-center gap-4 mb-4">
        <div className="flex-1 max-w-md">
          <SelectInput
            value={selectedTarget}
            onChange={setSelectedTarget}
            options={targetOptions.length > 0 ? targetOptions : [{ value: "", label: "No targets scanned yet" }]}
          />
        </div>
        <button onClick={() => { loadTargets(); loadMap(); }}
          className="flex items-center gap-2 px-3 py-2 text-sawlah-dim hover:text-sawlah-text hover:bg-white/5 rounded-lg transition-colors text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {summary && (
        <div className="grid grid-cols-4 md:grid-cols-7 gap-3 mb-4">
          {[
            { label: "Ports", value: summary.ports?.length || 0, color: "text-emerald-400" },
            { label: "Services", value: summary.services?.length || 0, color: "text-cyan-400" },
            { label: "Subdomains", value: summary.subdomains?.length || 0, color: "text-blue-400" },
            { label: "Directories", value: summary.directories?.length || 0, color: "text-purple-400" },
            { label: "Technologies", value: summary.technologies?.length || 0, color: "text-cyan-400" },
            { label: "Exploits", value: summary.exploits?.length || 0, color: "text-orange-400" },
            { label: "Vulns", value: summary.vulns?.length || 0, color: "text-red-400" },
          ].map((s) => (
            <div key={s.label} className="bg-sawlah-card border border-sawlah-border rounded-xl px-3 py-2 text-center">
              <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
              <p className="text-[9px] text-sawlah-dim uppercase tracking-wider">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      <div className="bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden" style={{ height: 600 }}>
        {nodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-sawlah-dim">
            <Map className="w-16 h-16 mb-4 opacity-10" />
            <p className="text-lg font-semibold">No map data yet</p>
            <p className="text-sm mt-1">Run Nmap, web scans, or subdomain enumeration to populate the map</p>
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={3}
            defaultEdgeOptions={defaultEdgeOptions}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1a1a1a" gap={20} />
            <Controls className="!bg-sawlah-surface !border-sawlah-border !rounded-lg [&>button]:!bg-sawlah-surface [&>button]:!border-sawlah-border [&>button]:!text-sawlah-muted [&>button:hover]:!bg-white/5" />
            <MiniMap
              nodeColor={(n) => {
                if (n.type === "target") return "#dc2626";
                if (n.type === "port") return "#4ade80";
                if (n.type === "service") return "#22d3ee";
                if (n.type === "subdomain") return "#60a5fa";
                if (n.type === "technology") return "#06b6d4";
                if (n.type === "exploit") return "#f97316";
                if (n.type === "vuln") return "#ef4444";
                if (n.type === "directory") return "#a855f7";
                return "#71717a";
              }}
              style={{ background: "#0a0a0a", border: "1px solid #2a2a2a", borderRadius: 8 }}
            />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}
