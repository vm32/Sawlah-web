import { useState, useEffect, useRef } from "react";
import { FileText, Download, Eye, RefreshCw, Printer } from "lucide-react";
import { projectsApi, reportsApi, toolsApi } from "../api/client";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import StatusBadge from "../components/StatusBadge";

const CLASSIFICATIONS = [
  { value: "CONFIDENTIAL", label: "Confidential" },
  { value: "INTERNAL", label: "Internal Use Only" },
  { value: "PUBLIC", label: "Public" },
  { value: "TOP SECRET", label: "Top Secret" },
];

export default function Reports({ setOutput, setTitle }) {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [scans, setScans] = useState([]);
  const [reportHtml, setReportHtml] = useState("");
  const [loading, setLoading] = useState(false);
  const [testerName, setTesterName] = useState("");
  const [classification, setClassification] = useState("CONFIDENTIAL");
  const [scopeNotes, setScopeNotes] = useState("");
  const [includeRaw, setIncludeRaw] = useState(true);
  const iframeRef = useRef(null);

  useEffect(() => { setTitle("Reports"); }, [setTitle]);

  useEffect(() => {
    projectsApi.list().then((res) => setProjects(res.data)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedProject) { setScans([]); return; }
    toolsApi.scans(selectedProject).then((res) => setScans(res.data)).catch(() => {});
  }, [selectedProject]);

  const handleGenerate = async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const res = await reportsApi.generate(selectedProject, {
        tester_name: testerName,
        classification,
        scope_notes: scopeNotes,
        include_raw: includeRaw,
      });
      setReportHtml(res.data);
      setOutput("[Report generated successfully]\n");
    } catch (err) {
      setOutput(`Error generating report: ${err.message}\n`);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!selectedProject) return;
    window.open(reportsApi.download(selectedProject), "_blank");
  };

  const handlePrint = () => {
    if (iframeRef.current) {
      iframeRef.current.contentWindow.print();
    }
  };

  return (
    <div>
      <PageHeader title="Reports" description="Generate professional penetration test reports" icon={FileText} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4 max-h-[700px] overflow-y-auto">
          <FormField label="Select Project">
            <SelectInput value={selectedProject} onChange={setSelectedProject}
              options={[{ value: "", label: "Choose a project..." }, ...projects.map((p) => ({ value: String(p.id), label: `${p.name} (${p.target})` }))]} />
          </FormField>

          {selectedProject && (
            <>
              <FormField label="Tester Name" hint="Appears on the cover page">
                <TextInput value={testerName} onChange={setTesterName} placeholder="John Doe / Security Team" />
              </FormField>

              <FormField label="Classification">
                <SelectInput value={classification} onChange={setClassification} options={CLASSIFICATIONS} />
              </FormField>

              <FormField label="Scope Notes" hint="Additional scope details for the report">
                <textarea
                  value={scopeNotes} onChange={(e) => setScopeNotes(e.target.value)}
                  placeholder="Internal network assessment of 10.0.0.0/24. Excludes production servers."
                  className="w-full h-20 resize-none text-sm"
                />
              </FormField>

              <CheckboxInput checked={includeRaw} onChange={setIncludeRaw} label="Include raw output appendix" />

              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted">
                  Scans ({scans.length})
                </p>
                {scans.length === 0 && <p className="text-sm text-sawlah-dim">No scans found for this project</p>}
                <div className="max-h-40 overflow-y-auto space-y-1.5">
                  {scans.map((s) => (
                    <div key={s.id} className="bg-sawlah-surface border border-sawlah-border rounded-lg p-2.5">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-xs font-medium text-sawlah-text">{s.tool_name}</span>
                        <StatusBadge status={s.status} />
                      </div>
                      <p className="text-[10px] font-mono text-sawlah-dim truncate">{s.command}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  onClick={handleGenerate} disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 bg-sawlah-red text-white rounded-lg text-sm font-medium hover:bg-sawlah-red-hover transition-colors disabled:opacity-50 shadow-lg shadow-sawlah-red-glow"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
                  Generate
                </button>
                <button onClick={handleDownload}
                  className="flex items-center gap-2 px-4 py-2 bg-sawlah-surface border border-sawlah-border text-white rounded-lg text-sm font-medium hover:bg-white/5 transition-colors">
                  <Download className="w-4 h-4" /> Download
                </button>
                {reportHtml && (
                  <button onClick={handlePrint}
                    className="flex items-center gap-2 px-4 py-2 bg-sawlah-surface border border-sawlah-border text-white rounded-lg text-sm font-medium hover:bg-white/5 transition-colors">
                    <Printer className="w-4 h-4" /> Print
                  </button>
                )}
              </div>
            </>
          )}
        </div>

        <div className="lg:col-span-2 bg-white border border-sawlah-border rounded-xl overflow-hidden">
          {reportHtml ? (
            <iframe
              ref={iframeRef}
              srcDoc={reportHtml}
              className="w-full border-0"
              style={{ height: 700 }}
              title="Report Preview"
            />
          ) : (
            <div className="flex items-center justify-center h-[500px] bg-sawlah-card">
              <div className="text-center text-sawlah-dim">
                <FileText className="w-12 h-12 mx-auto mb-3 opacity-20" />
                <p className="text-sm">Select a project and generate a report</p>
                <p className="text-[11px] mt-1">Reports include auto-extracted findings, PoC evidence, and are print-ready</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
