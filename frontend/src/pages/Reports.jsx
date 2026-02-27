import { useState, useEffect } from "react";
import { FileText, Download, Eye, RefreshCw } from "lucide-react";
import { projectsApi, reportsApi, toolsApi } from "../api/client";
import { PageHeader, FormField, SelectInput } from "../components/ToolForm";
import StatusBadge from "../components/StatusBadge";

export default function Reports({ setOutput, setTitle }) {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [scans, setScans] = useState([]);
  const [reportHtml, setReportHtml] = useState("");
  const [loading, setLoading] = useState(false);

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
      const res = await reportsApi.generate(selectedProject);
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

  return (
    <div>
      <PageHeader title="Reports" description="Generate and download penetration test reports" icon={FileText} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Select Project">
            <SelectInput value={selectedProject} onChange={setSelectedProject}
              options={[{ value: "", label: "Choose a project..." }, ...projects.map((p) => ({ value: String(p.id), label: `${p.name} (${p.target})` }))]} />
          </FormField>

          {selectedProject && (
            <>
              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wider text-sawlah-muted">
                  Scans ({scans.length})
                </p>
                {scans.length === 0 && <p className="text-sm text-sawlah-dim">No scans found for this project</p>}
                <div className="max-h-60 overflow-y-auto space-y-2">
                  {scans.map((s) => (
                    <div key={s.id} className="bg-sawlah-surface border border-sawlah-border rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium text-sawlah-text">{s.tool_name}</span>
                        <StatusBadge status={s.status} />
                      </div>
                      <p className="text-[11px] font-mono text-sawlah-dim truncate">{s.command}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={handleGenerate}
                  disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 bg-sawlah-red text-white rounded-lg text-sm font-medium hover:bg-sawlah-red-hover transition-colors disabled:opacity-50"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
                  Generate Report
                </button>
                <button
                  onClick={handleDownload}
                  className="flex items-center gap-2 px-4 py-2 bg-sawlah-surface border border-sawlah-border text-white rounded-lg text-sm font-medium hover:bg-white/5 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Download
                </button>
              </div>
            </>
          )}
        </div>

        <div className="lg:col-span-2 bg-sawlah-card border border-sawlah-border rounded-xl overflow-hidden">
          {reportHtml ? (
            <iframe
              srcDoc={reportHtml}
              className="w-full h-[600px] border-0"
              title="Report Preview"
            />
          ) : (
            <div className="flex items-center justify-center h-[400px] text-sawlah-dim">
              <div className="text-center">
                <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p className="text-sm">Select a project and generate a report</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
