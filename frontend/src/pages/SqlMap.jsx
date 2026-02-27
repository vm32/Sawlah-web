import { useState, useEffect, useCallback } from "react";
import { Database } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const LEVELS = [1, 2, 3, 4, 5].map((v) => ({ value: String(v), label: `Level ${v}` }));
const RISKS = [1, 2, 3].map((v) => ({ value: String(v), label: `Risk ${v}` }));
const TAMPER_SCRIPTS = [
  "space2comment", "between", "randomcase", "charencode", "equaltolike",
  "base64encode", "apostrophemask", "percentage", "halfversionedmorekeywords",
];

export default function SqlMap({ setOutput, setTitle }) {
  const [target, setTarget] = useState("");
  const [method, setMethod] = useState("GET");
  const [data, setData] = useState("");
  const [level, setLevel] = useState("1");
  const [risk, setRisk] = useState("1");
  const [tamper, setTamper] = useState("");
  const [dbs, setDbs] = useState(false);
  const [tables, setTables] = useState(false);
  const [columns, setColumns] = useState(false);
  const [dump, setDump] = useState(false);
  const [currentDb, setCurrentDb] = useState(false);
  const [currentUser, setCurrentUser] = useState(false);
  const [isDba, setIsDba] = useState(false);
  const [database, setDatabase] = useState("");
  const [table, setTable] = useState("");
  const [randomAgent, setRandomAgent] = useState(true);
  const [threads, setThreads] = useState("5");
  const [extraFlags, setExtraFlags] = useState("");
  const [cookie, setCookie] = useState("");
  const [userAgent, setUserAgent] = useState("");
  const [proxy, setProxy] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("SQLMap"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    toolsApi.history("sqlmap").then((res) => setHistory(res.data)).catch(() => {});
  }, []);
  useEffect(() => { loadHistory(); }, [loadHistory]);

  useEffect(() => {
    if (!taskId) return;
    const interval = setInterval(async () => {
      try {
        const res = await toolsApi.status(taskId);
        setStatus(res.data.status);
        if (["completed", "error", "killed"].includes(res.data.status)) { clearInterval(interval); loadHistory(); }
      } catch {}
    }, 2000);
    return () => clearInterval(interval);
  }, [taskId, loadHistory]);

  const handleRun = async () => {
    if (!target.trim()) return;
    ws.reset(); setOutput("");
    const params = {
      target: target.trim(), method, data, level, risk, tamper,
      dbs, tables, columns, dump, current_db: currentDb,
      current_user: currentUser, is_dba: isDba,
      database, table, random_agent: randomAgent,
      threads: parseInt(threads) || 5, extra_flags: extraFlags,
      cookie, user_agent: userAgent, proxy,
    };
    try {
      const res = await toolsApi.run("sqlmap", params);
      setTaskId(res.data.task_id); setCommand(res.data.command);
      setStatus("running"); ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="SQLMap" description="Automatic SQL injection and database takeover tool" icon={Database} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4">
          <FormField label="Target URL" hint="URL with injectable parameter (e.g. http://target.com/page?id=1)">
            <TextInput value={target} onChange={setTarget} placeholder="http://target.com/page.php?id=1" />
          </FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Method">
              <SelectInput value={method} onChange={setMethod} options={[{value:"GET",label:"GET"},{value:"POST",label:"POST"}]} />
            </FormField>
            <FormField label="POST Data" hint="For POST requests">
              <TextInput value={data} onChange={setData} placeholder="user=test&pass=test" />
            </FormField>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <FormField label="Level (1-5)"><SelectInput value={level} onChange={setLevel} options={LEVELS} /></FormField>
            <FormField label="Risk (1-3)"><SelectInput value={risk} onChange={setRisk} options={RISKS} /></FormField>
            <FormField label="Threads"><TextInput value={threads} onChange={setThreads} placeholder="5" /></FormField>
          </div>
          <FormField label="Tamper Scripts" hint="Comma-separated tamper scripts">
            <TextInput value={tamper} onChange={setTamper} placeholder="space2comment,between" />
            <div className="flex flex-wrap gap-1.5 mt-2">
              {TAMPER_SCRIPTS.map((t) => (
                <button key={t} onClick={() => setTamper((prev) => prev ? `${prev},${t}` : t)}
                  className="px-2 py-0.5 text-[11px] bg-sawlah-surface border border-sawlah-border rounded hover:border-sawlah-red hover:text-sawlah-red transition-colors text-sawlah-muted"
                >{t}</button>
              ))}
            </div>
          </FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Database (-D)"><TextInput value={database} onChange={setDatabase} placeholder="database_name" /></FormField>
            <FormField label="Table (-T)"><TextInput value={table} onChange={setTable} placeholder="table_name" /></FormField>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Cookie"><TextInput value={cookie} onChange={setCookie} placeholder="PHPSESSID=abc123" /></FormField>
            <FormField label="User-Agent"><TextInput value={userAgent} onChange={setUserAgent} placeholder="Custom UA string" /></FormField>
          </div>
          <FormField label="Proxy" hint="e.g. http://127.0.0.1:8080"><TextInput value={proxy} onChange={setProxy} placeholder="http://127.0.0.1:8080" /></FormField>
          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="--os-shell" /></FormField>
          <div className="grid grid-cols-2 gap-3">
            <CheckboxInput checked={dbs} onChange={setDbs} label="List databases (--dbs)" />
            <CheckboxInput checked={tables} onChange={setTables} label="List tables (--tables)" />
            <CheckboxInput checked={columns} onChange={setColumns} label="List columns (--columns)" />
            <CheckboxInput checked={dump} onChange={setDump} label="Dump data (--dump)" />
            <CheckboxInput checked={currentDb} onChange={setCurrentDb} label="Current database" />
            <CheckboxInput checked={currentUser} onChange={setCurrentUser} label="Current user" />
            <CheckboxInput checked={isDba} onChange={setIsDba} label="Check DBA" />
            <CheckboxInput checked={randomAgent} onChange={setRandomAgent} label="Random User-Agent" />
          </div>
        </div>

        <OutputPanel onRun={handleRun} onStop={handleStop} status={status} command={command} output={ws.output} history={history} toolName="sqlmap" />
      </div>
    </div>
  );
}
