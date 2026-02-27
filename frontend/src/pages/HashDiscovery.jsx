import { useState, useEffect, useCallback } from "react";
import { Fingerprint, Zap, FileKey, Search } from "lucide-react";
import { toolsApi } from "../api/client";
import useWebSocket from "../hooks/useWebSocket";
import { PageHeader, FormField, TextInput, SelectInput, CheckboxInput } from "../components/ToolForm";
import OutputPanel from "../components/OutputPanel";

const HASH_MODES = [
  { value: "", label: "Select mode..." },
  { value: "0", label: "0 - MD5" },
  { value: "100", label: "100 - SHA1" },
  { value: "1400", label: "1400 - SHA256" },
  { value: "1700", label: "1700 - SHA512" },
  { value: "500", label: "500 - md5crypt ($1$)" },
  { value: "1800", label: "1800 - sha512crypt ($6$)" },
  { value: "3200", label: "3200 - bcrypt ($2*$)" },
  { value: "1000", label: "1000 - NTLM" },
  { value: "3000", label: "3000 - LM" },
  { value: "5600", label: "5600 - NetNTLMv2" },
  { value: "5500", label: "5500 - NetNTLMv1" },
  { value: "13100", label: "13100 - Kerberoast TGS-REP" },
  { value: "18200", label: "18200 - AS-REP Roast" },
  { value: "13400", label: "13400 - KeePass" },
  { value: "7500", label: "7500 - Kerberos 5" },
  { value: "11300", label: "11300 - Bitcoin wallet" },
  { value: "16800", label: "16800 - WPA-PMKID" },
  { value: "22000", label: "22000 - WPA-PBKDF2-PMKID+EAPOL" },
  { value: "400", label: "400 - phpass (WordPress)" },
  { value: "7900", label: "7900 - Drupal7" },
  { value: "1500", label: "1500 - descrypt (DES)" },
  { value: "2100", label: "2100 - Domain Cached Creds 2" },
];

const ATTACK_MODES = [
  { value: "0", label: "0 - Dictionary" },
  { value: "1", label: "1 - Combination" },
  { value: "3", label: "3 - Brute-force" },
  { value: "6", label: "6 - Hybrid Wordlist + Mask" },
  { value: "7", label: "7 - Hybrid Mask + Wordlist" },
];

const WORDLISTS = [
  { value: "/usr/share/wordlists/rockyou.txt", label: "rockyou.txt" },
  { value: "/usr/share/wordlists/fasttrack.txt", label: "fasttrack.txt" },
  { value: "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt", label: "10M passwords (top 1M)" },
  { value: "/usr/share/wordlists/seclists/Passwords/darkweb2017-top10000.txt", label: "darkweb top 10k" },
  { value: "/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou-75.txt", label: "rockyou-75" },
  { value: "", label: "Custom..." },
];

const JOHN_FORMATS = [
  { value: "", label: "Auto-detect" },
  { value: "raw-md5", label: "Raw MD5" },
  { value: "raw-sha1", label: "Raw SHA1" },
  { value: "raw-sha256", label: "Raw SHA256" },
  { value: "raw-sha512", label: "Raw SHA512" },
  { value: "NT", label: "NTLM" },
  { value: "LM", label: "LM" },
  { value: "netntlmv2", label: "NetNTLMv2" },
  { value: "bcrypt", label: "bcrypt" },
  { value: "md5crypt", label: "md5crypt" },
  { value: "sha512crypt", label: "sha512crypt" },
  { value: "krb5tgs", label: "Kerberoast" },
  { value: "krb5asrep", label: "AS-REP" },
  { value: "zip", label: "ZIP" },
  { value: "rar", label: "RAR" },
  { value: "keepass", label: "KeePass" },
  { value: "wpapsk", label: "WPA PSK" },
];

const RULE_FILES = [
  { value: "", label: "No rules" },
  { value: "/usr/share/hashcat/rules/best64.rule", label: "best64" },
  { value: "/usr/share/hashcat/rules/rockyou-30000.rule", label: "rockyou-30000" },
  { value: "/usr/share/hashcat/rules/d3ad0ne.rule", label: "d3ad0ne" },
  { value: "/usr/share/hashcat/rules/dive.rule", label: "dive" },
  { value: "/usr/share/hashcat/rules/toggles1.rule", label: "toggles1" },
  { value: "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule", label: "OneRuleToRuleThemAll" },
];

const TABS = [
  { id: "identify", label: "Identify Hash", icon: Search },
  { id: "hashcat", label: "Hashcat", icon: Zap },
  { id: "john", label: "John the Ripper", icon: FileKey },
];

export default function HashDiscovery({ setOutput, setTitle }) {
  const [activeTab, setActiveTab] = useState("identify");
  const [hashInput, setHashInput] = useState("");
  const [hashFile, setHashFile] = useState("");
  const [hashMode, setHashMode] = useState("");
  const [attackMode, setAttackMode] = useState("0");
  const [wordlistPreset, setWordlistPreset] = useState("/usr/share/wordlists/rockyou.txt");
  const [customWordlist, setCustomWordlist] = useState("");
  const [rules, setRules] = useState("");
  const [workload, setWorkload] = useState("2");
  const [force, setForce] = useState(false);
  const [showResult, setShowResult] = useState(false);
  const [increment, setIncrement] = useState(false);
  const [incrementMin, setIncrementMin] = useState("");
  const [incrementMax, setIncrementMax] = useState("");
  const [johnFormat, setJohnFormat] = useState("");
  const [johnRules, setJohnRules] = useState("");
  const [johnSingle, setJohnSingle] = useState(false);
  const [johnShow, setJohnShow] = useState(false);
  const [extraFlags, setExtraFlags] = useState("");
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState([]);

  const ws = useWebSocket();

  useEffect(() => { setTitle("Hash Discovery"); }, [setTitle]);
  useEffect(() => { if (ws.output) setOutput(ws.output); }, [ws.output, setOutput]);

  const loadHistory = useCallback(() => {
    const toolName = activeTab === "identify" ? "hashid" : activeTab === "hashcat" ? "hashcat_crack" : "john_crack";
    toolsApi.history(toolName).then((res) => setHistory(res.data)).catch(() => {});
  }, [activeTab]);
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
    ws.reset(); setOutput(""); setStatus("running");

    let toolName, params;

    if (activeTab === "identify") {
      if (!hashInput.trim()) return;
      toolName = "hashid";
      params = { hash: hashInput.trim(), extended: true, mode: true };
    } else if (activeTab === "hashcat") {
      if (!hashFile.trim() && !hashInput.trim()) return;
      toolName = "hashcat_crack";
      const wl = wordlistPreset || customWordlist;
      params = {
        hashfile: hashFile.trim(),
        hash: hashInput.trim(),
        mode: hashMode,
        attack_mode: attackMode,
        wordlist: wl,
        rules,
        workload,
        force,
        show: showResult,
        increment,
        increment_min: incrementMin,
        increment_max: incrementMax,
        extra_flags: extraFlags,
      };
    } else {
      if (!hashFile.trim()) return;
      toolName = "john_crack";
      const wl = wordlistPreset || customWordlist;
      params = {
        hashfile: hashFile.trim(),
        wordlist: wl,
        format: johnFormat,
        rules: johnRules,
        single: johnSingle,
        show: johnShow,
        extra_flags: extraFlags,
      };
    }

    try {
      const res = await toolsApi.run(toolName, params);
      if (res.data.error) {
        setOutput(`Error: ${res.data.error}\n`);
        setStatus("error");
        return;
      }
      setTaskId(res.data.task_id); setCommand(res.data.command);
      ws.connect(res.data.task_id);
    } catch (err) { setOutput(`Error: ${err.message}\n`); setStatus("error"); }
  };

  const handleStop = async () => {
    if (taskId) { await toolsApi.kill(taskId); setStatus("killed"); }
  };

  return (
    <div>
      <PageHeader title="Hash Discovery" description="Identify, analyze, and crack hashes" icon={Fingerprint} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-5 space-y-4 max-h-[720px] overflow-y-auto">
          {/* Mode tabs */}
          <div className="flex gap-1 p-1 bg-sawlah-surface rounded-lg">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-1.5 flex-1 px-3 py-2 rounded-md text-xs font-semibold transition-all ${
                  activeTab === t.id
                    ? "bg-sawlah-red text-white shadow-lg shadow-sawlah-red-glow"
                    : "text-sawlah-dim hover:text-sawlah-muted hover:bg-white/5"
                }`}
              >
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            ))}
          </div>

          {/* Hash input (shared) */}
          <FormField label="Hash Value" hint="Paste hash directly or provide file path below">
            <textarea
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99"
              className="w-full h-20 resize-none font-mono text-sm"
            />
          </FormField>

          {activeTab !== "identify" && (
            <FormField label="Hash File Path" hint="Path to file containing hashes">
              <TextInput value={hashFile} onChange={setHashFile} placeholder="/tmp/hashes.txt" />
            </FormField>
          )}

          {/* Hashcat options */}
          {activeTab === "hashcat" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Hash Mode (-m)">
                  <SelectInput value={hashMode} onChange={setHashMode} options={HASH_MODES} />
                </FormField>
                <FormField label="Attack Mode (-a)">
                  <SelectInput value={attackMode} onChange={setAttackMode} options={ATTACK_MODES} />
                </FormField>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Wordlist">
                  <SelectInput value={wordlistPreset} onChange={setWordlistPreset} options={WORDLISTS} />
                </FormField>
                {wordlistPreset === "" && (
                  <FormField label="Custom Wordlist">
                    <TextInput value={customWordlist} onChange={setCustomWordlist} placeholder="/path/to/wordlist" />
                  </FormField>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Rules File">
                  <SelectInput value={rules} onChange={setRules} options={RULE_FILES} />
                </FormField>
                <FormField label="Workload (-w)">
                  <SelectInput value={workload} onChange={setWorkload} options={[
                    { value: "1", label: "1 - Low" },
                    { value: "2", label: "2 - Default" },
                    { value: "3", label: "3 - High" },
                    { value: "4", label: "4 - Nightmare" },
                  ]} />
                </FormField>
              </div>
              <div className="grid grid-cols-3 gap-2">
                <CheckboxInput checked={force} onChange={setForce} label="--force" />
                <CheckboxInput checked={showResult} onChange={setShowResult} label="--show" />
                <CheckboxInput checked={increment} onChange={setIncrement} label="--increment" />
              </div>
              {increment && (
                <div className="grid grid-cols-2 gap-4">
                  <FormField label="Increment Min"><TextInput value={incrementMin} onChange={setIncrementMin} placeholder="1" /></FormField>
                  <FormField label="Increment Max"><TextInput value={incrementMax} onChange={setIncrementMax} placeholder="8" /></FormField>
                </div>
              )}
            </>
          )}

          {/* John options */}
          {activeTab === "john" && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <FormField label="Format">
                  <SelectInput value={johnFormat} onChange={setJohnFormat} options={JOHN_FORMATS} />
                </FormField>
                <FormField label="Wordlist">
                  <SelectInput value={wordlistPreset} onChange={setWordlistPreset} options={WORDLISTS} />
                </FormField>
              </div>
              {wordlistPreset === "" && (
                <FormField label="Custom Wordlist">
                  <TextInput value={customWordlist} onChange={setCustomWordlist} placeholder="/path/to/wordlist" />
                </FormField>
              )}
              <FormField label="Rules" hint="e.g. best64, wordlist, single">
                <TextInput value={johnRules} onChange={setJohnRules} placeholder="best64" />
              </FormField>
              <div className="grid grid-cols-2 gap-2">
                <CheckboxInput checked={johnSingle} onChange={setJohnSingle} label="--single mode" />
                <CheckboxInput checked={johnShow} onChange={setJohnShow} label="--show cracked" />
              </div>
            </>
          )}

          <FormField label="Extra Flags"><TextInput value={extraFlags} onChange={setExtraFlags} placeholder="Additional flags" /></FormField>
        </div>

        <OutputPanel
          onRun={handleRun} onStop={handleStop} status={status}
          command={command} output={ws.output} history={history}
          toolName={activeTab === "identify" ? "hashid" : activeTab === "hashcat" ? "hashcat_crack" : "john_crack"}
        />
      </div>
    </div>
  );
}
