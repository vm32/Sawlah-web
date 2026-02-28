import { Routes, Route } from "react-router-dom";
import { useState, useEffect, useCallback } from "react";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Nmap from "./pages/Nmap";
import SqlMap from "./pages/SqlMap";
import SubEnum from "./pages/SubEnum";
import WebScan from "./pages/WebScan";
import Nikto from "./pages/Nikto";
import NXC from "./pages/NXC";
import Enum from "./pages/Enum";
import Exploit from "./pages/Exploit";
import PasswordAttack from "./pages/PasswordAttack";
import HashDiscovery from "./pages/HashDiscovery";
import AdvancedScan from "./pages/AdvancedScan";
import ReconMap from "./pages/ReconMap";
import Automation from "./pages/Automation";
import Reports from "./pages/Reports";

export default function App() {
  const [termOutput, setTermOutput] = useState("");
  const [termTitle, setTermTitle] = useState("Terminal Output");
  const [authed, setAuthed] = useState(() => !!localStorage.getItem("sawlah_token"));
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("sawlah_user") || "null"); } catch { return null; }
  });

  const handleLogin = (data) => {
    setAuthed(true);
    setUser({ username: data.username, role: data.role });
  };

  const handleLogout = () => {
    localStorage.removeItem("sawlah_token");
    localStorage.removeItem("sawlah_user");
    setAuthed(false);
    setUser(null);
  };

  const terminalProps = {
    appendOutput: (text) => setTermOutput((prev) => prev + text),
    setOutput: setTermOutput,
    setTitle: setTermTitle,
  };

  if (!authed) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Layout user={user} onLogout={handleLogout}>
      <Routes>
        <Route path="/" element={<Dashboard {...terminalProps} />} />
        <Route path="/nmap" element={<Nmap {...terminalProps} />} />
        <Route path="/sqlmap" element={<SqlMap {...terminalProps} />} />
        <Route path="/subenum" element={<SubEnum {...terminalProps} />} />
        <Route path="/nikto" element={<Nikto {...terminalProps} />} />
        <Route path="/webscan" element={<WebScan {...terminalProps} />} />
        <Route path="/nxc" element={<NXC {...terminalProps} />} />
        <Route path="/enum" element={<Enum {...terminalProps} />} />
        <Route path="/exploit" element={<Exploit {...terminalProps} />} />
        <Route path="/password" element={<PasswordAttack {...terminalProps} />} />
        <Route path="/hash" element={<HashDiscovery {...terminalProps} />} />
        <Route path="/advanced" element={<AdvancedScan {...terminalProps} />} />
        <Route path="/recon-map" element={<ReconMap {...terminalProps} />} />
        <Route path="/automation" element={<Automation {...terminalProps} />} />
        <Route path="/reports" element={<Reports {...terminalProps} />} />
      </Routes>
    </Layout>
  );
}
