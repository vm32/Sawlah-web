import { Routes, Route } from "react-router-dom";
import { useState } from "react";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Nmap from "./pages/Nmap";
import SqlMap from "./pages/SqlMap";
import SubEnum from "./pages/SubEnum";
import WebScan from "./pages/WebScan";
import NXC from "./pages/NXC";
import Enum from "./pages/Enum";
import Exploit from "./pages/Exploit";
import PasswordAttack from "./pages/PasswordAttack";
import Automation from "./pages/Automation";
import Reports from "./pages/Reports";

export default function App() {
  const [termOutput, setTermOutput] = useState("");
  const [termTitle, setTermTitle] = useState("Terminal Output");

  const terminalProps = {
    appendOutput: (text) => setTermOutput((prev) => prev + text),
    setOutput: setTermOutput,
    setTitle: setTermTitle,
  };

  return (
    <Layout terminalOutput={termOutput} terminalTitle={termTitle}>
      <Routes>
        <Route path="/" element={<Dashboard {...terminalProps} />} />
        <Route path="/nmap" element={<Nmap {...terminalProps} />} />
        <Route path="/sqlmap" element={<SqlMap {...terminalProps} />} />
        <Route path="/subenum" element={<SubEnum {...terminalProps} />} />
        <Route path="/webscan" element={<WebScan {...terminalProps} />} />
        <Route path="/nxc" element={<NXC {...terminalProps} />} />
        <Route path="/enum" element={<Enum {...terminalProps} />} />
        <Route path="/exploit" element={<Exploit {...terminalProps} />} />
        <Route path="/password" element={<PasswordAttack {...terminalProps} />} />
        <Route path="/automation" element={<Automation {...terminalProps} />} />
        <Route path="/reports" element={<Reports {...terminalProps} />} />
      </Routes>
    </Layout>
  );
}
