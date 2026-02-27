import { useState } from "react";
import Sidebar from "./Sidebar";
import Terminal from "./Terminal";

export default function Layout({ children, terminalOutput, terminalTitle }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex min-h-screen bg-sawlah-bg">
      <Sidebar />
      <div className="flex-1 ml-60 flex flex-col">
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
        <Terminal
          output={terminalOutput || ""}
          title={terminalTitle || "Terminal Output"}
          collapsed={collapsed}
          onToggle={() => setCollapsed(!collapsed)}
        />
      </div>
    </div>
  );
}
