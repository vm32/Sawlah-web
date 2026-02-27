import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, Radar, Globe, SearchCode, Database, Network,
  Shield, Key, Workflow, FileText, Server, Bug
} from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/nmap", label: "Nmap Scanner", icon: Radar },
  { to: "/subenum", label: "Sub Enumeration", icon: Globe },
  { to: "/webscan", label: "Web Scanning", icon: SearchCode },
  { to: "/sqlmap", label: "SQL Injection", icon: Database },
  { to: "/nxc", label: "NetExec (NXC)", icon: Network },
  { to: "/enum", label: "Enumeration", icon: Server },
  { to: "/exploit", label: "Exploit Search", icon: Bug },
  { to: "/password", label: "Password Attacks", icon: Key },
  { to: "/automation", label: "Automation", icon: Workflow },
  { to: "/reports", label: "Reports", icon: FileText },
];

export default function Sidebar() {
  return (
    <aside className="w-60 h-screen bg-sawlah-surface border-r border-sawlah-border flex flex-col fixed left-0 top-0 z-40">
      <div className="px-5 py-5 border-b border-sawlah-border">
        <div className="flex items-center gap-2">
          <Shield className="w-7 h-7 text-sawlah-red" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-sawlah-text">Sawlah</h1>
            <span className="text-[10px] uppercase tracking-widest text-sawlah-red font-semibold">web panel</span>
          </div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-0.5">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                isActive
                  ? "bg-sawlah-red/10 text-sawlah-red border border-sawlah-red/20"
                  : "text-sawlah-muted hover:text-sawlah-text hover:bg-white/5 border border-transparent"
              }`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-sawlah-border text-[11px] text-sawlah-dim">
        Sawlah-web v1.0 &middot; Kali Linux
      </div>
    </aside>
  );
}
