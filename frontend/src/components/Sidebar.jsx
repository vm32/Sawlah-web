import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, Radar, Globe, SearchCode, Database, Network,
  Shield, ShieldAlert, Key, Workflow, FileText, Server, Bug, Fingerprint,
  Crosshair, Map, LogOut, User, ScanEye
} from "lucide-react";

const NAV_SECTIONS = [
  {
    label: "Main",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard },
      { to: "/recon-map", label: "Recon Map", icon: Map },
    ],
  },
  {
    label: "Reconnaissance",
    items: [
      { to: "/nmap", label: "Nmap Scanner", icon: Radar },
      { to: "/nikto", label: "Nikto Scanner", icon: ScanEye },
      { to: "/subenum", label: "Sub Enumeration", icon: Globe },
      { to: "/webscan", label: "Web Scanning", icon: SearchCode },
      { to: "/waf", label: "WAF Detection", icon: ShieldAlert },
      { to: "/advanced", label: "Advanced Scan", icon: Crosshair },
    ],
  },
  {
    label: "Exploitation",
    items: [
      { to: "/sqlmap", label: "SQL Injection", icon: Database },
      { to: "/exploit", label: "Exploit Search", icon: Bug },
    ],
  },
  {
    label: "Enumeration",
    items: [
      { to: "/nxc", label: "NetExec (NXC)", icon: Network },
      { to: "/enum", label: "Enumeration", icon: Server },
    ],
  },
  {
    label: "Credentials",
    items: [
      { to: "/password", label: "Password Attacks", icon: Key },
      { to: "/hash", label: "Hash Discovery", icon: Fingerprint },
    ],
  },
  {
    label: "Workflow",
    items: [
      { to: "/automation", label: "Automation", icon: Workflow },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
];

export default function Sidebar({ user, onLogout }) {
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
      <nav className="flex-1 overflow-y-auto py-2 px-3">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="mb-1">
            <p className="text-[9px] uppercase tracking-widest text-sawlah-dim/60 font-bold px-3 pt-3 pb-1.5">
              {section.label}
            </p>
            <div className="space-y-0.5">
              {section.items.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
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
            </div>
          </div>
        ))}
      </nav>
      <div className="px-3 py-3 border-t border-sawlah-border space-y-2">
        {user && (
          <div className="flex items-center justify-between px-3 py-1.5">
            <div className="flex items-center gap-2">
              <User className="w-3.5 h-3.5 text-sawlah-red" />
              <span className="text-xs font-medium text-sawlah-muted">{user.username}</span>
            </div>
            <button onClick={onLogout} className="p-1 text-sawlah-dim hover:text-sawlah-red transition-colors" title="Logout">
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
        <p className="text-[10px] text-sawlah-dim/60 text-center">Sawlah-web v2.0 &middot; Kali Linux</p>
      </div>
    </aside>
  );
}
