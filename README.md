# Sawlah-web — Penetration Testing Web Panel

A full-stack web application that provides a GUI for Kali Linux penetration testing tools with real-time terminal output, automated pentesting workflows, and report generation.

## One-Command Install & Run

```bash
git clone https://github.com/vm32/Sawlah-web.git && cd Sawlah-web && bash start.sh
```

That single command clones the repo, installs all dependencies (Python + Node), and starts both servers. Open **http://localhost:3000** when you see the ready message.

> **Requirements:** Kali Linux with `python3`, `pip3`, `node`, and `npm` (all pre-installed on Kali).

### Already cloned?

```bash
cd Sawlah-web && bash start.sh
```

Press `Ctrl+C` to stop both servers.

### Manual Start (if preferred)

**Terminal 1 — Backend:**
```bash
pip3 install --break-system-packages -r backend/requirements.txt
cd backend && python3 main.py
```

**Terminal 2 — Frontend:**
```bash
cd frontend && npm install && npm run dev
```

- API: `http://127.0.0.1:8000`
- Panel: `http://localhost:3000`

## Tools Supported

| Category           | Tools                                           |
|--------------------|------------------------------------------------|
| Port Scanning      | Nmap (quick, full TCP, SYN, UDP, service, OS, vuln scripts) |
| Web Scanning       | Nikto (dedicated scanner with HTML reports), Dirb, Gobuster Dir, FFUF, WhatWeb, Wfuzz |
| SQL Injection      | SQLMap (with tamper, levels, dump)              |
| Subdomain Enum     | Amass, Gobuster DNS, DNSEnum                   |
| Network Enum       | NetExec/NXC (SMB/LDAP/RDP/WinRM/SSH), Enum4linux, SMBClient |
| Exploit Search     | SearchSploit                                    |
| Password Attacks   | Hydra, John the Ripper, Hashcat                |
| Reconnaissance     | Whois, Dig                                     |
| Advanced           | Nuclei, WPScan, Feroxbuster, Wafw00f           |

## Features

- Real-time terminal output via WebSocket
- Project management with scan history
- Dedicated Nikto web scanner with professional HTML reports
- Automated pentesting pipelines (scan → enum → exploit)
- HTML report generation with severity classification
- Interactive recon map visualization
- Dark UI (red/black/white)
