# Sawlah-web - Penetration Testing Web Panel

A full-stack web application that provides a GUI for Kali Linux penetration testing tools with real-time terminal output, automated pentesting workflows, and report generation.

## Quick Start

### 1. Start the Backend

```bash
cd backend
python3 main.py
```

The API server runs on `http://127.0.0.1:8000`.

### 2. Start the Frontend

```bash
cd frontend
npm run dev
```

The web UI runs on `http://localhost:3000`.

## Tools Supported

| Category           | Tools                                           |
|--------------------|------------------------------------------------|
| Port Scanning      | Nmap (quick, full TCP, SYN, UDP, service, OS, vuln scripts) |
| SQL Injection      | SQLMap (with tamper, levels, dump)              |
| Subdomain Enum     | Amass, Gobuster DNS, DNSEnum                   |
| Web Scanning       | Nikto, Dirb, Gobuster Dir, FFUF, WhatWeb, Wfuzz |
| Network Enum       | NetExec/NXC (SMB/LDAP/RDP/WinRM/SSH), Enum4linux, SMBClient |
| Exploit Search     | SearchSploit                                    |
| Password Attacks   | Hydra, John the Ripper, Hashcat                |
| Reconnaissance     | Whois, Dig                                     |

## Features

- Real-time terminal output via WebSocket
- Project management with scan history
- Automated pentesting pipelines (scan → enum → exploit)
- HTML report generation
- Swiss-inspired dark UI (red/black/white)
