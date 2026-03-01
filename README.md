# Sawlah-web — Penetration Testing Web Panel

A full-stack web application that provides a GUI for Kali Linux penetration testing tools with real-time terminal output, automated pentesting workflows, and report generation.

## Install & Run

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/vm32/Sawlah-web/main/install.sh)"
```

That's it. One command — clones the repo, installs everything, and launches the panel. Open **http://localhost:3000** when you see the ready message.

> **Works on Kali Linux out of the box.** The installer auto-installs any missing packages (`git`, `python3`, `node`, `npm`) via apt if needed.

### Custom install location

```bash
SAWLAH_DIR=/opt/Sawlah-web sh -c "$(curl -fsSL https://raw.githubusercontent.com/vm32/Sawlah-web/main/install.sh)"
```

### Already installed? Run again

```bash
cd ~/Sawlah-web && bash start.sh
```

Or just re-run the curl command — it will pull the latest changes and start.

Press `Ctrl+C` to stop both servers.

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

