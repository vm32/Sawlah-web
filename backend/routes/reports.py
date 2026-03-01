import os
import re
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import select
from jinja2 import Environment, FileSystemLoader
from datetime import datetime, timezone
from pydantic import BaseModel
from typing import Optional

from database import async_session, Project, Scan, Finding
from config import TEMPLATE_DIR, REPORTS_DIR

router = APIRouter()
jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

TOOL_PURPOSES = {
    "nmap": "Port scanning & service detection",
    "sqlmap": "SQL injection testing",
    "nikto": "Web server vulnerability scanning",
    "dirb": "Directory brute-forcing",
    "gobuster_dir": "Directory & file discovery",
    "ffuf": "Web fuzzing",
    "whatweb": "Web technology fingerprinting",
    "wfuzz": "Web application fuzzing",
    "nxc": "Network service enumeration & exploitation",
    "enum4linux": "SMB/Samba enumeration",
    "smbclient": "SMB share access",
    "searchsploit": "Exploit database search",
    "hydra": "Online brute-force attacks",
    "john": "Offline password cracking",
    "hashcat": "GPU-accelerated password cracking",
    "hashid": "Hash type identification",
    "amass": "Subdomain enumeration",
    "gobuster_dns": "DNS subdomain brute-force",
    "dnsenum": "DNS enumeration",
    "nuclei": "Template-based vulnerability scanning",
    "wafw00f": "WAF detection",
    "feroxbuster": "Content discovery",
    "wpscan": "WordPress security scanning",
    "whois": "Domain registration lookup",
    "dig": "DNS query tool",
}

REMEDIATION_MAP = {
    "open_port": "Review if this port/service is required. Disable unnecessary services and apply firewall rules.",
    "vuln_detected": "Apply vendor patches or upgrade to the latest version. Implement compensating controls if patching is not immediately possible.",
    "sql_injection": "Use parameterized queries/prepared statements. Implement input validation and WAF rules.",
    "credential_found": "Enforce strong password policies. Implement account lockout and MFA. Rotate compromised credentials immediately.",
    "exploit_available": "Patch or upgrade the affected software immediately. Monitor for exploitation attempts.",
    "default": "Investigate and remediate according to organizational security policy.",
}


def extract_findings_from_output(tool_name: str, command: str, output: str) -> list[dict]:
    findings = []
    if not output:
        return findings

    if tool_name == "nmap":
        for m in re.finditer(r"(\d+)/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)", output):
            port, proto, state, service, version = m.groups()
            version = version.strip()
            sev = "info"
            title = f"Open Port {port}/{proto} - {service}"
            desc = f"Port {port}/{proto} is open running {service}"
            if version:
                desc += f" ({version})"
                title += f" ({version})"
            findings.append({
                "severity": sev, "title": title, "description": desc,
                "evidence": m.group(0).strip(), "component": f"{port}/{proto}",
                "tool": tool_name, "command": command, "remediation": REMEDIATION_MAP["open_port"],
            })
        for m in re.finditer(r"(.*VULNERABLE.*)", output, re.I):
            findings.append({
                "severity": "high", "title": "Vulnerability Detected (Nmap NSE)",
                "description": m.group(1).strip(),
                "evidence": _extract_context(output, m.start(), 300),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["vuln_detected"],
            })
        for m in re.finditer(r"(CVE-\d{4}-\d+)", output):
            findings.append({
                "severity": "high", "title": f"CVE Reference: {m.group(1)}",
                "description": f"Nmap scripts identified {m.group(1)}",
                "evidence": _extract_context(output, m.start(), 200),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["vuln_detected"],
            })

    elif tool_name == "sqlmap":
        if re.search(r"(is vulnerable|injectable)", output, re.I):
            param_match = re.search(r"Parameter:\s*(\S+)", output)
            param = param_match.group(1) if param_match else "unknown"
            findings.append({
                "severity": "critical",
                "title": f"SQL Injection - Parameter '{param}'",
                "description": f"SQLMap confirmed SQL injection vulnerability in parameter '{param}'",
                "evidence": output[:2000], "component": param,
                "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["sql_injection"],
            })
        for m in re.finditer(r"Type:\s*(.+?)(?:\n|$)", output):
            technique = m.group(1).strip()
            findings.append({
                "severity": "critical",
                "title": f"SQL Injection Technique: {technique}",
                "description": f"SQLMap identified injection using: {technique}",
                "evidence": _extract_context(output, m.start(), 300),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["sql_injection"],
            })

    elif tool_name == "nikto":
        for m in re.finditer(r"\+\s+(OSVDB-\d+):\s*(.*?)(?:\n|$)", output):
            ref = m.group(1)
            detail = m.group(2).strip()
            sev = "medium"
            if re.search(r"VULNERABLE|injection|XSS|remote\s+code|backdoor", detail, re.I):
                sev = "critical"
            elif re.search(r"header|cookie|disclosure|version", detail, re.I):
                sev = "low"
            findings.append({
                "severity": sev,
                "title": f"Nikto [{ref}]: {detail[:70]}",
                "description": detail,
                "evidence": m.group(0).strip(),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["vuln_detected"],
            })
        for m in re.finditer(r"\+\s+(/\S+.*?)(?:\n|$)", output):
            line = m.group(1).strip()
            if len(line) > 10 and "OSVDB" not in line:
                sev = "info"
                if re.search(r"directory listing|index of|default|enabled", line, re.I):
                    sev = "medium"
                elif re.search(r"X-Frame|X-Content|Strict-Transport|Content-Security", line, re.I):
                    sev = "low"
                findings.append({
                    "severity": sev,
                    "title": f"Nikto: {line[:80]}",
                    "description": line, "evidence": line,
                    "component": "", "tool": tool_name, "command": command,
                    "remediation": REMEDIATION_MAP["default"],
                })

    elif tool_name == "whatweb":
        for m in re.finditer(r"\+\s+(/\S+.*?)(?:\n|$)", output):
            line = m.group(1).strip()
            if len(line) > 10:
                findings.append({
                    "severity": "info", "title": f"Web Finding: {line[:80]}",
                    "description": line, "evidence": line,
                    "component": "", "tool": tool_name, "command": command,
                    "remediation": REMEDIATION_MAP["default"],
                })

    elif tool_name == "searchsploit":
        for m in re.finditer(r"(exploits/\S+)", output):
            path = m.group(1)
            title_match = re.search(r"(.+?)\s*\|\s*" + re.escape(path), output)
            title = title_match.group(1).strip() if title_match else path
            findings.append({
                "severity": "high", "title": f"Exploit Available: {title[:80]}",
                "description": f"Public exploit found at {path}",
                "evidence": _extract_context(output, m.start(), 200),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["exploit_available"],
            })

    elif tool_name == "nxc":
        for m in re.finditer(r"(Pwn3d!|STATUS_PASSWORD_EXPIRED|STATUS_LOGON_FAILURE.*admin|SUCCESS)", output, re.I):
            findings.append({
                "severity": "critical" if "Pwn3d" in m.group(0) else "high",
                "title": f"NXC: {m.group(0).strip()[:60]}",
                "description": _extract_context(output, m.start(), 200),
                "evidence": _extract_context(output, m.start(), 300),
                "component": "", "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["credential_found"],
            })
        for m in re.finditer(r"\[\+\]\s*(.*)", output):
            line = m.group(1).strip()
            if line and "Pwn3d" not in line:
                findings.append({
                    "severity": "info", "title": f"NXC Finding: {line[:80]}",
                    "description": line, "evidence": line,
                    "component": "", "tool": tool_name, "command": command,
                    "remediation": REMEDIATION_MAP["default"],
                })

    elif tool_name in ("hydra", "john", "hashcat", "hashcat_crack", "john_crack"):
        for m in re.finditer(r"\[(\d+)\]\[(\w+)\]\s*host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)", output):
            port, svc, host, user, pw = m.groups()
            findings.append({
                "severity": "critical",
                "title": f"Credential Found: {user}@{host}:{port} ({svc})",
                "description": f"Valid credentials discovered: {user}:{pw} on {host}:{port} ({svc})",
                "evidence": m.group(0), "component": f"{host}:{port}",
                "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["credential_found"],
            })
        for m in re.finditer(r"(\S+):(\S+)", output):
            if "password" in output.lower() and "cracked" in output.lower():
                findings.append({
                    "severity": "high",
                    "title": f"Hash Cracked: {m.group(1)[:30]}",
                    "description": f"Cracked hash value found", "evidence": m.group(0),
                    "component": "", "tool": tool_name, "command": command,
                    "remediation": REMEDIATION_MAP["credential_found"],
                })
                break

    elif tool_name == "nuclei":
        for m in re.finditer(r"\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)", output):
            sev_raw = m.group(1).lower()
            template = m.group(2)
            proto = m.group(3)
            rest = m.group(4).strip()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
            sev = sev_map.get(sev_raw, "info")
            findings.append({
                "severity": sev, "title": f"Nuclei: {template}",
                "description": f"[{proto}] {rest}",
                "evidence": m.group(0), "component": rest[:60],
                "tool": tool_name, "command": command,
                "remediation": REMEDIATION_MAP["vuln_detected"],
            })

    elif tool_name == "wafw00f":
        for m in re.finditer(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", output, re.I | re.M):
            waf_name = m.group(1).strip()
            findings.append({
                "severity": "medium",
                "title": f"WAF Detected: {waf_name}",
                "description": f"The target is protected by {waf_name} WAF. Verify WAF rules cover OWASP Top 10.",
                "evidence": _extract_context(output, m.start(), 300),
                "component": "", "tool": tool_name, "command": command,
                "remediation": "Ensure WAF rules are up-to-date. Test for WAF bypass techniques.",
            })
        if re.search(r"No WAF detected|is not behind a WAF", output, re.I):
            findings.append({
                "severity": "critical",
                "title": "No WAF Detected",
                "description": "The target does not appear to be protected by a Web Application Firewall.",
                "evidence": output[:500],
                "component": "", "tool": tool_name, "command": command,
                "remediation": "Deploy a WAF to protect against common web attacks (SQLi, XSS, RFI).",
            })

    return findings


def _extract_context(text: str, pos: int, length: int) -> str:
    start = max(0, pos - 50)
    end = min(len(text), pos + length)
    return text[start:end].strip()


class ReportRequest(BaseModel):
    tester_name: str = ""
    classification: str = "CONFIDENTIAL"
    scope_notes: str = ""
    include_raw: bool = True


@router.post("/{project_id}")
async def generate_report(project_id: int, req: ReportRequest = ReportRequest()):
    async with async_session() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")

        result = await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.started_at)
        )
        scans = result.scalars().all()

        fr = await session.execute(
            select(Finding).join(Scan).where(Scan.project_id == project_id)
        )
        db_findings = fr.scalars().all()

    all_findings = []
    for f in db_findings:
        all_findings.append({
            "severity": f.severity, "title": f.title,
            "description": f.description, "evidence": f.evidence,
            "component": "", "tool": "", "command": "", "remediation": "",
        })

    from tool_runner import tasks as mem_tasks
    for s in scans:
        output = s.output or ""
        for tid, t in mem_tasks.items():
            if t.get("command") == s.command and t.get("tool_name") == s.tool_name:
                if len(t.get("output", "")) > len(output):
                    output = t["output"]
                break
        auto = extract_findings_from_output(s.tool_name, s.command, output)
        all_findings.extend(auto)

    seen = set()
    unique_findings = []
    for f in all_findings:
        key = f"{f['title']}|{f['severity']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    unique_findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5))

    severity_counts = {}
    for f in unique_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    scan_data = []
    for s in scans:
        duration = ""
        if s.started_at and s.finished_at:
            delta = s.finished_at - s.started_at
            duration = f"{int(delta.total_seconds())}s"
        output = s.output or ""
        for tid, t in mem_tasks.items():
            if t.get("command") == s.command and t.get("tool_name") == s.tool_name:
                if len(t.get("output", "")) > len(output):
                    output = t["output"]
                break
        scan_data.append({
            "tool_name": s.tool_name, "command": s.command,
            "status": s.status, "output": output,
            "started_at": s.started_at.isoformat() if s.started_at else "",
            "finished_at": s.finished_at.isoformat() if s.finished_at else "",
            "duration": duration,
        })

    template = jinja_env.get_template("template.html")
    html = template.render(
        project_name=project.name,
        target=project.target,
        scope=req.scope_notes or project.scope,
        tester_name=req.tester_name,
        classification=req.classification,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scans=scan_data,
        findings=unique_findings,
        total_scans=len(scans),
        total_findings=len(unique_findings),
        severity_counts=severity_counts,
        tool_purposes=TOOL_PURPOSES,
        include_raw=req.include_raw,
    )

    filename = f"report_{project.name.replace(' ', '_')}_{project_id}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        f.write(html)

    return HTMLResponse(content=html)


@router.get("/{project_id}")
async def get_report(project_id: int):
    return await generate_report(project_id)


@router.get("/{project_id}/download")
async def download_report(project_id: int):
    async with async_session() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")

    filename = f"report_{project.name.replace(' ', '_')}_{project_id}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        await generate_report(project_id)
    return FileResponse(filepath, filename=filename, media_type="text/html")
