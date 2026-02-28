import os
import re
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional

from config import REPORTS_DIR
from tool_runner import runner, new_task_id, tasks
from tools.web_scan import build_webscan_command

router = APIRouter()


class NiktoRunRequest(BaseModel):
    target: str
    port: str = ""
    ssl: bool = False
    tuning: str = ""
    mutate: str = ""
    cgidirs: str = ""
    plugins: str = ""
    evasion: str = ""
    timeout: str = ""
    maxtime: str = ""
    useragent: str = ""
    display: str = ""
    followredirects: bool = False
    no404: bool = False
    extra_flags: str = ""
    save_report: bool = True
    project_id: Optional[int] = None


@router.post("/run")
async def run_nikto(req: NiktoRunRequest):
    target = req.target.strip()
    if not target:
        return {"error": "Target URL is required"}

    is_full_uri = "://" in target
    use_ssl = req.ssl or target.startswith("https://")

    report_filename = ""
    output_file = ""
    if req.save_report:
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", target.replace("://", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"nikto_{safe_name}_{ts}.html"
        output_file = os.path.join(REPORTS_DIR, report_filename)

    port = req.port if not is_full_uri else ""

    params = {
        "target": target,
        "port": port,
        "ssl": use_ssl and not target.startswith("https://"),
        "tuning": req.tuning,
        "mutate": req.mutate,
        "cgidirs": req.cgidirs,
        "plugins": req.plugins,
        "evasion": req.evasion,
        "timeout": req.timeout,
        "maxtime": req.maxtime,
        "useragent": req.useragent,
        "display": req.display,
        "followredirects": req.followredirects,
        "no404": req.no404,
        "extra_flags": req.extra_flags,
        "output_file": output_file,
    }

    command = build_webscan_command("nikto", params)
    if not command:
        return {"error": "Failed to build Nikto command"}

    task_id = new_task_id()

    scan_id = None
    if req.project_id:
        from database import async_session, Scan
        async with async_session() as session:
            scan = Scan(
                project_id=req.project_id,
                tool_name="nikto",
                command=" ".join(command),
                status="running",
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            scan_id = scan.id

    async def _run():
        output = await runner.run(task_id, command, tool_name="nikto")

        if report_filename and os.path.exists(output_file):
            enhanced = _build_enhanced_report(output, target, output_file)
            if enhanced:
                with open(output_file, "w") as f:
                    f.write(enhanced)

        if scan_id:
            from database import async_session, Scan
            async with async_session() as session:
                scan = await session.get(Scan, scan_id)
                if scan:
                    scan.output = output
                    scan.status = tasks[task_id]["status"]
                    scan.finished_at = datetime.now(timezone.utc)
                    await session.commit()

    asyncio.create_task(_run())

    return {
        "task_id": task_id,
        "command": " ".join(command),
        "scan_id": scan_id,
        "report_filename": report_filename,
        "status": "running",
    }


@router.get("/reports")
async def list_nikto_reports():
    reports = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.startswith("nikto_") and f.endswith(".html"):
            path = os.path.join(REPORTS_DIR, f)
            stat = os.stat(path)
            reports.append({
                "filename": f,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return reports


@router.get("/reports/{filename}")
async def get_nikto_report(filename: str):
    if not filename.startswith("nikto_") or not filename.endswith(".html"):
        return {"error": "Invalid report filename"}
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": "Report not found"}
    with open(filepath, "r") as f:
        content = f.read()
    return HTMLResponse(content=content)


@router.get("/reports/{filename}/download")
async def download_nikto_report(filename: str):
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": "Report not found"}
    return FileResponse(filepath, filename=filename, media_type="text/html")


def _parse_nikto_output(output: str) -> dict:
    """Parse Nikto raw terminal output into structured data."""
    findings = []
    server_info = {}
    stats = {"items_found": 0, "items_tested": 0, "errors": 0}

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue

        server_match = re.match(r"\+\s*Server:\s*(.+)", line)
        if server_match:
            server_info["server"] = server_match.group(1).strip()
            continue

        target_match = re.match(r"\+\s*Target IP:\s*(.+)", line)
        if target_match:
            server_info["ip"] = target_match.group(1).strip()
            continue

        host_match = re.match(r"\+\s*Target Hostname:\s*(.+)", line)
        if host_match:
            server_info["hostname"] = host_match.group(1).strip()
            continue

        port_match = re.match(r"\+\s*Target Port:\s*(.+)", line)
        if port_match:
            server_info["port"] = port_match.group(1).strip()
            continue

        ssl_match = re.match(r"\+\s*SSL Info:\s*(.+)", line)
        if ssl_match:
            server_info["ssl_info"] = ssl_match.group(1).strip()
            continue

        stat_match = re.search(r"(\d+)\s+requests.*?(\d+)\s+error", line, re.I)
        if stat_match:
            stats["items_tested"] = int(stat_match.group(1))
            stats["errors"] = int(stat_match.group(2))

        items_match = re.search(r"(\d+)\s+item\(s\)\s+reported", line, re.I)
        if items_match:
            stats["items_found"] = int(items_match.group(1))

        finding_match = re.match(r"\+\s+(OSVDB-\d+|/\S+|[A-Z].*?):\s*(.*)", line)
        if finding_match:
            ref = finding_match.group(1).strip()
            detail = finding_match.group(2).strip()
            severity = "info"
            if re.search(r"VULNERABLE|injection|XSS|remote\s+code|command\s+execution|backdoor", detail, re.I):
                severity = "critical"
            elif re.search(r"OSVDB-\d+", ref) or re.search(r"may allow|allows|directory listing|default|enabled", detail, re.I):
                severity = "medium"
            elif re.search(r"header|cookie|disclosure|information|outdated|version", detail, re.I):
                severity = "low"

            category = "General"
            if re.search(r"header|X-Frame|X-Content|Strict-Transport|Content-Security", detail, re.I):
                category = "Headers & Security Policy"
            elif re.search(r"OSVDB", ref):
                category = "Known Vulnerabilities"
            elif re.search(r"directory|index|listing", detail, re.I):
                category = "Directory Exposure"
            elif re.search(r"SSL|TLS|certificate|cipher", detail, re.I):
                category = "SSL/TLS Configuration"
            elif re.search(r"server|version|banner|powered", detail, re.I):
                category = "Server Information"
            elif re.search(r"cookie|session", detail, re.I):
                category = "Cookie & Session"
            elif re.search(r"method|OPTIONS|TRACE|PUT|DELETE", detail, re.I):
                category = "HTTP Methods"
            elif re.search(r"file|backup|config|\.bak|\.old|\.conf", detail, re.I):
                category = "Sensitive Files"

            findings.append({
                "ref": ref,
                "detail": detail,
                "severity": severity,
                "category": category,
                "raw": line,
            })

    return {
        "server_info": server_info,
        "findings": findings,
        "stats": stats,
    }


def _build_enhanced_report(raw_output: str, target: str, existing_report_path: str) -> str:
    """Build a professional HTML report from Nikto output."""
    parsed = _parse_nikto_output(raw_output)
    findings = parsed["findings"]
    server_info = parsed["server_info"]
    stats = parsed["stats"]

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    categories = {}
    for f in findings:
        cat = f["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(f)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda x: sev_order.get(x["severity"], 5))

    findings_rows = ""
    for i, f in enumerate(findings_sorted, 1):
        findings_rows += f"""
        <tr>
            <td class="finding-num">N-{i:03d}</td>
            <td><span class="sev sev-{f['severity']}">{f['severity'].upper()}</span></td>
            <td class="finding-cat">{f['category']}</td>
            <td>{f['ref']}</td>
            <td>{f['detail']}</td>
        </tr>"""

    category_sections = ""
    cat_order = ["Known Vulnerabilities", "Headers & Security Policy", "SSL/TLS Configuration",
                 "HTTP Methods", "Directory Exposure", "Sensitive Files",
                 "Cookie & Session", "Server Information", "General"]
    for cat in cat_order:
        items = categories.get(cat, [])
        if not items:
            continue
        items_html = ""
        for f in items:
            items_html += f"""
            <div class="cat-item cat-{f['severity']}">
                <span class="sev sev-{f['severity']}">{f['severity'].upper()}</span>
                <strong>{f['ref']}</strong> &mdash; {f['detail']}
            </div>"""
        category_sections += f"""
        <div class="cat-group">
            <h3>{cat} <span class="cat-count">({len(items)})</span></h3>
            {items_html}
        </div>"""

    server_rows = ""
    for key, val in server_info.items():
        label = key.replace("_", " ").title()
        server_rows += f"<tr><td class='info-label'>{label}</td><td>{val}</td></tr>"

    total = len(findings) or 1
    risk_segs = ""
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev_name, 0)
        if count > 0:
            pct = round(count / total * 100)
            risk_segs += f'<div class="seg seg-{sev_name}" style="width:{pct}%">{count}</div>'

    raw_lines = ""
    for line in raw_output.splitlines():
        escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        cls = ""
        if re.search(r"OSVDB|VULNERABLE", line, re.I):
            cls = "hl-vuln"
        elif line.strip().startswith("+"):
            cls = "hl-finding"
        elif line.strip().startswith("-"):
            cls = "hl-sep"
        raw_lines += f'<div class="raw-line {cls}">{escaped}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nikto Scan Report - {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#0a0a0a;color:#e5e5e5;line-height:1.6;font-size:13px}}
a{{color:#dc2626;text-decoration:none}}
a:hover{{text-decoration:underline}}

.report-wrap{{max-width:1100px;margin:0 auto;padding:20px}}

.cover{{text-align:center;padding:60px 40px;border-bottom:3px solid #dc2626;margin-bottom:40px}}
.cover .logo{{font-size:42px;font-weight:800;color:#dc2626;letter-spacing:2px}}
.cover .logo-sub{{font-size:11px;text-transform:uppercase;letter-spacing:6px;color:#666;margin:4px 0 30px}}
.cover h1{{font-size:24px;font-weight:700;color:#fff;margin-bottom:4px}}
.cover .target{{font-size:18px;color:#dc2626;font-family:monospace;margin-bottom:30px}}
.cover-meta{{display:grid;grid-template-columns:1fr 1fr;gap:8px;text-align:left;max-width:450px;margin:0 auto}}
.cover-meta dt{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#666;font-weight:600}}
.cover-meta dd{{font-size:13px;color:#ccc;margin-bottom:6px}}

.section-title{{font-size:18px;font-weight:700;color:#fff;border-bottom:2px solid #dc2626;padding-bottom:6px;margin:36px 0 16px}}

.stats-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0}}
.stat-box{{background:#141414;border:1px solid #222;border-radius:8px;padding:16px;text-align:center}}
.stat-box .num{{font-size:28px;font-weight:800}}
.stat-box .lbl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#666;margin-top:2px}}
.num-critical{{color:#dc2626}}.num-high{{color:#e67e22}}.num-medium{{color:#f1c40f}}.num-low{{color:#3498db}}.num-info{{color:#95a5a6}}
.num-total{{color:#fff}}

.risk-bar{{display:flex;height:20px;border-radius:6px;overflow:hidden;margin:12px 0;background:#1a1a1a}}
.risk-bar .seg{{display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff}}
.seg-critical{{background:#dc2626}}.seg-high{{background:#e67e22}}.seg-medium{{background:#f1c40f;color:#333}}.seg-low{{background:#3498db}}.seg-info{{background:#95a5a6}}

.info-table{{width:100%;border-collapse:collapse;margin:12px 0}}
.info-table td{{padding:8px 12px;border-bottom:1px solid #1a1a1a;font-size:13px}}
.info-table .info-label{{color:#888;font-weight:600;width:160px;font-size:11px;text-transform:uppercase;letter-spacing:.5px}}

.findings-table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px}}
.findings-table th{{background:#1a1a1a;color:#888;padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #dc2626}}
.findings-table td{{padding:8px 10px;border-bottom:1px solid #1a1a1a;vertical-align:top}}
.findings-table tr:hover{{background:#111}}
.finding-num{{font-weight:700;color:#666;font-family:monospace}}
.finding-cat{{color:#888;font-size:11px}}

.sev{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;text-transform:uppercase;color:#fff}}
.sev-critical{{background:#dc2626}}.sev-high{{background:#e67e22}}.sev-medium{{background:#f39c12;color:#333}}.sev-low{{background:#3498db}}.sev-info{{background:#555}}

.cat-group{{margin:20px 0}}
.cat-group h3{{font-size:15px;color:#ccc;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid #222}}
.cat-count{{font-size:12px;color:#666;font-weight:400}}
.cat-item{{padding:8px 12px;margin:4px 0;border-radius:6px;font-size:12px;border-left:3px solid #333;background:#111}}
.cat-item .sev{{margin-right:8px}}
.cat-critical{{border-left-color:#dc2626}}.cat-high{{border-left-color:#e67e22}}.cat-medium{{border-left-color:#f39c12}}.cat-low{{border-left-color:#3498db}}.cat-info{{border-left-color:#555}}

.raw-block{{background:#050505;border:1px solid #222;border-radius:8px;padding:16px;margin:12px 0;max-height:500px;overflow-y:auto;font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;line-height:1.6}}
.raw-line{{padding:1px 0;white-space:pre-wrap;word-break:break-all}}
.hl-vuln{{color:#dc2626;font-weight:700}}
.hl-finding{{color:#4ade80}}
.hl-sep{{color:#333}}

.footer{{border-top:2px solid #dc2626;padding-top:16px;margin-top:40px;text-align:center;font-size:10px;color:#555}}
.footer .conf{{font-weight:700;color:#dc2626;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}}

.toc{{margin:16px 0}}
.toc ol{{list-style:none;counter-reset:toc}}
.toc ol li{{counter-increment:toc;padding:6px 0;border-bottom:1px dotted #222}}
.toc ol li::before{{content:counter(toc) ". ";font-weight:700;color:#dc2626}}
.toc ol li a{{color:#ccc;font-size:13px}}

@media print{{
  body{{background:#fff;color:#1a1a2e}}
  .report-wrap{{max-width:100%}}
  .cover{{border-bottom-color:#c0392b}}
  .stat-box{{background:#fafafa;border-color:#eee}}
  .info-table td,.findings-table td{{border-bottom-color:#eee}}
  .findings-table th{{background:#1a1a2e}}
  .cat-item{{background:#fafafa}}
  .raw-block{{background:#f7f7f7;color:#333;border-color:#ddd}}
  .hl-vuln{{color:#c0392b}}.hl-finding{{color:#27ae60}}
  .cover .logo,.sev-critical,.seg-critical{{color:#c0392b}}
  .footer{{border-top-color:#c0392b}}
}}
</style>
</head>
<body>
<div class="report-wrap">

<div class="cover">
  <div class="logo">SAWLAH</div>
  <div class="logo-sub">Web Vulnerability Scanner</div>
  <h1>Nikto Scan Report</h1>
  <div class="target">{target}</div>
  <dl class="cover-meta">
    <dt>Scan Date</dt><dd>{ts}</dd>
    <dt>Scanner</dt><dd>Nikto / Sawlah-web</dd>
    <dt>Total Findings</dt><dd>{len(findings)}</dd>
    <dt>Server</dt><dd>{server_info.get('server', 'N/A')}</dd>
  </dl>
</div>

<div class="toc">
  <h2 class="section-title">Table of Contents</h2>
  <ol>
    <li><a href="#summary">Executive Summary</a></li>
    <li><a href="#server">Server Information</a></li>
    <li><a href="#findings">Findings Overview</a></li>
    <li><a href="#categories">Findings by Category</a></li>
    <li><a href="#raw">Raw Output</a></li>
  </ol>
</div>

<h2 class="section-title" id="summary">1. Executive Summary</h2>
<div class="stats-grid">
  <div class="stat-box"><div class="num num-total">{len(findings)}</div><div class="lbl">Total</div></div>
  <div class="stat-box"><div class="num num-critical">{sev_counts['critical']}</div><div class="lbl">Critical</div></div>
  <div class="stat-box"><div class="num num-high">{sev_counts['high']}</div><div class="lbl">High</div></div>
  <div class="stat-box"><div class="num num-medium">{sev_counts['medium']}</div><div class="lbl">Medium</div></div>
  <div class="stat-box"><div class="num num-low">{sev_counts['low'] + sev_counts['info']}</div><div class="lbl">Low / Info</div></div>
</div>
<div class="risk-bar">{risk_segs}</div>
<p style="color:#888;margin:12px 0">
  Nikto scanned <strong style="color:#ccc">{target}</strong> and tested approximately
  <strong style="color:#ccc">{stats['items_tested']}</strong> items, identifying
  <strong style="color:#ccc">{len(findings)}</strong> potential findings.
  {f"Encountered {stats['errors']} error(s) during scanning." if stats['errors'] else ""}
</p>

<h2 class="section-title" id="server">2. Server Information</h2>
<table class="info-table">
  {server_rows if server_rows else "<tr><td>No server information extracted</td></tr>"}
</table>

<h2 class="section-title" id="findings">3. Findings Overview</h2>
<table class="findings-table">
  <thead><tr><th>#</th><th>Severity</th><th>Category</th><th>Reference</th><th>Detail</th></tr></thead>
  <tbody>{findings_rows if findings_rows else "<tr><td colspan='5' style='color:#666;text-align:center;padding:20px'>No findings detected</td></tr>"}</tbody>
</table>

<h2 class="section-title" id="categories">4. Findings by Category</h2>
{category_sections if category_sections else "<p style='color:#666'>No categorized findings</p>"}

<h2 class="section-title" id="raw">5. Raw Nikto Output</h2>
<div class="raw-block">{raw_lines}</div>

<div class="footer">
  <div class="conf">Confidential &mdash; Security Assessment</div>
  Sawlah-web Penetration Testing Framework | Nikto Report generated {ts}
</div>

</div>
</body>
</html>"""
    return html
