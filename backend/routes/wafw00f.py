import os
import re
import shutil
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional

from config import REPORTS_DIR
from tool_runner import runner, new_task_id, tasks

router = APIRouter()


class Wafw00fRunRequest(BaseModel):
    target: str
    all_waf: bool = False
    verbose: bool = False
    double_check: bool = True
    extra_flags: str = ""
    save_report: bool = True
    project_id: Optional[int] = None


def _split_urls(raw: str) -> list[str]:
    urls = []
    for part in re.split(r"[,\n\r]+", raw):
        url = part.strip()
        if url:
            urls.append(url)
    return urls


def _build_wafw00f_cmd(url: str, all_waf: bool, verbose: bool, extra_flags: str) -> list[str]:
    binary = shutil.which("wafw00f")
    if not binary:
        return []
    cmd = [binary, url]
    if all_waf:
        cmd.append("-a")
    if verbose:
        cmd.append("-v")
    extra = extra_flags.strip()
    if extra:
        cmd.extend(extra.split())
    return cmd


@router.post("/run")
async def run_wafw00f(req: Wafw00fRunRequest):
    raw_target = req.target.strip()
    if not raw_target:
        return {"error": "Target URL(s) required"}

    urls = _split_urls(raw_target)
    if not urls:
        return {"error": "No valid URLs provided"}

    binary = shutil.which("wafw00f")
    if not binary:
        return {"error": "wafw00f binary not found on system"}

    report_filename = ""
    if req.save_report:
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", urls[0][:40].replace("://", "_"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"wafw00f_{safe}_{ts}.html"

    task_id = new_task_id()

    scan_id = None
    if req.project_id:
        from database import async_session, Scan
        async with async_session() as session:
            scan = Scan(
                project_id=req.project_id,
                tool_name="wafw00f",
                command=f"wafw00f double-check on {len(urls)} URL(s)",
                status="running",
            )
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            scan_id = scan.id

    async def _run():
        tasks[task_id] = {
            "status": "running",
            "tool_name": "wafw00f",
            "command": f"wafw00f double-check on {len(urls)} URL(s)",
            "output": "",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

        all_output = ""
        url_results = []

        for url in urls:
            tasks[task_id]["output"] += f"\n{'='*60}\n[*] Scanning: {url}\n{'='*60}\n"

            pass1_output = ""
            tasks[task_id]["output"] += "\n--- Pass 1 ---\n"
            cmd1 = _build_wafw00f_cmd(url, req.all_waf, req.verbose, req.extra_flags)
            if cmd1:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd1,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        env={**__import__("os").environ, "TERM": "xterm-256color"},
                    )
                    while True:
                        line = await proc.stdout.readline()
                        if not line:
                            break
                        decoded = line.decode("utf-8", errors="replace")
                        pass1_output += decoded
                        tasks[task_id]["output"] += decoded
                    await proc.wait()
                except Exception as e:
                    tasks[task_id]["output"] += f"[ERROR] Pass 1 failed: {e}\n"

            pass2_output = ""
            if req.double_check:
                tasks[task_id]["output"] += "\n--- Pass 2 (Double Check) ---\n"
                cmd2 = _build_wafw00f_cmd(url, req.all_waf, req.verbose, req.extra_flags)
                if cmd2:
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd2,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT,
                            env={**__import__("os").environ, "TERM": "xterm-256color"},
                        )
                        while True:
                            line = await proc.stdout.readline()
                            if not line:
                                break
                            decoded = line.decode("utf-8", errors="replace")
                            pass2_output += decoded
                            tasks[task_id]["output"] += decoded
                        await proc.wait()
                    except Exception as e:
                        tasks[task_id]["output"] += f"[ERROR] Pass 2 failed: {e}\n"

            p1 = _parse_single_output(pass1_output, url)
            p2 = _parse_single_output(pass2_output, url) if req.double_check else None

            url_results.append({
                "url": url,
                "pass1": p1,
                "pass2": p2,
                "pass1_raw": pass1_output,
                "pass2_raw": pass2_output,
            })

        summary_lines = ["\n" + "=" * 60, "[*] DOUBLE-CHECK SUMMARY", "=" * 60]
        for r in url_results:
            p1s = r["pass1"]
            p2s = r["pass2"]
            p1_waf = p1s["waf_name"] or ("No WAF" if p1s["no_waf"] else "Unknown")
            p2_waf = (p2s["waf_name"] or ("No WAF" if p2s["no_waf"] else "Unknown")) if p2s else "N/A"
            match = "CONFIRMED" if p1_waf == p2_waf else "INCONSISTENT"
            summary_lines.append(f"  {r['url']}: Pass1={p1_waf} | Pass2={p2_waf} => {match}")
        summary_lines.append("")
        tasks[task_id]["output"] += "\n".join(summary_lines)
        all_output = tasks[task_id]["output"]

        findings = _build_findings(url_results)

        if req.save_report and report_filename:
            clean_output = _strip_ansi(all_output)
            html = _build_wafw00f_report(url_results, findings, urls, clean_output)
            filepath = os.path.join(REPORTS_DIR, report_filename)
            with open(filepath, "w") as f:
                f.write(html)

        tasks[task_id]["status"] = "completed"
        tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        if scan_id:
            from database import async_session, Scan
            async with async_session() as session:
                scan = await session.get(Scan, scan_id)
                if scan:
                    scan.output = all_output
                    scan.status = "completed"
                    scan.finished_at = datetime.now(timezone.utc)
                    await session.commit()

        try:
            from notifications import add_notification
            add_notification(
                title="wafw00f scan completed",
                message=f"Scanned {len(urls)} URL(s) with double-check",
                severity="success", tool_name="wafw00f", task_id=task_id,
            )
        except Exception:
            pass

    asyncio.create_task(_run())

    return {
        "task_id": task_id,
        "command": f"wafw00f double-check on {len(urls)} URL(s)",
        "scan_id": scan_id,
        "report_filename": report_filename,
        "url_count": len(urls),
        "status": "running",
    }


@router.get("/reports")
async def list_wafw00f_reports():
    reports = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.startswith("wafw00f_") and f.endswith(".html"):
            path = os.path.join(REPORTS_DIR, f)
            stat = os.stat(path)
            reports.append({
                "filename": f,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return reports


@router.get("/reports/{filename}")
async def get_wafw00f_report(filename: str):
    if not filename.startswith("wafw00f_") or not filename.endswith(".html"):
        return {"error": "Invalid report filename"}
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": "Report not found"}
    with open(filepath, "r") as f:
        content = f.read()
    return HTMLResponse(content=content)


@router.get("/reports/{filename}/download")
async def download_wafw00f_report(filename: str):
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        return {"error": "Report not found"}
    return FileResponse(filepath, filename=filename, media_type="text/html")


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _parse_single_output(output: str, url: str) -> dict:
    """Parse a single wafw00f run output to extract WAF detection info."""
    result = {
        "url": url,
        "waf_name": None,
        "waf_detected": False,
        "no_waf": False,
        "generic_detection": False,
        "details": [],
    }
    if not output:
        return result

    for line in output.splitlines():
        line_stripped = _strip_ansi(line.strip())

        m = re.search(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", line_stripped, re.I)
        if m:
            result["waf_name"] = m.group(1).strip()
            result["waf_detected"] = True

        if re.search(r"No WAF detected|is not behind a WAF", line_stripped, re.I):
            result["no_waf"] = True
            result["waf_detected"] = False

        if re.search(r"generic detection", line_stripped, re.I):
            result["generic_detection"] = True

        if re.search(r"behind a WAF or security", line_stripped, re.I) and not result["waf_name"]:
            result["waf_detected"] = True
            result["generic_detection"] = True

        if line_stripped and not line_stripped.startswith("["):
            pass

        if re.search(r"\[\*\]|\[\+\]|\[-\]", line_stripped):
            result["details"].append(line_stripped)

    return result


WAF_RECOMMENDATIONS = {
    "no_waf": [
        "Deploy a Web Application Firewall (WAF) to protect against common web attacks (SQLi, XSS, RFI).",
        "Consider cloud-based WAF solutions (Cloudflare, AWS WAF, Akamai) for immediate protection.",
    ],
    "waf_detected": [
        "Verify WAF rules are up-to-date and cover OWASP Top 10 attack categories.",
        "Test WAF bypass techniques to ensure the WAF configuration is robust against evasion.",
    ],
    "inconsistent": [
        "Investigate inconsistent WAF detection — the WAF may have intermittent issues or load-balancer misconfig.",
        "Ensure all backend servers behind the load balancer have consistent WAF coverage.",
    ],
    "generic": [
        "The WAF could not be fingerprinted — consider running with -a flag to test against all known WAF signatures.",
        "Review server response headers for WAF-related indicators and harden header exposure.",
    ],
}


def _build_findings(url_results: list[dict]) -> list[dict]:
    findings = []
    for r in url_results:
        p1 = r["pass1"]
        p2 = r["pass2"]
        url = r["url"]
        p1_raw = r["pass1_raw"]
        p2_raw = r["pass2_raw"]

        poc_text = f"=== Pass 1 ===\n{_strip_ansi(p1_raw.strip())}"
        if p2:
            poc_text += f"\n\n=== Pass 2 (Double Check) ===\n{_strip_ansi(p2_raw.strip())}"

        if p1["no_waf"] and (not p2 or p2["no_waf"]):
            findings.append({
                "id": None,
                "name": f"No WAF Detected: {url}",
                "severity": "critical",
                "description": f"The target {url} does not appear to be protected by any Web Application Firewall. "
                               f"This was {'confirmed by double-check scanning' if p2 else 'detected in a single pass'}. "
                               f"Without a WAF, the application is directly exposed to web-based attacks.",
                "recommendations": WAF_RECOMMENDATIONS["no_waf"],
                "poc": poc_text,
                "url": url,
                "component": url,
            })

        elif p1["waf_detected"] and p2 and p2["waf_detected"]:
            p1_name = p1["waf_name"] or "Unknown/Generic"
            p2_name = p2["waf_name"] or "Unknown/Generic"
            if p1_name == p2_name:
                severity = "medium" if not p1["generic_detection"] else "low"
                recs = WAF_RECOMMENDATIONS["waf_detected"] if not p1["generic_detection"] else WAF_RECOMMENDATIONS["generic"]
                findings.append({
                    "id": None,
                    "name": f"WAF Detected (Confirmed): {p1_name}",
                    "severity": severity,
                    "description": f"The target {url} is protected by {p1_name} WAF. "
                                   f"Detection was confirmed across both scan passes. "
                                   f"{'The WAF was generically detected and could not be fingerprinted precisely.' if p1['generic_detection'] else 'The WAF was positively identified.'}",
                    "recommendations": recs,
                    "poc": poc_text,
                    "url": url,
                    "component": url,
                })
            else:
                findings.append({
                    "id": None,
                    "name": f"WAF Inconsistent: {p1_name} vs {p2_name}",
                    "severity": "high",
                    "description": f"The target {url} returned inconsistent WAF detection results. "
                                   f"Pass 1 identified '{p1_name}' while Pass 2 identified '{p2_name}'. "
                                   f"This may indicate load-balancer routing to differently configured backends.",
                    "recommendations": WAF_RECOMMENDATIONS["inconsistent"],
                    "poc": poc_text,
                    "url": url,
                    "component": url,
                })

        elif p1["waf_detected"] and p2 and p2["no_waf"]:
            findings.append({
                "id": None,
                "name": f"WAF Inconsistent: Detected then Absent on {url}",
                "severity": "high",
                "description": f"Pass 1 detected a WAF ({p1['waf_name'] or 'generic'}) on {url} but Pass 2 found no WAF. "
                               f"This inconsistency suggests intermittent WAF coverage or load-balancer misconfiguration.",
                "recommendations": WAF_RECOMMENDATIONS["inconsistent"],
                "poc": poc_text,
                "url": url,
                "component": url,
            })

        elif p1["no_waf"] and p2 and p2["waf_detected"]:
            findings.append({
                "id": None,
                "name": f"WAF Inconsistent: Absent then Detected on {url}",
                "severity": "high",
                "description": f"Pass 1 found no WAF on {url} but Pass 2 detected {p2['waf_name'] or 'a generic WAF'}. "
                               f"This inconsistency suggests intermittent WAF coverage.",
                "recommendations": WAF_RECOMMENDATIONS["inconsistent"],
                "poc": poc_text,
                "url": url,
                "component": url,
            })

        elif p1["waf_detected"] and not p2:
            waf_name = p1["waf_name"] or "Unknown/Generic"
            severity = "info" if not p1["generic_detection"] else "low"
            findings.append({
                "id": None,
                "name": f"WAF Detected: {waf_name}",
                "severity": severity,
                "description": f"The target {url} is protected by {waf_name} WAF (single-pass detection).",
                "recommendations": WAF_RECOMMENDATIONS["waf_detected"],
                "poc": poc_text,
                "url": url,
                "component": url,
            })

        else:
            findings.append({
                "id": None,
                "name": f"WAF Status Unknown: {url}",
                "severity": "info",
                "description": f"wafw00f could not determine the WAF status of {url}. The target may be unreachable or returned unexpected responses.",
                "recommendations": WAF_RECOMMENDATIONS["generic"],
                "poc": poc_text,
                "url": url,
                "component": url,
            })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))
    for i, f in enumerate(findings, 1):
        f["id"] = f"W-{i:03d}"

    return findings


def _build_wafw00f_report(url_results: list[dict], findings: list[dict], urls: list[str], raw_output: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    waf_found_count = sum(1 for r in url_results if r["pass1"]["waf_detected"])
    no_waf_count = sum(1 for r in url_results if r["pass1"]["no_waf"])
    confirmed = sum(1 for r in url_results if r["pass1"]["waf_detected"] and r["pass2"] and r["pass2"]["waf_detected"]
                    and r["pass1"]["waf_name"] == r["pass2"]["waf_name"])

    total = len(findings) or 1
    risk_segs = ""
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev_name, 0)
        if count > 0:
            pct = max(round(count / total * 100), 5)
            risk_segs += f'<div class="seg seg-{sev_name}" style="width:{pct}%">{count}</div>'

    findings_rows = ""
    for f in findings:
        rec_html = "<ul>" + "".join(f"<li>{r}</li>" for r in f["recommendations"]) + "</ul>"
        poc_escaped = f["poc"][:800].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        findings_rows += f"""
        <tr>
            <td class="finding-num">{f['id']}</td>
            <td class="finding-name">{f['name']}</td>
            <td>{f['description']}</td>
            <td class="finding-rec">{rec_html}</td>
            <td><pre class="poc-inline">{poc_escaped}</pre></td>
            <td><span class="sev sev-{f['severity']}">{f['severity'].upper()}</span></td>
        </tr>"""

    detail_cards = ""
    for f in findings:
        rec_items = "".join(f"<li>{r}</li>" for r in f["recommendations"])
        poc_escaped = f["poc"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        detail_cards += f"""
        <div class="finding-card {f['severity']}" id="finding-{f['id']}">
            <div class="finding-header">
                <span class="finding-id">{f['id']}</span>
                <span class="sev sev-{f['severity']}">{f['severity'].upper()}</span>
                <span class="finding-title">{f['name']}</span>
            </div>
            <div class="finding-meta">
                <div><dt>Affected Component</dt><dd>{f['component']}</dd></div>
                <div><dt>Tool</dt><dd>wafw00f (double-check)</dd></div>
            </div>
            <div class="finding-desc">{f['description']}</div>
            <div class="poc-block">
                <div class="poc-label">Proof of Concept</div>
                <div class="poc-output">{poc_escaped}</div>
            </div>
            <div class="remediation">
                <strong>Recommendations:</strong>
                <ol>{rec_items}</ol>
            </div>
        </div>"""

    url_comparison = ""
    for r in url_results:
        p1 = r["pass1"]
        p2 = r["pass2"]
        p1_status = p1["waf_name"] or ("No WAF" if p1["no_waf"] else "Unknown")
        p2_status = (p2["waf_name"] or ("No WAF" if p2["no_waf"] else "Unknown")) if p2 else "N/A"
        match_class = "match-ok" if p1_status == p2_status else "match-warn"
        match_txt = "Confirmed" if p1_status == p2_status else "Inconsistent"
        url_comparison += f"""
        <tr>
            <td class="url-cell">{r['url']}</td>
            <td>{p1_status}</td>
            <td>{p2_status}</td>
            <td><span class="{match_class}">{match_txt}</span></td>
        </tr>"""

    raw_lines = ""
    for line in raw_output.splitlines():
        escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        cls = ""
        if re.search(r"is behind", line, re.I):
            cls = "hl-waf"
        elif re.search(r"No WAF|not behind", line, re.I):
            cls = "hl-nowaf"
        elif re.search(r"SUMMARY|={10,}", line):
            cls = "hl-sep"
        elif line.strip().startswith("[*]"):
            cls = "hl-info"
        raw_lines += f'<div class="raw-line {cls}">{escaped}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Detection Report - wafw00f</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#0a0a0a;color:#e5e5e5;line-height:1.6;font-size:13px}}
a{{color:#dc2626;text-decoration:none}}
a:hover{{text-decoration:underline}}
.report-wrap{{max-width:1200px;margin:0 auto;padding:20px}}
.cover{{text-align:center;padding:60px 40px;border-bottom:3px solid #dc2626;margin-bottom:40px}}
.cover .logo{{font-size:42px;font-weight:800;color:#dc2626;letter-spacing:2px}}
.cover .logo-sub{{font-size:11px;text-transform:uppercase;letter-spacing:6px;color:#666;margin:4px 0 30px}}
.cover h1{{font-size:24px;font-weight:700;color:#fff;margin-bottom:4px}}
.cover .target{{font-size:16px;color:#dc2626;font-family:monospace;margin-bottom:30px}}
.cover-meta{{display:grid;grid-template-columns:1fr 1fr;gap:8px;text-align:left;max-width:450px;margin:0 auto}}
.cover-meta dt{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#666;font-weight:600}}
.cover-meta dd{{font-size:13px;color:#ccc;margin-bottom:6px}}
.section-title{{font-size:18px;font-weight:700;color:#fff;border-bottom:2px solid #dc2626;padding-bottom:6px;margin:36px 0 16px}}
.stats-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0}}
.stat-box{{background:#141414;border:1px solid #222;border-radius:8px;padding:16px;text-align:center}}
.stat-box .num{{font-size:28px;font-weight:800}}
.stat-box .lbl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#666;margin-top:2px}}
.num-critical{{color:#dc2626}}.num-high{{color:#e67e22}}.num-medium{{color:#f1c40f}}.num-low{{color:#3498db}}.num-total{{color:#fff}}
.risk-bar{{display:flex;height:20px;border-radius:6px;overflow:hidden;margin:12px 0;background:#1a1a1a}}
.risk-bar .seg{{display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff}}
.seg-critical{{background:#dc2626}}.seg-high{{background:#e67e22}}.seg-medium{{background:#f1c40f;color:#333}}.seg-low{{background:#3498db}}.seg-info{{background:#95a5a6}}
.findings-table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px}}
.findings-table th{{background:#1a1a1a;color:#888;padding:10px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #dc2626}}
.findings-table td{{padding:10px;border-bottom:1px solid #1a1a1a;vertical-align:top}}
.findings-table tr:hover{{background:#111}}
.finding-num{{font-weight:700;color:#666;font-family:monospace;white-space:nowrap}}
.finding-name{{font-weight:600;color:#e5e5e5;min-width:180px}}
.finding-rec ul{{margin:0;padding-left:16px;font-size:11px;color:#aaa}}
.finding-rec li{{margin:2px 0}}
.poc-inline{{background:#0d0d0d;border:1px solid #222;border-radius:4px;padding:6px 8px;font-size:10px;color:#888;white-space:pre-wrap;max-height:120px;overflow-y:auto;margin:0;font-family:'JetBrains Mono','Fira Code',monospace}}
.sev{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;text-transform:uppercase;color:#fff;white-space:nowrap}}
.sev-critical{{background:#dc2626}}.sev-high{{background:#e67e22}}.sev-medium{{background:#f39c12;color:#333}}.sev-low{{background:#3498db}}.sev-info{{background:#555}}
.comparison-table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px}}
.comparison-table th{{background:#1a1a1a;color:#888;padding:8px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #dc2626}}
.comparison-table td{{padding:8px 12px;border-bottom:1px solid #1a1a1a}}
.comparison-table tr:hover{{background:#111}}
.url-cell{{font-family:monospace;color:#dc2626;font-size:12px}}
.match-ok{{color:#4ade80;font-weight:700}}.match-warn{{color:#f59e0b;font-weight:700}}
.finding-card{{border:1px solid #222;border-left:4px solid;border-radius:6px;padding:16px 20px;margin:16px 0;background:#111}}
.finding-card.critical{{border-left-color:#dc2626}}.finding-card.high{{border-left-color:#e67e22}}.finding-card.medium{{border-left-color:#f39c12}}.finding-card.low{{border-left-color:#3498db}}.finding-card.info{{border-left-color:#555}}
.finding-header{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.finding-id{{font-size:11px;font-weight:700;color:#666}}
.finding-title{{font-size:15px;font-weight:700;color:#fff}}
.finding-meta{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:10px 0;font-size:12px}}
.finding-meta dt{{color:#666;font-size:10px;text-transform:uppercase}}.finding-meta dd{{color:#ccc}}
.finding-desc{{margin:10px 0;color:#aaa;font-size:13px;line-height:1.7}}
.poc-block{{background:#0a0a0a;border:1px solid #222;border-radius:6px;margin:10px 0;overflow:hidden}}
.poc-label{{background:#1a1a1a;color:#888;padding:4px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px}}
.poc-output{{padding:10px 14px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:10px;color:#888;white-space:pre-wrap;max-height:300px;overflow-y:auto;line-height:1.5}}
.remediation{{background:#0d1f0d;border:1px solid #1a3a1a;border-radius:6px;padding:10px 14px;margin:10px 0;font-size:12px;color:#4ade80}}
.remediation strong{{color:#22c55e}}.remediation ol{{margin:6px 0 0 16px;color:#6ee7b7}}.remediation li{{margin:3px 0}}
.raw-block{{background:#050505;border:1px solid #222;border-radius:8px;padding:16px;margin:12px 0;max-height:500px;overflow-y:auto;font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;line-height:1.6}}
.raw-line{{padding:1px 0;white-space:pre-wrap;word-break:break-all}}
.hl-waf{{color:#4ade80;font-weight:700}}.hl-nowaf{{color:#dc2626;font-weight:700}}.hl-sep{{color:#444;font-weight:700}}.hl-info{{color:#60a5fa}}
.toc{{margin:16px 0}}.toc ol{{list-style:none;counter-reset:toc}}.toc ol li{{counter-increment:toc;padding:6px 0;border-bottom:1px dotted #222}}.toc ol li::before{{content:counter(toc) ". ";font-weight:700;color:#dc2626}}.toc ol li a{{color:#ccc;font-size:13px}}
.footer{{border-top:2px solid #dc2626;padding-top:16px;margin-top:40px;text-align:center;font-size:10px;color:#555}}
.footer .conf{{font-weight:700;color:#dc2626;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}}
@media print{{
  body{{background:#fff;color:#1a1a2e}}
  .report-wrap{{max-width:100%}}
  .stat-box{{background:#fafafa;border-color:#eee}}
  .findings-table td,.findings-table th{{border-bottom-color:#eee}}
  .findings-table th,.comparison-table th{{background:#1a1a2e;color:#fff}}
  .finding-card{{background:#fff;border-color:#ddd}}
  .raw-block{{background:#f7f7f7;color:#333;border-color:#ddd}}
  .poc-inline{{background:#f7f7f7;color:#333;border-color:#ddd}}
  .remediation{{background:#eaf7ea;border-color:#c3e6c3;color:#2d6a2d}}
  .cover .logo,.sev-critical{{color:#c0392b}}
  .footer{{border-top-color:#c0392b}}
}}
</style>
</head>
<body>
<div class="report-wrap">

<div class="cover">
  <div class="logo">SAWLAH</div>
  <div class="logo-sub">WAF Detection Scanner</div>
  <h1>WAF Detection Report (Double-Check)</h1>
  <div class="target">{len(urls)} URL(s) scanned</div>
  <dl class="cover-meta">
    <dt>Scan Date</dt><dd>{ts}</dd>
    <dt>Scanner</dt><dd>wafw00f / Sawlah-web</dd>
    <dt>Total URLs</dt><dd>{len(urls)}</dd>
    <dt>Total Findings</dt><dd>{len(findings)}</dd>
  </dl>
</div>

<div class="toc">
  <h2 class="section-title">Table of Contents</h2>
  <ol>
    <li><a href="#summary">Executive Summary</a></li>
    <li><a href="#findings-table">Findings Table</a></li>
    <li><a href="#findings-detail">Detailed Findings</a></li>
    <li><a href="#comparison">URL Comparison (Pass 1 vs Pass 2)</a></li>
    <li><a href="#raw">Raw Output</a></li>
  </ol>
</div>

<h2 class="section-title" id="summary">1. Executive Summary</h2>
<div class="stats-grid">
  <div class="stat-box"><div class="num num-total">{len(urls)}</div><div class="lbl">URLs Scanned</div></div>
  <div class="stat-box"><div class="num num-medium">{waf_found_count}</div><div class="lbl">WAFs Found</div></div>
  <div class="stat-box"><div class="num num-critical">{no_waf_count}</div><div class="lbl">Unprotected</div></div>
  <div class="stat-box"><div class="num" style="color:#4ade80">{confirmed}</div><div class="lbl">Confirmed</div></div>
  <div class="stat-box"><div class="num num-high">{sev_counts.get('high',0)}</div><div class="lbl">Inconsistent</div></div>
</div>
<div class="risk-bar">{risk_segs}</div>
<p style="color:#888;margin:12px 0">
  wafw00f scanned <strong style="color:#ccc">{len(urls)}</strong> URL(s) with double-check verification,
  producing <strong style="color:#ccc">{len(findings)}</strong> findings.
  {f'<strong style="color:#dc2626">{no_waf_count}</strong> URL(s) appear unprotected by any WAF.' if no_waf_count else ''}
</p>

<h2 class="section-title" id="findings-table">2. Findings Table</h2>
<table class="findings-table">
  <thead><tr><th>#</th><th>Finding Name</th><th>Description</th><th>Recommendations</th><th>POC</th><th>Score</th></tr></thead>
  <tbody>{findings_rows if findings_rows else "<tr><td colspan='6' style='color:#666;text-align:center;padding:20px'>No findings detected</td></tr>"}</tbody>
</table>

<h2 class="section-title" id="findings-detail">3. Detailed Findings</h2>
{detail_cards if detail_cards else "<p style='color:#666'>No detailed findings to display</p>"}

<h2 class="section-title" id="comparison">4. URL Comparison (Pass 1 vs Pass 2)</h2>
<table class="comparison-table">
  <thead><tr><th>URL</th><th>Pass 1 Result</th><th>Pass 2 Result</th><th>Status</th></tr></thead>
  <tbody>{url_comparison}</tbody>
</table>

<h2 class="section-title" id="raw">5. Raw Output</h2>
<div class="raw-block">{raw_lines}</div>

<div class="footer">
  <div class="conf">Confidential &mdash; Security Assessment</div>
  Sawlah-web Penetration Testing Framework | wafw00f Report generated {ts}
</div>

</div>
</body>
</html>"""
    return html
