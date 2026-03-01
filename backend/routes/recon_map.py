import re
import os
import math
import shutil
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from tool_runner import runner, new_task_id, tasks
from config import TOOL_PATHS

router = APIRouter()


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _parse_nmap_services(output: str) -> list[dict]:
    services = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", line)
        if m:
            services.append({
                "port": int(m.group(1)), "proto": m.group(2),
                "state": m.group(3), "service": m.group(4),
                "version": m.group(5).strip(),
            })
    return services


def _parse_subdomains(output: str) -> list[str]:
    subs = set()
    for line in output.splitlines():
        cleaned = _strip_ansi(line.strip())
        if re.match(r"^[\w.-]+\.\w{2,}$", cleaned):
            subs.add(cleaned)
        m = re.search(r"([\w.-]+\.\w{2,})", cleaned)
        if m and "." in m.group(1) and len(m.group(1)) > 4:
            candidate = m.group(1)
            if not candidate.startswith(("usr.", "share.", "com.", "seclists.")):
                subs.add(candidate)
    return sorted(subs)


def _parse_directories(output: str) -> list[dict]:
    dirs = []
    for line in output.splitlines():
        m = re.search(r"(https?://\S+)\s+.*?(\d{3})", line)
        if m:
            dirs.append({"url": m.group(1), "status": int(m.group(2))})
            continue
        m2 = re.search(r"\+\s+(https?://\S+)\s+\(Code:\s*(\d+)", line)
        if m2:
            dirs.append({"url": m2.group(1), "status": int(m2.group(2))})
    return dirs


def _parse_vulns(output: str) -> list[str]:
    vulns = []
    for line in output.splitlines():
        if re.search(r"VULNERABLE|CVE-\d{4}-\d+", line, re.I):
            vulns.append(_strip_ansi(line.strip()))
    return vulns


def _parse_wafw00f(output: str) -> dict:
    clean = _strip_ansi(output)
    result = {"detected": False, "waf_name": None, "details": ""}
    for line in clean.splitlines():
        m = re.search(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", line, re.I)
        if m:
            result["detected"] = True
            result["waf_name"] = m.group(1).strip()
            result["details"] = line.strip()
        if re.search(r"No WAF detected|is not behind a WAF", line, re.I):
            result["detected"] = False
            result["waf_name"] = "No WAF"
            result["details"] = line.strip()
    return result


def _parse_whois(output: str) -> dict:
    info = {}
    for line in output.splitlines():
        lower = line.lower().strip()
        if lower.startswith("registrar:"):
            info["registrar"] = line.split(":", 1)[1].strip()
        elif lower.startswith("creation date:") or lower.startswith("created:"):
            info["created"] = line.split(":", 1)[1].strip()
        elif lower.startswith("registry expiry date:") or lower.startswith("expiry date:"):
            info["expires"] = line.split(":", 1)[1].strip()
        elif lower.startswith("registrant country:"):
            info["country"] = line.split(":", 1)[1].strip()
        elif lower.startswith("registrant organization:") or lower.startswith("org:"):
            info["org"] = line.split(":", 1)[1].strip()
        elif lower.startswith("name server:") or lower.startswith("nserver:"):
            info.setdefault("nameservers", [])
            ns = line.split(":", 1)[1].strip()
            if ns and ns not in info["nameservers"]:
                info["nameservers"].append(ns)
    return info


def _parse_sslscan(output: str) -> dict:
    clean = _strip_ansi(output)
    info = {"protocols": [], "ciphers": [], "cert_subject": "", "cert_issuer": "", "cert_expiry": ""}
    for line in clean.splitlines():
        stripped = line.strip()
        if re.match(r"(SSLv|TLSv)\S+\s+(enabled|disabled)", stripped, re.I):
            info["protocols"].append(stripped)
        m = re.search(r"Subject:\s*(.+)", stripped)
        if m:
            info["cert_subject"] = m.group(1).strip()
        m = re.search(r"Issuer:\s*(.+)", stripped)
        if m:
            info["cert_issuer"] = m.group(1).strip()
        m = re.search(r"Not valid after:\s*(.+)", stripped)
        if m:
            info["cert_expiry"] = m.group(1).strip()
    return info


def _parse_whatweb_techs(output: str) -> list[dict]:
    techs = []
    seen = set()
    clean = _strip_ansi(output)
    for line in clean.splitlines():
        for m in re.finditer(r"(\w[\w./ -]+?)\[([^\]]+)\]", line):
            name = m.group(1).strip()
            detail = m.group(2).strip()
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            version = ""
            vm = re.search(r"([\d]+\.[\d.]+)", detail)
            if vm:
                version = vm.group(1)
            category = "Technology"
            if re.search(r"PHP|Python|Ruby|Java|Node|ASP|Perl", name, re.I):
                category = "Language"
            elif re.search(r"Apache|Nginx|IIS|LiteSpeed|Caddy", name, re.I):
                category = "Server"
            elif re.search(r"WordPress|Joomla|Drupal|Django|Laravel", name, re.I):
                category = "Framework"
            elif re.search(r"jQuery|Bootstrap|React|Angular|Vue", name, re.I):
                category = "Frontend"
            techs.append({"name": name, "version": version, "detail": detail, "category": category})
    return techs


def _merge_webrecon_sessions(targets: dict):
    try:
        from routes.webrecon import recon_sessions
    except ImportError:
        return

    for sid, session in recon_sessions.items():
        if session.get("status") not in ("completed", "running"):
            continue
        domain = session.get("domain", "")
        if not domain:
            continue

        if domain not in targets:
            targets[domain] = _empty_target(domain)

        t = targets[domain]
        results = session.get("results", {})

        for sub in results.get("subdomains", []):
            fqdn = sub.get("subdomain", "")
            if fqdn and fqdn not in t["subdomains"]:
                t["subdomains"].append(fqdn)
        for d in results.get("directories", []):
            path = d.get("path", "")
            if path:
                existing = [x.get("url") or x.get("path", "") for x in t["directories"]]
                if path not in existing:
                    t["directories"].append({"url": path, "status": d.get("status", 0)})
        for tech in results.get("technologies", []):
            name = tech.get("name", "")
            existing = [x.get("name", "") for x in t["technologies"]]
            if name and name not in existing:
                t["technologies"].append(tech)
        for exp in results.get("exploits", []):
            title = exp.get("title", "")
            existing = [x.get("title", "") for x in t["exploits"]]
            if title and title not in existing:
                t["exploits"].append(exp)
        si = results.get("server_info", {})
        if si:
            t["server_info"].update(si)
        t["scans"].append({"task_id": sid, "tool": "webrecon", "status": session.get("status")})


def _empty_target(name: str) -> dict:
    return {
        "target": name, "ports": [], "services": [], "subdomains": [],
        "directories": [], "technologies": [], "exploits": [], "vulns": [],
        "server_info": {}, "scans": [], "errors": [],
        "waf_status": None, "whois_info": None, "ssl_info": None,
    }


@router.get("/targets")
async def list_targets():
    targets = {}
    for tid, t in tasks.items():
        cmd = t.get("command", "")
        tool = t.get("tool_name", "")
        output = t.get("output", "")

        ip_matches = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", cmd)
        domain_matches = re.findall(r"(?:https?://)?([a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,})", cmd)
        all_targets = set(ip_matches + domain_matches)

        for target in all_targets:
            if target.startswith("usr") or target.startswith("share") or target.startswith("seclists"):
                continue
            if target not in targets:
                targets[target] = _empty_target(target)

            targets[target]["scans"].append({
                "task_id": tid, "tool": tool, "status": t.get("status"),
            })

            if tool == "nmap" and output:
                for svc in _parse_nmap_services(output):
                    existing_ports = [p["port"] for p in targets[target]["ports"]]
                    if svc["port"] not in existing_ports:
                        targets[target]["ports"].append(svc)
                        targets[target]["services"].append(svc)

            if tool in ("gobuster_dns", "dnsenum", "ffuf", "subenum_all", "fierce", "dnsrecon", "theHarvester") and output:
                for sub in _parse_subdomains(output):
                    if sub not in targets[target]["subdomains"]:
                        targets[target]["subdomains"].append(sub)

            if tool in ("gobuster_dir", "ffuf", "dirb", "feroxbuster", "subenum_all") and output:
                for d in _parse_directories(output):
                    targets[target]["directories"].append(d)

            if tool == "wafw00f" and output:
                waf = _parse_wafw00f(output)
                if waf.get("waf_name") or waf.get("detected"):
                    targets[target]["waf_status"] = waf
                elif not targets[target]["waf_status"]:
                    targets[target]["waf_status"] = waf

            if tool == "whois" and output:
                info = _parse_whois(output)
                if info:
                    targets[target]["whois_info"] = info

            if tool == "sslscan" and output:
                info = _parse_sslscan(output)
                if info.get("cert_subject") or info.get("protocols"):
                    targets[target]["ssl_info"] = info

            if tool == "whatweb" and output:
                for tech in _parse_whatweb_techs(output):
                    existing = [x.get("name", "") for x in targets[target]["technologies"]]
                    if tech["name"] not in existing:
                        targets[target]["technologies"].append(tech)

            if tool == "dig" and output:
                for line in _strip_ansi(output).splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith(";") and "\t" in stripped:
                        targets[target].setdefault("dns_records", [])
                        if stripped not in targets[target]["dns_records"]:
                            targets[target]["dns_records"].append(stripped)

            if output:
                for v in _parse_vulns(output):
                    if v not in targets[target]["vulns"]:
                        targets[target]["vulns"].append(v)

            task_status = t.get("status", "")
            if task_status == "error" and tool not in ("auto_recon",):
                error_msg = f"{tool}: "
                last_lines = [l.strip() for l in output.splitlines() if l.strip()][-3:]
                error_msg += "; ".join(last_lines)[:120] if last_lines else "Unknown error"
                targets[target].setdefault("errors", [])
                if error_msg not in targets[target]["errors"]:
                    targets[target]["errors"].append(error_msg)

    _merge_webrecon_sessions(targets)
    return list(targets.values())


@router.get("/targets/{target}")
async def get_target_map(target: str):
    all_targets = await list_targets()
    data = None
    for t in all_targets:
        if t["target"] == target:
            data = t
            break

    if not data:
        return {"nodes": [], "edges": [], "target": target}

    nodes = []
    edges = []
    node_id = 0
    cx, cy = 600, 500

    center_id = f"target-{node_id}"
    nodes.append({
        "id": center_id, "type": "target",
        "data": {"label": data["target"], "scans": len(data["scans"])},
        "position": {"x": cx, "y": cy},
    })

    # -- Info ring: WAF, SSL, WHOIS at fixed positions around center --
    waf = data.get("waf_status")
    if waf:
        node_id += 1
        wid = f"waf-{node_id}"
        nodes.append({
            "id": wid, "type": "waf",
            "data": {"detected": waf.get("detected", False), "name": waf.get("waf_name", "Unknown"), "details": waf.get("details", "")},
            "position": {"x": cx - 350, "y": cy - 50},
        })
        edges.append({"id": f"e-{center_id}-{wid}", "source": center_id, "target": wid, "sourceHandle": "l"})

    whois = data.get("whois_info")
    if whois:
        node_id += 1
        whid = f"whois-{node_id}"
        nodes.append({
            "id": whid, "type": "whois",
            "data": whois,
            "position": {"x": cx + 350, "y": cy - 50},
        })
        edges.append({"id": f"e-{center_id}-{whid}", "source": center_id, "target": whid})

    ssl = data.get("ssl_info")
    if ssl and (ssl.get("cert_subject") or ssl.get("protocols")):
        node_id += 1
        slid = f"ssl-{node_id}"
        nodes.append({
            "id": slid, "type": "ssl",
            "data": ssl,
            "position": {"x": cx, "y": cy - 250},
        })
        edges.append({"id": f"e-{center_id}-{slid}", "source": center_id, "target": slid, "sourceHandle": "t"})

    # -- Ports: arc on the right side --
    port_count = len(data["ports"])
    for i, port in enumerate(data["ports"]):
        node_id += 1
        pid = f"port-{node_id}"
        arc_start = -0.8
        arc_span = 1.6
        angle = arc_start + (i / max(port_count, 1)) * arc_span
        r = 280
        x = cx + math.cos(angle) * r
        y = cy + math.sin(angle) * r
        nodes.append({
            "id": pid, "type": "port",
            "data": {"port": port["port"], "proto": port["proto"], "state": port["state"], "service": port["service"], "version": port.get("version", "")},
            "position": {"x": x, "y": y},
        })
        edges.append({"id": f"e-{center_id}-{pid}", "source": center_id, "target": pid})
        if port.get("version"):
            node_id += 1
            sid = f"svc-{node_id}"
            nodes.append({
                "id": sid, "type": "service",
                "data": {"label": f"{port['service']} {port['version']}"},
                "position": {"x": x + 160, "y": y},
            })
            edges.append({"id": f"e-{pid}-{sid}", "source": pid, "target": sid})

    # -- Technologies: grid above center --
    techs = data.get("technologies", [])[:12]
    for i, tech in enumerate(techs):
        node_id += 1
        tid = f"tech-{node_id}"
        col, row = i % 4, i // 4
        nodes.append({
            "id": tid, "type": "technology",
            "data": {"name": tech.get("name", ""), "version": tech.get("version", ""), "category": tech.get("category", "Technology")},
            "position": {"x": cx - 250 + col * 170, "y": cy - 400 - row * 80},
        })
        edges.append({"id": f"e-{center_id}-{tid}", "source": center_id, "target": tid, "sourceHandle": "t"})

    # -- Subdomains: left-side column --
    subs = data.get("subdomains", [])[:30]
    for i, sub in enumerate(subs):
        node_id += 1
        sid = f"sub-{node_id}"
        col, row = i % 2, i // 2
        nodes.append({
            "id": sid, "type": "subdomain", "data": {"label": sub},
            "position": {"x": cx - 550 - col * 200, "y": cy + 150 + row * 40},
        })
        edges.append({"id": f"e-{center_id}-{sid}", "source": center_id, "target": sid, "sourceHandle": "l"})

    # -- Directories: bottom-right grid --
    directories = data.get("directories", [])[:20]
    for i, d in enumerate(directories):
        node_id += 1
        did = f"dir-{node_id}"
        col, row = i % 4, i // 4
        url = d.get("url") or d.get("path", "")
        nodes.append({
            "id": did, "type": "directory", "data": {"url": url, "status": d.get("status", 0)},
            "position": {"x": cx + 150 + col * 180, "y": cy + 300 + row * 50},
        })
        port80 = next((n for n in nodes if n.get("type") == "port" and n["data"].get("port") in (80, 443, 8080, 8443)), None)
        parent = port80["id"] if port80 else center_id
        edges.append({"id": f"e-{parent}-{did}", "source": parent, "target": did})

    # -- Exploits: bottom-left --
    exploits = data.get("exploits", [])[:16]
    tech_nodes_by_name = {n["data"]["name"].lower(): n["id"] for n in nodes if n["type"] == "technology"}
    for i, exp in enumerate(exploits):
        node_id += 1
        eid = f"exploit-{node_id}"
        col, row = i % 3, i // 3
        nodes.append({
            "id": eid, "type": "exploit",
            "data": {"title": exp.get("title", "")[:70], "path": exp.get("path", ""), "search_term": exp.get("search_term", "")},
            "position": {"x": cx - 500 + col * 200, "y": cy + 500 + row * 70},
        })
        parent = center_id
        search = exp.get("search_term", "").lower()
        for tname, tnid in tech_nodes_by_name.items():
            if tname in search or search in tname:
                parent = tnid
                break
        edges.append({"id": f"e-{parent}-{eid}", "source": parent, "target": eid})

    # -- Vulns: bottom center --
    vulns_list = data.get("vulns", [])[:10]
    for i, vuln in enumerate(vulns_list):
        node_id += 1
        vid = f"vuln-{node_id}"
        col, row = i % 3, i // 3
        nodes.append({
            "id": vid, "type": "vuln", "data": {"label": vuln[:80]},
            "position": {"x": cx - 200 + col * 200, "y": cy + 700 + row * 60},
        })
        edges.append({"id": f"e-{center_id}-{vid}", "source": center_id, "target": vid, "sourceHandle": "b"})

    # -- Errors: bottom row in red --
    errors = data.get("errors", [])[:8]
    for i, err in enumerate(errors):
        node_id += 1
        eid = f"err-{node_id}"
        nodes.append({
            "id": eid, "type": "error",
            "data": {"label": err[:100]},
            "position": {"x": cx - 200 + (i % 4) * 200, "y": cy + 800 + (i // 4) * 60},
        })
        edges.append({"id": f"e-{center_id}-{eid}", "source": center_id, "target": eid, "sourceHandle": "b"})

    # Include scan list in summary for the detail panel
    scan_details = []
    for s in data.get("scans", []):
        tid = s.get("task_id", "")
        task = tasks.get(tid, {})
        scan_details.append({
            "task_id": tid,
            "tool": s.get("tool", ""),
            "status": s.get("status", ""),
            "command": task.get("command", ""),
            "output_preview": task.get("output", "")[:500],
        })
    data["scan_details"] = scan_details

    return {"nodes": nodes, "edges": edges, "target": data["target"], "summary": data}


class AutoScanRequest(BaseModel):
    target: str
    project_id: Optional[int] = None


active_recon: dict[str, dict] = {}

DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


@router.post("/auto-scan")
async def auto_scan(req: AutoScanRequest):
    target = req.target.strip()
    if not target:
        return {"error": "Target is required"}

    domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    url_https = f"https://{domain}"
    url_http = f"http://{domain}"

    task_id = new_task_id()

    bins = {
        "nmap": shutil.which("nmap"),
        "whatweb": shutil.which("whatweb"),
        "whois": shutil.which("whois"),
        "wafw00f": shutil.which("wafw00f"),
        "sslscan": shutil.which("sslscan"),
        "gobuster": shutil.which("gobuster"),
        "dig": shutil.which("dig"),
        "fierce": shutil.which("fierce"),
        "dnsrecon": shutil.which("dnsrecon"),
        "theHarvester": shutil.which("theHarvester"),
    }

    tool_defs = []
    if bins["nmap"]:
        tool_defs.append(("nmap", "Port Scan", [bins["nmap"], "-sV", "-T4", "-F", domain]))
    if bins["whatweb"]:
        tool_defs.append(("whatweb", "Tech Detection", [bins["whatweb"], "-a", "3", "-v", url_https]))
    if bins["dig"]:
        tool_defs.append(("dig", "DNS Records", [bins["dig"], domain, "ANY", "+noall", "+answer"]))
    if bins["whois"]:
        tool_defs.append(("whois", "WHOIS Lookup", [bins["whois"], domain]))
    if bins["wafw00f"]:
        tool_defs.append(("wafw00f", "WAF Detection", [bins["wafw00f"], "-a", url_https]))
    if bins["sslscan"]:
        tool_defs.append(("sslscan", "SSL/TLS Scan", [bins["sslscan"], domain]))
    if bins["gobuster"] and os.path.exists(DNS_WORDLIST):
        tool_defs.append(("gobuster_dns", "Subdomain Brute", [bins["gobuster"], "dns", "--do", domain, "-w", DNS_WORDLIST, "-q", "-t", "20"]))
    if bins["fierce"]:
        tool_defs.append(("fierce", "DNS Brute (fierce)", [bins["fierce"], "--domain", domain]))
    if bins["dnsrecon"]:
        tool_defs.append(("dnsrecon", "DNS Recon", [bins["dnsrecon"], "-d", domain]))
    if bins["theHarvester"]:
        tool_defs.append(("theHarvester", "OSINT Harvester", [bins["theHarvester"], "-d", domain, "-b", "anubis,crtsh,dnsdumpster,hackertarget,rapiddns,sublist3r,threatminer", "-l", "200"]))
    if bins["gobuster"] and os.path.exists(DIR_WORDLIST):
        tool_defs.append(("gobuster_dir", "Directory Scan", [bins["gobuster"], "dir", "-u", url_https, "-w", DIR_WORDLIST, "-q", "--no-error", "-t", "20"]))

    total = len(tool_defs)

    timeline = []
    for tool_name, label, _ in tool_defs:
        timeline.append({"tool": tool_name, "label": label, "status": "pending", "task_id": None, "started_at": None, "finished_at": None})

    recon_state = {
        "task_id": task_id, "domain": domain, "status": "running",
        "timeline": timeline, "sub_task_ids": [], "total": total,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    active_recon[task_id] = recon_state

    async def _run():
        tasks[task_id] = {
            "status": "running", "tool_name": "auto_recon",
            "command": f"auto-recon: {domain} ({total} tools in parallel)",
            "output": "", "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

        def _append(text):
            tasks[task_id]["output"] += text

        _append(f"[*] Starting parallel auto-recon on {domain} with {total} tools\n")
        _append(f"[*] Tools: {', '.join(t[0] for t in tool_defs)}\n\n")

        async def _run_tool(idx, tool_name, label, cmd):
            sub_tid = new_task_id()
            recon_state["sub_task_ids"].append(sub_tid)
            recon_state["timeline"][idx]["task_id"] = sub_tid
            recon_state["timeline"][idx]["status"] = "running"
            recon_state["timeline"][idx]["started_at"] = datetime.now(timezone.utc).isoformat()
            _append(f"[STARTED] {tool_name}\n")
            try:
                output = await runner.run(sub_tid, cmd, tool_name=tool_name)
                status = tasks.get(sub_tid, {}).get("status", "completed")
                recon_state["timeline"][idx]["status"] = status
                recon_state["timeline"][idx]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _append(f"[DONE] {tool_name} ({status})\n")

                if req.project_id:
                    from database import async_session, Scan
                    async with async_session() as session:
                        scan = Scan(
                            project_id=req.project_id, tool_name=tool_name,
                            command=" ".join(cmd), status=status,
                            output=output, finished_at=datetime.now(timezone.utc),
                        )
                        session.add(scan)
                        await session.commit()
                return tool_name, status
            except Exception as e:
                recon_state["timeline"][idx]["status"] = "error"
                recon_state["timeline"][idx]["finished_at"] = datetime.now(timezone.utc).isoformat()
                _append(f"[ERROR] {tool_name}: {e}\n")
                return tool_name, "error"

        await asyncio.gather(
            *[_run_tool(i, name, label, cmd) for i, (name, label, cmd) in enumerate(tool_defs)],
            return_exceptions=True,
        )

        done = sum(1 for t in recon_state["timeline"] if t["status"] == "completed")
        errs = sum(1 for t in recon_state["timeline"] if t["status"] == "error")
        _append(f"\n[100%] Auto-Recon Complete: {done} succeeded, {errs} failed\n")
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
        recon_state["status"] = "completed"

        try:
            from notifications import add_notification
            add_notification(
                title="Auto-Recon completed",
                message=f"Recon of {domain}: {done}/{total} tools succeeded",
                severity="success" if errs == 0 else "warning",
                tool_name="auto_recon", task_id=task_id,
            )
        except Exception:
            pass

    asyncio.create_task(_run())

    return {
        "task_id": task_id, "target": target, "domain": domain,
        "tools": [t[0] for t in tool_defs], "total_tools": total, "status": "running",
    }


@router.get("/auto-scan/{task_id}")
async def auto_scan_status(task_id: str):
    state = active_recon.get(task_id)
    if not state:
        task = tasks.get(task_id)
        if task:
            return {"status": task.get("status", "unknown"), "timeline": [], "total": 0}
        return {"error": "Not found"}
    return {
        "status": state["status"], "domain": state["domain"],
        "timeline": state["timeline"], "total": state["total"],
        "started_at": state["started_at"],
    }


@router.delete("/auto-scan/{task_id}")
async def kill_auto_scan(task_id: str):
    state = active_recon.get(task_id)
    killed = 0
    if state:
        for sid in state.get("sub_task_ids", []):
            ok = await runner.kill(sid)
            if ok:
                killed += 1
        for t in state["timeline"]:
            if t["status"] == "running":
                t["status"] = "killed"
                t["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["status"] = "killed"
    await runner.kill(task_id)
    if task_id in tasks:
        tasks[task_id]["status"] = "killed"
        tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
    return {"killed": True, "sub_tasks_killed": killed}
