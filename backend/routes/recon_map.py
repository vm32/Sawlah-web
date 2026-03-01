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
        "server_info": {}, "scans": [],
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
                targets[target]["waf_status"] = _parse_wafw00f(output)

            if tool == "whois" and output:
                targets[target]["whois_info"] = _parse_whois(output)

            if tool == "sslscan" and output:
                targets[target]["ssl_info"] = _parse_sslscan(output)

            if tool == "whatweb" and output:
                for tech in _parse_whatweb_techs(output):
                    existing = [x.get("name", "") for x in targets[target]["technologies"]]
                    if tech["name"] not in existing:
                        targets[target]["technologies"].append(tech)

            if output:
                for v in _parse_vulns(output):
                    if v not in targets[target]["vulns"]:
                        targets[target]["vulns"].append(v)

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
    cx, cy = 500, 400

    center_id = f"target-{node_id}"
    nodes.append({
        "id": center_id, "type": "target",
        "data": {"label": data["target"], "scans": len(data["scans"])},
        "position": {"x": cx, "y": cy},
    })

    # WAF node - top left
    waf = data.get("waf_status")
    if waf:
        node_id += 1
        wid = f"waf-{node_id}"
        nodes.append({
            "id": wid, "type": "waf",
            "data": {"detected": waf.get("detected", False), "name": waf.get("waf_name", "Unknown"), "details": waf.get("details", "")},
            "position": {"x": cx - 300, "y": cy - 180},
        })
        edges.append({"id": f"e-{center_id}-{wid}", "source": center_id, "target": wid})

    # Whois node - top right
    whois = data.get("whois_info")
    if whois:
        node_id += 1
        whid = f"whois-{node_id}"
        nodes.append({
            "id": whid, "type": "whois",
            "data": whois,
            "position": {"x": cx + 300, "y": cy - 180},
        })
        edges.append({"id": f"e-{center_id}-{whid}", "source": center_id, "target": whid})

    # SSL node - top center
    ssl = data.get("ssl_info")
    if ssl and (ssl.get("cert_subject") or ssl.get("protocols")):
        node_id += 1
        slid = f"ssl-{node_id}"
        nodes.append({
            "id": slid, "type": "ssl",
            "data": ssl,
            "position": {"x": cx, "y": cy - 220},
        })
        edges.append({"id": f"e-{center_id}-{slid}", "source": center_id, "target": slid})

    # Ports
    for i, port in enumerate(data["ports"]):
        node_id += 1
        pid = f"port-{node_id}"
        angle = (i / max(len(data["ports"]), 1)) * 3.14 - 1.2
        x = cx + math.cos(angle) * 220
        y = cy + math.sin(angle) * 220
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
                "position": {"x": x + math.cos(angle) * 130, "y": y + math.sin(angle) * 130},
            })
            edges.append({"id": f"e-{pid}-{sid}", "source": pid, "target": sid})

    # Subdomains
    subs = data.get("subdomains", [])[:30]
    for i, sub in enumerate(subs):
        node_id += 1
        sid = f"sub-{node_id}"
        spread = min(len(subs), 30)
        angle = math.pi + (i / max(spread, 1)) * 1.8 - 0.9
        r = 300 + (i % 3) * 60
        nodes.append({
            "id": sid, "type": "subdomain", "data": {"label": sub},
            "position": {"x": cx + math.cos(angle) * r, "y": cy + math.sin(angle) * r},
        })
        edges.append({"id": f"e-{center_id}-{sid}", "source": center_id, "target": sid})

    # Directories
    directories = data.get("directories", [])[:25]
    for i, d in enumerate(directories):
        node_id += 1
        did = f"dir-{node_id}"
        col, row = i % 5, i // 5
        url = d.get("url") or d.get("path", "")
        nodes.append({
            "id": did, "type": "directory", "data": {"url": url, "status": d.get("status", 0)},
            "position": {"x": cx + 200 + col * 150, "y": cy + 280 + row * 60},
        })
        port80 = next((n for n in nodes if n.get("type") == "port" and n["data"].get("port") in (80, 443, 8080, 8443)), None)
        parent = port80["id"] if port80 else center_id
        edges.append({"id": f"e-{parent}-{did}", "source": parent, "target": did})

    # Technologies
    techs = data.get("technologies", [])[:12]
    for i, tech in enumerate(techs):
        node_id += 1
        tid = f"tech-{node_id}"
        col, row = i % 4, i // 4
        nodes.append({
            "id": tid, "type": "technology",
            "data": {"name": tech.get("name", ""), "version": tech.get("version", ""), "category": tech.get("category", "Technology")},
            "position": {"x": cx - 150 + col * 160, "y": cy - 350 - row * 70},
        })
        edges.append({"id": f"e-{center_id}-{tid}", "source": center_id, "target": tid})

    # Exploits
    exploits = data.get("exploits", [])[:20]
    tech_nodes_by_name = {n["data"]["name"].lower(): n["id"] for n in nodes if n["type"] == "technology"}
    for i, exp in enumerate(exploits):
        node_id += 1
        eid = f"exploit-{node_id}"
        col, row = i % 4, i // 4
        nodes.append({
            "id": eid, "type": "exploit",
            "data": {"title": exp.get("title", "")[:70], "path": exp.get("path", ""), "search_term": exp.get("search_term", "")},
            "position": {"x": cx - 400 + col * 180, "y": cy + 250 + row * 65},
        })
        parent = center_id
        search = exp.get("search_term", "").lower()
        for tname, tnid in tech_nodes_by_name.items():
            if tname in search or search in tname:
                parent = tnid
                break
        edges.append({"id": f"e-{parent}-{eid}", "source": parent, "target": eid})

    # Vulns
    for i, vuln in enumerate(data.get("vulns", [])[:15]):
        node_id += 1
        vid = f"vuln-{node_id}"
        nodes.append({
            "id": vid, "type": "vuln", "data": {"label": vuln[:80]},
            "position": {"x": cx - 300 + (i % 5) * 140, "y": cy + 500 + (i // 5) * 70},
        })
        edges.append({"id": f"e-{center_id}-{vid}", "source": center_id, "target": vid})

    return {"nodes": nodes, "edges": edges, "target": data["target"], "summary": data}


class AutoScanRequest(BaseModel):
    target: str
    project_id: Optional[int] = None


@router.post("/auto-scan")
async def auto_scan(req: AutoScanRequest):
    target = req.target.strip()
    if not target:
        return {"error": "Target is required"}

    domain = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    url = target if target.startswith(("http://", "https://")) else f"http://{target}"

    task_id = new_task_id()

    nmap_bin = shutil.which("nmap") or TOOL_PATHS.get("nmap", "")
    whatweb_bin = shutil.which("whatweb") or TOOL_PATHS.get("whatweb", "")
    whois_bin = shutil.which("whois") or TOOL_PATHS.get("whois", "")
    wafw00f_bin = shutil.which("wafw00f")
    sslscan_bin = shutil.which("sslscan")
    gobuster_bin = shutil.which("gobuster") or TOOL_PATHS.get("gobuster", "")

    tools_to_run = []
    if nmap_bin:
        tools_to_run.append(("nmap", [nmap_bin, "-sV", "-T4", "--top-ports", "1000", target]))
    if whatweb_bin:
        tools_to_run.append(("whatweb", [whatweb_bin, "-a", "3", "-v", url]))
    if whois_bin:
        tools_to_run.append(("whois", [whois_bin, domain]))
    if wafw00f_bin:
        tools_to_run.append(("wafw00f", [wafw00f_bin, "-a", url]))
    if sslscan_bin:
        tools_to_run.append(("sslscan", [sslscan_bin, target]))
    if gobuster_bin:
        dns_wl = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if os.path.exists(dns_wl):
            tools_to_run.append(("gobuster_dns", [gobuster_bin, "dns", "--do", domain, "-w", dns_wl, "-q", "-t", "20"]))

    total = len(tools_to_run)

    async def _run():
        tasks[task_id] = {
            "status": "running", "tool_name": "auto_recon",
            "command": f"auto-recon: {target} ({total} tools)",
            "output": "", "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
        }

        def _append(text):
            tasks[task_id]["output"] += text

        for i, (tool_name, cmd) in enumerate(tools_to_run):
            pct = int((i / total) * 100)
            _append(f"\n{'='*60}\n[{pct}%] Running: {tool_name}\n{'='*60}\n\n")
            try:
                sub_tid = new_task_id()
                output = await runner.run(sub_tid, cmd, tool_name=tool_name)
                _append(output)

                if req.project_id:
                    from database import async_session, Scan
                    async with async_session() as session:
                        scan = Scan(
                            project_id=req.project_id, tool_name=tool_name,
                            command=" ".join(cmd), status=tasks[sub_tid]["status"],
                            output=output, finished_at=datetime.now(timezone.utc),
                        )
                        session.add(scan)
                        await session.commit()
            except Exception as e:
                _append(f"[ERROR] {tool_name} failed: {e}\n")

        _append(f"\n{'='*60}\n[100%] Auto-Recon Complete\n{'='*60}\n")
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        try:
            from notifications import add_notification
            add_notification(
                title="Auto-Recon completed",
                message=f"Full recon of {target} finished ({total} tools)",
                severity="success", tool_name="auto_recon", task_id=task_id,
            )
        except Exception:
            pass

    asyncio.create_task(_run())

    return {
        "task_id": task_id,
        "target": target,
        "tools": [t[0] for t in tools_to_run],
        "total_tools": total,
        "status": "running",
    }
