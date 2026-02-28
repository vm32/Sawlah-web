import re
import math
from fastapi import APIRouter
from tool_runner import tasks

router = APIRouter()


def _parse_nmap_services(output: str) -> list[dict]:
    services = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", line)
        if m:
            services.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "version": m.group(5).strip(),
            })
    return services


def _parse_subdomains(output: str) -> list[str]:
    subs = set()
    for line in output.splitlines():
        cleaned = line.strip()
        if re.match(r"^[\w.-]+\.\w{2,}$", cleaned):
            subs.add(cleaned)
        m = re.search(r"([\w.-]+\.\w{2,})", cleaned)
        if m and "." in m.group(1) and len(m.group(1)) > 4:
            subs.add(m.group(1))
    return sorted(subs)


def _parse_directories(output: str) -> list[dict]:
    dirs = []
    for line in output.splitlines():
        m = re.search(r"(https?://\S+)\s+.*?(\d{3})", line)
        if m:
            dirs.append({"url": m.group(1), "status": int(m.group(2))})
        m2 = re.search(r"\+\s+(https?://\S+)\s+\(Code:\s*(\d+)", line)
        if m2:
            dirs.append({"url": m2.group(1), "status": int(m2.group(2))})
    return dirs


def _parse_vulns(output: str) -> list[str]:
    vulns = []
    for line in output.splitlines():
        if re.search(r"VULNERABLE|CVE-\d{4}-\d+", line, re.I):
            vulns.append(line.strip())
    return vulns


def _merge_webrecon_sessions(targets: dict):
    """Merge web recon session results into the targets map."""
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
            targets[domain] = {
                "target": domain,
                "ports": [],
                "services": [],
                "subdomains": [],
                "directories": [],
                "technologies": [],
                "exploits": [],
                "vulns": [],
                "server_info": {},
                "scans": [],
            }

        t = targets[domain]
        t.setdefault("technologies", [])
        t.setdefault("exploits", [])
        t.setdefault("server_info", {})

        results = session.get("results", {})

        for sub in results.get("subdomains", []):
            fqdn = sub.get("subdomain", "")
            if fqdn and fqdn not in t["subdomains"]:
                t["subdomains"].append(fqdn)

        for d in results.get("directories", []):
            path = d.get("path", "")
            status = d.get("status", 0)
            if path:
                existing_paths = [x.get("url") or x.get("path", "") for x in t["directories"]]
                if path not in existing_paths:
                    t["directories"].append({"url": path, "status": status, "size": d.get("size", 0)})

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

        t["scans"].append({
            "task_id": sid, "tool": "webrecon",
            "status": session.get("status"),
            "started_at": session.get("started_at"),
        })


@router.get("/targets")
async def list_targets():
    """Extract unique targets from all scan history."""
    targets = {}
    for tid, t in tasks.items():
        cmd = t.get("command", "")
        tool = t.get("tool_name", "")
        output = t.get("output", "")

        ip_matches = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", cmd)
        domain_matches = re.findall(r"(?:https?://)?([a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,})", cmd)
        all_targets = set(ip_matches + domain_matches)

        for target in all_targets:
            if target.startswith("usr") or target.startswith("share"):
                continue
            if target not in targets:
                targets[target] = {
                    "target": target,
                    "ports": [],
                    "services": [],
                    "subdomains": [],
                    "directories": [],
                    "technologies": [],
                    "exploits": [],
                    "vulns": [],
                    "server_info": {},
                    "scans": [],
                }

            targets[target]["scans"].append({
                "task_id": tid,
                "tool": tool,
                "status": t.get("status"),
                "started_at": t.get("started_at"),
            })

            if tool == "nmap" and output:
                for svc in _parse_nmap_services(output):
                    existing_ports = [p["port"] for p in targets[target]["ports"]]
                    if svc["port"] not in existing_ports:
                        targets[target]["ports"].append(svc)
                        targets[target]["services"].append(svc)

            if tool in ("amass", "gobuster_dns", "dnsenum", "ffuf") and output:
                for sub in _parse_subdomains(output):
                    if sub not in targets[target]["subdomains"]:
                        targets[target]["subdomains"].append(sub)

            if tool in ("gobuster_dir", "ffuf", "dirb", "feroxbuster") and output:
                for d in _parse_directories(output):
                    targets[target]["directories"].append(d)

            if output:
                for v in _parse_vulns(output):
                    if v not in targets[target]["vulns"]:
                        targets[target]["vulns"].append(v)

    _merge_webrecon_sessions(targets)

    return list(targets.values())


@router.get("/targets/{target}")
async def get_target_map(target: str):
    """Build graph data for a specific target."""
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

    # Ports — ring at radius 200, top-right
    for i, port in enumerate(data["ports"]):
        node_id += 1
        pid = f"port-{node_id}"
        angle = (i / max(len(data["ports"]), 1)) * 3.14 - 1.2
        x = cx + math.cos(angle) * 220
        y = cy + math.sin(angle) * 220
        nodes.append({
            "id": pid, "type": "port",
            "data": {
                "port": port["port"], "proto": port["proto"],
                "state": port["state"], "service": port["service"],
                "version": port.get("version", ""),
            },
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

    # Subdomains — left side fan
    subs = data.get("subdomains", [])[:30]
    for i, sub in enumerate(subs):
        node_id += 1
        sid = f"sub-{node_id}"
        spread = min(len(subs), 30)
        angle = math.pi + (i / max(spread, 1)) * 1.8 - 0.9
        r = 300 + (i % 3) * 60
        x = cx + math.cos(angle) * r
        y = cy + math.sin(angle) * r
        nodes.append({
            "id": sid, "type": "subdomain",
            "data": {"label": sub},
            "position": {"x": x, "y": y},
        })
        edges.append({"id": f"e-{center_id}-{sid}", "source": center_id, "target": sid})

    # Directories — bottom-right cluster
    directories = data.get("directories", [])[:25]
    for i, d in enumerate(directories):
        node_id += 1
        did = f"dir-{node_id}"
        col = i % 5
        row = i // 5
        x = cx + 200 + col * 150
        y = cy + 280 + row * 60
        url = d.get("url") or d.get("path", "")
        status = d.get("status", 0)
        nodes.append({
            "id": did, "type": "directory",
            "data": {"url": url, "status": status},
            "position": {"x": x, "y": y},
        })
        port80 = next((n for n in nodes if n.get("type") == "port" and n["data"].get("port") in (80, 443, 8080, 8443)), None)
        parent = port80["id"] if port80 else center_id
        edges.append({"id": f"e-{parent}-{did}", "source": parent, "target": did})

    # Technologies — top cluster
    techs = data.get("technologies", [])[:12]
    for i, tech in enumerate(techs):
        node_id += 1
        tid = f"tech-{node_id}"
        col = i % 4
        row = i // 4
        x = cx - 150 + col * 160
        y = cy - 250 - row * 70
        nodes.append({
            "id": tid, "type": "technology",
            "data": {
                "name": tech.get("name", ""),
                "version": tech.get("version", ""),
                "category": tech.get("category", "Technology"),
            },
            "position": {"x": x, "y": y},
        })
        edges.append({"id": f"e-{center_id}-{tid}", "source": center_id, "target": tid})

    # Exploits — bottom-left danger zone, linked to their technology
    exploits = data.get("exploits", [])[:20]
    tech_nodes_by_name = {}
    for n in nodes:
        if n["type"] == "technology":
            tech_nodes_by_name[n["data"]["name"].lower()] = n["id"]

    for i, exp in enumerate(exploits):
        node_id += 1
        eid = f"exploit-{node_id}"
        col = i % 4
        row = i // 4
        x = cx - 400 + col * 180
        y = cy + 250 + row * 65
        nodes.append({
            "id": eid, "type": "exploit",
            "data": {
                "title": exp.get("title", "")[:70],
                "path": exp.get("path", ""),
                "search_term": exp.get("search_term", ""),
            },
            "position": {"x": x, "y": y},
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
            "id": vid, "type": "vuln",
            "data": {"label": vuln[:80]},
            "position": {"x": cx - 300 + (i % 5) * 140, "y": cy + 500 + (i // 5) * 70},
        })
        edges.append({"id": f"e-{center_id}-{vid}", "source": center_id, "target": vid})

    return {"nodes": nodes, "edges": edges, "target": data["target"], "summary": data}
