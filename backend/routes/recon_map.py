import re
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
                    "vulns": [],
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

            if tool in ("amass", "gobuster_dns", "dnsenum") and output:
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

    center_id = f"target-{node_id}"
    nodes.append({
        "id": center_id, "type": "target",
        "data": {"label": data["target"], "scans": len(data["scans"])},
        "position": {"x": 400, "y": 300},
    })

    for i, port in enumerate(data["ports"]):
        node_id += 1
        pid = f"port-{node_id}"
        angle = (i / max(len(data["ports"]), 1)) * 6.28
        import math
        x = 400 + math.cos(angle) * 200
        y = 300 + math.sin(angle) * 200
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
                "position": {"x": x + math.cos(angle) * 120, "y": y + math.sin(angle) * 120},
            })
            edges.append({"id": f"e-{pid}-{sid}", "source": pid, "target": sid})

    for i, sub in enumerate(data["subdomains"][:20]):
        node_id += 1
        sid = f"sub-{node_id}"
        angle = (i / max(len(data["subdomains"]), 1)) * 6.28 + 0.5
        import math
        x = 400 + math.cos(angle) * 350
        y = 300 + math.sin(angle) * 350
        nodes.append({
            "id": sid, "type": "subdomain",
            "data": {"label": sub},
            "position": {"x": x, "y": y},
        })
        edges.append({"id": f"e-{center_id}-{sid}", "source": center_id, "target": sid})

    for i, vuln in enumerate(data["vulns"][:15]):
        node_id += 1
        vid = f"vuln-{node_id}"
        nodes.append({
            "id": vid, "type": "vuln",
            "data": {"label": vuln[:80]},
            "position": {"x": 100 + (i % 5) * 160, "y": 550 + (i // 5) * 80},
        })
        edges.append({"id": f"e-{center_id}-{vid}", "source": center_id, "target": vid})

    for i, d in enumerate(data["directories"][:15]):
        node_id += 1
        did = f"dir-{node_id}"
        nodes.append({
            "id": did, "type": "directory",
            "data": {"url": d["url"], "status": d["status"]},
            "position": {"x": 700 + (i % 4) * 140, "y": 550 + (i // 4) * 70},
        })
        port80 = next((n for n in nodes if n.get("type") == "port" and n["data"].get("port") in (80, 443, 8080, 8443)), None)
        parent = port80["id"] if port80 else center_id
        edges.append({"id": f"e-{parent}-{did}", "source": parent, "target": did})

    return {"nodes": nodes, "edges": edges, "target": data["target"], "summary": data}
