import asyncio
import shutil
import re
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from tool_runner import runner, new_task_id, tasks
from config import TOOL_PATHS

router = APIRouter()

recon_sessions: dict[str, dict] = {}

SUBDOMAIN_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DIR_WORDLIST_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"


class WebReconRequest(BaseModel):
    target: str
    mode: str = "standard"
    threads: int = 30
    extensions: str = ""
    project_id: Optional[int] = None


def _extract_domain(target: str) -> str:
    """Extract bare domain from URL or hostname."""
    t = target.strip()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0].split(":")[0]
    return t


def _build_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = f"http://{t}"
    return t.rstrip("/")


@router.post("/run")
async def run_webrecon(req: WebReconRequest):
    target = req.target.strip()
    if not target:
        return {"error": "Target is required"}

    domain = _extract_domain(target)
    url = _build_target_url(target)
    session_id = new_task_id()
    threads = str(min(max(req.threads, 1), 100))

    scan_tasks = {}

    ffuf_bin = shutil.which("ffuf") or TOOL_PATHS.get("ffuf", "")
    gobuster_bin = shutil.which("gobuster") or TOOL_PATHS.get("gobuster", "")
    whatweb_bin = shutil.which("whatweb") or TOOL_PATHS.get("whatweb", "")
    searchsploit_bin = shutil.which("searchsploit") or TOOL_PATHS.get("searchsploit", "")

    # 1. FFUF subdomain fuzzing
    sub_tid = new_task_id()
    sub_cmd = [
        ffuf_bin, "-u", f"http://FUZZ.{domain}",
        "-w", SUBDOMAIN_WORDLIST,
        "-t", threads,
        "-mc", "200,201,202,301,302,307,401,403",
        "-ac",
    ]
    scan_tasks["subdomain_fuzz"] = {
        "task_id": sub_tid, "tool": "ffuf", "label": "Subdomain Fuzzing (FFUF)",
        "command": sub_cmd, "status": "pending",
    }

    # 2. Gobuster directory brute-force
    dir_tid = new_task_id()
    wordlist = DIR_WORDLIST_MEDIUM if req.mode == "deep" else DIR_WORDLIST
    dir_cmd = [
        gobuster_bin, "dir",
        "-u", url,
        "-w", wordlist,
        "-t", threads,
        "-q", "--no-error",
        "-s", "200,201,202,204,301,302,307,401,403",
    ]
    if req.extensions:
        dir_cmd.extend(["-x", req.extensions])
    scan_tasks["dir_bruteforce"] = {
        "task_id": dir_tid, "tool": "gobuster_dir", "label": "Directory Brute-force (Gobuster)",
        "command": dir_cmd, "status": "pending",
    }

    # 3. WhatWeb technology fingerprinting
    tech_tid = new_task_id()
    tech_cmd = [whatweb_bin, "-a", "3", "-v", url]
    scan_tasks["tech_detect"] = {
        "task_id": tech_tid, "tool": "whatweb", "label": "Technology Detection (WhatWeb)",
        "command": tech_cmd, "status": "pending",
    }

    recon_sessions[session_id] = {
        "status": "running",
        "target": target,
        "domain": domain,
        "url": url,
        "mode": req.mode,
        "tasks": scan_tasks,
        "results": {
            "subdomains": [],
            "directories": [],
            "technologies": [],
            "exploits": [],
            "server_info": {},
        },
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    }

    async def _execute():
        session = recon_sessions[session_id]

        # Mark all tasks running immediately so UI shows parallel start
        for info in session["tasks"].values():
            info["status"] = "running"

        async def _run_task(key: str):
            info = session["tasks"][key]
            try:
                output = await runner.run(info["task_id"], info["command"], tool_name=info["tool"])
                info["status"] = tasks[info["task_id"]].get("status", "completed")
                # Parse results as soon as each task finishes (while others still run)
                if key == "subdomain_fuzz":
                    session["results"]["subdomains"] = _parse_ffuf_subdomains(output, domain)
                elif key == "dir_bruteforce":
                    session["results"]["directories"] = _parse_gobuster_dirs(output)
                elif key == "tech_detect":
                    techs, server_info = _parse_whatweb(output)
                    session["results"]["technologies"] = techs
                    session["results"]["server_info"] = server_info
                return key, output
            except Exception as e:
                info["status"] = "error"
                return key, str(e)

        # All three run truly in parallel — each is an independent subprocess
        await asyncio.gather(
            _run_task("subdomain_fuzz"),
            _run_task("dir_bruteforce"),
            _run_task("tech_detect"),
            return_exceptions=True,
        )

        # 4. Run searchsploit on discovered technologies (after all parallel scans done)
        techs = session["results"]["technologies"]
        if techs and searchsploit_bin:
            exploit_tid = new_task_id()
            search_terms = []
            for t in techs:
                name = t.get("name", "")
                version = t.get("version", "")
                if version and name:
                    search_terms.append(f"{name} {version}")
                elif name and name.lower() not in ("html", "css", "script", "frame", "meta", "email"):
                    search_terms.append(name)

            unique_terms = list(dict.fromkeys(search_terms))[:8]

            session["tasks"]["exploit_search"] = {
                "task_id": exploit_tid, "tool": "searchsploit",
                "label": "Exploit Search (SearchSploit)", "status": "running",
                "command": [], "search_terms": unique_terms,
            }

            all_exploits = []
            for term in unique_terms:
                tid = new_task_id()
                cmd = [searchsploit_bin, "--color", term]
                try:
                    output = await runner.run(tid, cmd, tool_name="searchsploit")
                    exploits = _parse_searchsploit(output, term)
                    all_exploits.extend(exploits)
                except Exception:
                    pass

            session["results"]["exploits"] = all_exploits
            session["tasks"]["exploit_search"]["status"] = "completed"

        session["status"] = "completed"
        session["finished_at"] = datetime.now(timezone.utc).isoformat()

    asyncio.create_task(_execute())

    return {
        "session_id": session_id,
        "target": target,
        "domain": domain,
        "tasks": {k: {"task_id": v["task_id"], "label": v["label"]} for k, v in scan_tasks.items()},
        "status": "running",
    }


@router.get("/status/{session_id}")
async def recon_status(session_id: str):
    session = recon_sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    return {
        "status": session["status"],
        "target": session["target"],
        "domain": session["domain"],
        "mode": session["mode"],
        "tasks": {
            k: {"task_id": v["task_id"], "label": v["label"], "status": v["status"]}
            for k, v in session["tasks"].items()
        },
        "results": session["results"],
        "started_at": session["started_at"],
        "finished_at": session["finished_at"],
    }


@router.get("/sessions")
async def list_sessions():
    return [
        {
            "session_id": sid,
            "target": s["target"],
            "status": s["status"],
            "started_at": s["started_at"],
            "finished_at": s["finished_at"],
            "subdomain_count": len(s["results"].get("subdomains", [])),
            "dir_count": len(s["results"].get("directories", [])),
            "exploit_count": len(s["results"].get("exploits", [])),
            "tech_count": len(s["results"].get("technologies", [])),
        }
        for sid, s in sorted(
            recon_sessions.items(),
            key=lambda x: x[1].get("started_at", ""),
            reverse=True,
        )
    ]


@router.delete("/kill/{session_id}")
async def kill_recon(session_id: str):
    session = recon_sessions.get(session_id)
    if not session:
        return {"error": "Session not found"}
    for info in session["tasks"].values():
        tid = info.get("task_id")
        if tid:
            await runner.kill(tid)
    session["status"] = "killed"
    return {"killed": True}


def _parse_ffuf_subdomains(output: str, domain: str) -> list[dict]:
    subs = []
    seen = set()
    for line in output.splitlines():
        m = re.search(r"(\S+)\s+\[Status:\s*(\d+)", line)
        if m:
            name = m.group(1).strip()
            status = int(m.group(2))
            fqdn = f"{name}.{domain}" if "." not in name else name
            if fqdn not in seen:
                seen.add(fqdn)
                subs.append({"subdomain": fqdn, "status": status, "raw": line.strip()})
        else:
            m2 = re.match(r"^([\w-]+)\s+\d+", line.strip())
            if m2:
                name = m2.group(1)
                fqdn = f"{name}.{domain}"
                if fqdn not in seen:
                    seen.add(fqdn)
                    subs.append({"subdomain": fqdn, "status": 0, "raw": line.strip()})
    return subs


def _parse_gobuster_dirs(output: str) -> list[dict]:
    dirs = []
    seen = set()
    for line in output.splitlines():
        m = re.search(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
        if not m:
            m = re.search(r"(/\S+)\s+\[Status=(\d+)\]", line)
        if not m:
            m = re.search(r"(https?://\S+)\s+\(Status:\s*(\d+)\)", line)
        if not m:
            m = re.search(r"(/[\w./-]+)\s+(\d{3})", line)
        if m:
            path = m.group(1)
            status = int(m.group(2))
            if path not in seen:
                seen.add(path)
                size_m = re.search(r"\[Size=(\d+)\]", line)
                size = int(size_m.group(1)) if size_m else 0
                dirs.append({"path": path, "status": status, "size": size, "raw": line.strip()})
    return dirs


def _parse_whatweb(output: str) -> tuple[list[dict], dict]:
    techs = []
    server_info = {}
    seen = set()

    for line in output.splitlines():
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()

        for m in re.finditer(r"(\w[\w./ -]+?)\[([^\]]+)\]", clean):
            name = m.group(1).strip()
            detail = m.group(2).strip()
            if name.lower() in seen:
                continue
            seen.add(name.lower())

            version = ""
            vm = re.search(r"([\d]+\.[\d.]+)", detail)
            if vm:
                version = vm.group(1)

            if name.lower() in ("ip", "country"):
                server_info[name.lower()] = detail
            elif name.lower() == "httpserver":
                server_info["server"] = detail
                techs.append({"name": detail.split("/")[0], "version": version, "detail": detail, "category": "Server"})
            else:
                category = "Technology"
                if re.search(r"PHP|Python|Ruby|Java|Node|ASP|Perl", name, re.I):
                    category = "Language"
                elif re.search(r"Apache|Nginx|IIS|LiteSpeed|Caddy", name, re.I):
                    category = "Server"
                elif re.search(r"WordPress|Joomla|Drupal|Django|Laravel|Rails", name, re.I):
                    category = "Framework"
                elif re.search(r"jQuery|Bootstrap|React|Angular|Vue", name, re.I):
                    category = "Frontend"
                elif re.search(r"cookie|session|header", name, re.I):
                    category = "Security"
                techs.append({"name": name, "version": version, "detail": detail, "category": category})

        sm = re.search(r"HTTPServer\[([^\]]+)\]", clean)
        if sm and "server" not in server_info:
            server_info["server"] = sm.group(1)

        cm = re.search(r"Country\[([^\]]+)\]", clean)
        if cm:
            server_info["country"] = cm.group(1)

        ipm = re.search(r"IP\[([^\]]+)\]", clean)
        if ipm:
            server_info["ip"] = ipm.group(1)

    return techs, server_info


def _parse_searchsploit(output: str, search_term: str) -> list[dict]:
    exploits = []
    for line in output.splitlines():
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        if not clean or clean.startswith("-") or clean.startswith("Exploit Title"):
            continue
        m = re.match(r"(.+?)\s*\|\s*(\S+)", clean)
        if m:
            title = m.group(1).strip()
            path = m.group(2).strip()
            if path.startswith(("exploits/", "shellcodes/")):
                exploits.append({
                    "title": title, "path": path,
                    "search_term": search_term,
                    "type": "exploit" if "exploits/" in path else "shellcode",
                })
    return exploits
