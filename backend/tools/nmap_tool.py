from config import TOOL_PATHS


def build_nmap_command(tool_name: str, params: dict) -> list[str]:
    cmd = [TOOL_PATHS["nmap"]]
    target = params.get("target", "").strip()
    if not target:
        return []

    scan_type = params.get("scan_type", "quick")
    scan_map = {
        "quick": ["-T4", "-F"],
        "full_tcp": ["-p-", "-T4"],
        "syn": ["-sS", "-T4"],
        "udp": ["-sU", "-T4"],
        "service": ["-sV", "-T4"],
        "os": ["-O", "-T4"],
        "aggressive": ["-A", "-T4"],
        "vuln": ["--script", "vuln", "-sV"],
        "stealth": ["-sS", "-T2", "-f"],
    }
    cmd.extend(scan_map.get(scan_type, ["-T4", "-F"]))

    ports = params.get("ports", "")
    if ports == "all":
        cmd.extend(["-p-"])
    elif ports == "top100":
        cmd.extend(["--top-ports", "100"])
    elif ports == "top1000":
        cmd.extend(["--top-ports", "1000"])
    elif ports:
        cmd.extend(["-p", ports])

    timing = params.get("timing", "")
    if timing and timing in ("T0", "T1", "T2", "T3", "T4", "T5"):
        cmd.append(f"-{timing}")

    scripts = params.get("scripts", "")
    if scripts:
        cmd.extend(["--script", scripts])

    if params.get("version_detect"):
        cmd.append("-sV")

    if params.get("os_detect"):
        cmd.append("-O")

    if params.get("verbose"):
        cmd.append("-v")

    extra = params.get("extra_flags", "").strip()
    if extra:
        cmd.extend(extra.split())

    cmd.append(target)
    return cmd


def parse_nmap_output(raw: str) -> list[dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                findings.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2] if len(parts) > 2 else "",
                    "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                })
    return findings
