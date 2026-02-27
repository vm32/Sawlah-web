from config import TOOL_PATHS


def build_subdomain_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "amass":
        cmd = [TOOL_PATHS["amass"], "enum"]
        if params.get("passive"):
            cmd.append("-passive")
        if params.get("brute"):
            cmd.append("-brute")
        cmd.extend(["-d", target])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "gobuster_dns":
        cmd = [TOOL_PATHS["gobuster"], "dns"]
        cmd.extend(["-d", target])
        wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        cmd.extend(["-w", wordlist])
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "dnsenum":
        cmd = [TOOL_PATHS["dnsenum"]]
        if params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])
        if params.get("enum_subdomains"):
            cmd.append("--enum")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    return []
