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
        if params.get("asn_lookup"):
            cmd.append("-asn")
        cmd.extend(["-d", target])

        timeout = params.get("timeout", "").strip()
        if timeout:
            cmd.extend(["-timeout", timeout])

        max_dns = params.get("max_dns", "").strip()
        if max_dns:
            cmd.extend(["-max-dns-queries", max_dns])

        resolvers = params.get("resolvers", "").strip()
        if resolvers:
            cmd.extend(["-rf", resolvers])

        if params.get("ipv4"):
            cmd.append("-ip")
        if params.get("active"):
            cmd.append("-active")
        if params.get("include_unresolvable"):
            cmd.append("-include-unresolvable")

        src = params.get("sources", "").strip()
        if src:
            cmd.extend(["-src", src])

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
        if params.get("show_ips"):
            cmd.append("-i")
        if params.get("show_cname"):
            cmd.append("--show-cname")
        if params.get("wildcard"):
            cmd.append("--wildcard")
        timeout = params.get("timeout", "").strip()
        if timeout:
            cmd.extend(["--timeout", timeout])
        resolver = params.get("resolver", "").strip()
        if resolver:
            cmd.extend(["-r", resolver])

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
        if params.get("noreverse"):
            cmd.append("--noreverse")
        if params.get("private"):
            cmd.append("-p")
        pages = params.get("pages", "").strip()
        if pages:
            cmd.extend(["-p", pages])
        subfile = params.get("subfile", "").strip()
        if subfile:
            cmd.extend(["-f", subfile])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    return []
