import shutil

from config import TOOL_PATHS


def build_recon_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "whois":
        binary = shutil.which("whois") or TOOL_PATHS.get("whois", "")
        if not binary:
            return []
        cmd = [binary]
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    elif tool_name == "dig":
        binary = shutil.which("dig") or TOOL_PATHS.get("dig", "")
        if not binary:
            return []
        cmd = [binary]
        record_type = params.get("record_type", "A").upper()
        cmd.append(target)
        cmd.append(record_type)
        if params.get("short"):
            cmd.append("+short")
        if params.get("trace"):
            cmd.append("+trace")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "dnsrecon":
        binary = shutil.which("dnsrecon")
        if not binary:
            return []
        cmd = [binary, "-d", target]
        recon_type = params.get("type", "").strip()
        if recon_type:
            cmd.extend(["-t", recon_type])
        if params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "theHarvester":
        binary = shutil.which("theHarvester")
        if not binary:
            return []
        source = params.get("source", "all").strip() or "all"
        cmd = [binary, "-d", target, "-b", source]
        if params.get("limit"):
            cmd.extend(["-l", str(params["limit"])])
        if params.get("start"):
            cmd.extend(["-S", str(params["start"])])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "fierce":
        binary = shutil.which("fierce")
        if not binary:
            return []
        cmd = [binary, "--domain", target]
        if params.get("dns_servers"):
            cmd.extend(["--dns-servers", params["dns_servers"]])
        if params.get("subdomain_file"):
            cmd.extend(["--subdomain-file", params["subdomain_file"]])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "sslscan":
        binary = shutil.which("sslscan")
        if not binary:
            return []
        cmd = [binary]
        if params.get("no_color"):
            cmd.append("--no-colour")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    return []
