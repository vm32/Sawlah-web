import shutil

from config import TOOL_PATHS


def build_subdomain_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "gobuster_dns":
        binary = shutil.which("gobuster") or TOOL_PATHS.get("gobuster", "")
        if not binary:
            return []
        cmd = [binary, "dns"]
        cmd.extend(["--do", target])
        wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        cmd.extend(["-w", wordlist])
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        if params.get("show_cname"):
            cmd.append("-c")
        if params.get("wildcard"):
            cmd.append("--wc")
        cmd.append("-q")
        timeout = params.get("timeout", "").strip()
        if timeout:
            cmd.extend(["--to", timeout])
        resolver = params.get("resolver", "").strip()
        if resolver:
            cmd.extend(["--resolver", resolver])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "dnsenum":
        binary = shutil.which("dnsenum") or TOOL_PATHS.get("dnsenum", "")
        if not binary:
            return []
        cmd = [binary]
        if params.get("threads"):
            cmd.extend(["--threads", str(params["threads"])])
        if params.get("enum_subdomains"):
            cmd.append("--enum")
        if params.get("noreverse"):
            cmd.append("--noreverse")
        subfile = params.get("subfile", "").strip()
        if subfile:
            cmd.extend(["-f", subfile])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    return []
