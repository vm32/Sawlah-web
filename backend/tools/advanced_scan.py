import shutil


def build_advanced_scan_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()

    if tool_name == "nuclei":
        if not target:
            return []
        binary = shutil.which("nuclei")
        if not binary:
            return []
        cmd = [binary, "-u", target]

        templates = params.get("templates", "").strip()
        if templates:
            cmd.extend(["-t", templates])

        severity = params.get("severity", "").strip()
        if severity:
            cmd.extend(["-severity", severity])

        tags = params.get("tags", "").strip()
        if tags:
            cmd.extend(["-tags", tags])

        if params.get("new_templates"):
            cmd.append("-nt")
        if params.get("automatic_scan"):
            cmd.append("-as")

        rate = params.get("rate_limit", "").strip()
        if rate:
            cmd.extend(["-rl", rate])

        concurrency = params.get("concurrency", "").strip()
        if concurrency:
            cmd.extend(["-c", concurrency])

        if params.get("json_output"):
            cmd.append("-jsonl")

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "wafw00f":
        if not target:
            return []
        binary = shutil.which("wafw00f")
        if not binary:
            return []
        cmd = [binary, target]
        if params.get("all_waf"):
            cmd.append("-a")
        if params.get("verbose"):
            cmd.append("-v")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "feroxbuster":
        if not target:
            return []
        binary = shutil.which("feroxbuster")
        if not binary:
            return []
        cmd = [binary, "-u", target]

        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.extend(["-w", wordlist])
        else:
            cmd.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])

        threads = params.get("threads", "").strip()
        if threads:
            cmd.extend(["-t", threads])

        extensions = params.get("extensions", "").strip()
        if extensions:
            cmd.extend(["-x", extensions])

        status_codes = params.get("status_codes", "").strip()
        if status_codes:
            cmd.extend(["-s", status_codes])

        depth = params.get("depth", "").strip()
        if depth:
            cmd.extend(["-d", depth])

        if params.get("no_recursion"):
            cmd.append("-n")
        if params.get("quiet"):
            cmd.append("-q")

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "wpscan":
        if not target:
            return []
        binary = shutil.which("wpscan")
        if not binary:
            return []
        cmd = [binary, "--url", target]

        if params.get("enumerate"):
            cmd.extend(["-e", params["enumerate"]])

        if params.get("aggressive"):
            cmd.extend(["--plugins-detection", "aggressive"])

        api_token = params.get("api_token", "").strip()
        if api_token:
            cmd.extend(["--api-token", api_token])

        if params.get("stealthy"):
            cmd.append("--stealthy")

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())

        cmd.append("--no-banner")
        return cmd

    return []
