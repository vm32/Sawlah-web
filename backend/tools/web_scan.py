from config import TOOL_PATHS


def build_webscan_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "nikto":
        is_full_uri = "://" in target
        cmd = [TOOL_PATHS["nikto"], "-h", target, "-nointeractive"]
        if params.get("ssl") and not target.startswith("https://"):
            cmd.append("-ssl")
        if params.get("port") and not is_full_uri:
            cmd.extend(["-p", str(params["port"])])
        if params.get("tuning"):
            cmd.extend(["-Tuning", params["tuning"]])
        if params.get("mutate"):
            cmd.extend(["-mutate", str(params["mutate"])])
        if params.get("cgidirs"):
            cmd.extend(["-Cgidirs", params["cgidirs"]])
        if params.get("plugins"):
            cmd.extend(["-Plugins", params["plugins"]])
        if params.get("evasion"):
            cmd.extend(["-evasion", str(params["evasion"])])
        if params.get("timeout"):
            cmd.extend(["-timeout", str(params["timeout"])])
        if params.get("maxtime"):
            cmd.extend(["-maxtime", str(params["maxtime"])])
        if params.get("useragent"):
            cmd.extend(["-useragent", params["useragent"]])
        if params.get("display"):
            cmd.extend(["-Display", params["display"]])
        if params.get("followredirects"):
            cmd.append("-followredirects")
        if params.get("no404"):
            cmd.append("-no404")

        output_file = params.get("output_file", "")
        if output_file:
            cmd.extend(["-o", output_file, "-Format", "htm"])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "dirb":
        cmd = [TOOL_PATHS["dirb"], target]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.append(wordlist)
        if params.get("extensions"):
            cmd.extend(["-X", params["extensions"]])
        if params.get("user_agent"):
            cmd.extend(["-a", params["user_agent"]])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "gobuster_dir":
        cmd = [TOOL_PATHS["gobuster"], "dir"]
        cmd.extend(["-u", target])
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.extend(["-w", wordlist])
        if params.get("extensions"):
            cmd.extend(["-x", params["extensions"]])
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        if params.get("status_codes"):
            cmd.extend(["-s", params["status_codes"]])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "ffuf":
        cmd = [TOOL_PATHS["ffuf"]]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        cmd.extend(["-u", url, "-w", wordlist])
        if params.get("extensions"):
            cmd.extend(["-e", params["extensions"]])
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        if params.get("mc"):
            cmd.extend(["-mc", params["mc"]])
        if params.get("fc"):
            cmd.extend(["-fc", params["fc"]])
        if params.get("fs"):
            cmd.extend(["-fs", params["fs"]])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "whatweb":
        cmd = [TOOL_PATHS["whatweb"]]
        if params.get("aggression"):
            cmd.extend(["-a", str(params["aggression"])])
        if params.get("verbose"):
            cmd.append("-v")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    elif tool_name == "wfuzz":
        cmd = [TOOL_PATHS["wfuzz"]]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd.extend(["-w", wordlist])
        if params.get("hc"):
            cmd.extend(["--hc", params["hc"]])
        if params.get("hl"):
            cmd.extend(["--hl", params["hl"]])
        if params.get("hw"):
            cmd.extend(["--hw", params["hw"]])
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(url)
        return cmd

    return []
