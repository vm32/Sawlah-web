from config import TOOL_PATHS


def build_password_command(tool_name: str, params: dict) -> list[str]:
    if tool_name == "hydra":
        target = params.get("target", "").strip()
        if not target:
            return []
        service = params.get("service", "ssh").strip()
        cmd = [TOOL_PATHS["hydra"]]

        username = params.get("username", "").strip()
        userlist = params.get("userlist", "").strip()
        password = params.get("password", "").strip()
        passlist = params.get("passlist", "").strip()

        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])

        if password:
            cmd.extend(["-p", password])
        elif passlist:
            cmd.extend(["-P", passlist])

        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        if params.get("verbose"):
            cmd.append("-V")
        if params.get("force"):
            cmd.append("-f")

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())

        cmd.extend([target, service])
        return cmd

    elif tool_name == "john":
        hashfile = params.get("hashfile", "").strip()
        if not hashfile:
            return []
        cmd = [TOOL_PATHS["john"]]
        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.extend(["--wordlist=" + wordlist])
        fmt = params.get("format", "").strip()
        if fmt:
            cmd.extend(["--format=" + fmt])
        if params.get("show"):
            cmd.append("--show")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(hashfile)
        return cmd

    elif tool_name == "hashcat":
        hashfile = params.get("hashfile", "").strip()
        if not hashfile:
            return []
        cmd = [TOOL_PATHS["hashcat"]]
        mode = params.get("mode", "").strip()
        if mode:
            cmd.extend(["-m", mode])
        attack = params.get("attack_mode", "0").strip()
        cmd.extend(["-a", attack])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(hashfile)
        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.append(wordlist)
        return cmd

    return []
