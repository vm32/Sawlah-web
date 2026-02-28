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
        if params.get("try_nsr"):
            cmd.append("-e nsr")
        if params.get("exit_first"):
            cmd.append("-f")

        wait_time = params.get("wait_time", "").strip() if isinstance(params.get("wait_time"), str) else ""
        if wait_time:
            cmd.extend(["-W", wait_time])

        proxy = params.get("proxy", "").strip()
        if proxy:
            cmd.extend(["-o", proxy])

        custom_port = params.get("custom_port", "").strip() if isinstance(params.get("custom_port"), str) else ""
        if custom_port:
            cmd.extend(["-s", custom_port])

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
        if wordlist and not params.get("incremental"):
            cmd.append(f"--wordlist={wordlist}")
        fmt = params.get("format", "").strip()
        if fmt:
            cmd.append(f"--format={fmt}")
        if params.get("show"):
            cmd.append("--show")
        if params.get("incremental"):
            cmd.append("--incremental")

        fork = str(params.get("fork", "")).strip()
        if fork:
            cmd.append(f"--fork={fork}")

        session = params.get("session", "").strip() if isinstance(params.get("session"), str) else ""
        if session:
            cmd.append(f"--session={session}")

        if params.get("restore"):
            cmd.append("--restore")

        rules = params.get("rules", "").strip() if isinstance(params.get("rules"), str) else ""
        if rules:
            cmd.append(f"--rules={rules}")

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

        if params.get("hc_username"):
            cmd.append("--username")
        if params.get("optimized"):
            cmd.append("-O")

        status_timer = str(params.get("status_timer", "")).strip()
        if status_timer:
            cmd.extend(["--status", "--status-timer", status_timer])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(hashfile)
        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.append(wordlist)
        return cmd

    return []
