import shutil
from config import TOOL_PATHS


def build_hash_command(tool_name: str, params: dict) -> list[str]:
    if tool_name == "hashid":
        hash_value = params.get("hash", "").strip()
        if not hash_value:
            return []
        binary = shutil.which("hashid") or TOOL_PATHS.get("hashid", "hashid")
        cmd = [binary]
        if params.get("extended"):
            cmd.append("-e")
        if params.get("mode"):
            cmd.append("-m")
        cmd.append(hash_value)
        return cmd

    elif tool_name == "hash_identifier":
        hash_value = params.get("hash", "").strip()
        if not hash_value:
            return []
        binary = shutil.which("hashid") or "hashid"
        cmd = [binary, "-e", "-m", hash_value]
        return cmd

    elif tool_name == "hashcat_crack":
        hashfile = params.get("hashfile", "").strip()
        hash_value = params.get("hash", "").strip()
        if not hashfile and not hash_value:
            return []

        binary = shutil.which("hashcat") or TOOL_PATHS.get("hashcat", "hashcat")
        cmd = [binary]

        mode = params.get("mode", "").strip()
        if mode:
            cmd.extend(["-m", mode])

        attack = params.get("attack_mode", "0").strip()
        cmd.extend(["-a", attack])

        if params.get("force"):
            cmd.append("--force")
        if params.get("show"):
            cmd.append("--show")
        if params.get("potfile_disable"):
            cmd.append("--potfile-disable")
        if params.get("increment"):
            cmd.append("--increment")

        increment_min = params.get("increment_min", "").strip()
        if increment_min:
            cmd.extend(["--increment-min", increment_min])
        increment_max = params.get("increment_max", "").strip()
        if increment_max:
            cmd.extend(["--increment-max", increment_max])

        rules = params.get("rules", "").strip()
        if rules:
            cmd.extend(["-r", rules])

        workload = params.get("workload", "").strip()
        if workload:
            cmd.extend(["-w", workload])

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())

        if hashfile:
            cmd.append(hashfile)
        elif hash_value:
            cmd.append(hash_value)

        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.append(wordlist)

        return cmd

    elif tool_name == "john_crack":
        hashfile = params.get("hashfile", "").strip()
        if not hashfile:
            return []

        binary = shutil.which("john") or TOOL_PATHS.get("john", "john")
        cmd = [binary]

        wordlist = params.get("wordlist", "").strip()
        if wordlist:
            cmd.append(f"--wordlist={wordlist}")

        fmt = params.get("format", "").strip()
        if fmt:
            cmd.append(f"--format={fmt}")

        rules = params.get("rules", "").strip()
        if rules:
            cmd.append(f"--rules={rules}")

        if params.get("show"):
            cmd.append("--show")
        if params.get("single"):
            cmd.append("--single")

        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())

        cmd.append(hashfile)
        return cmd

    return []
