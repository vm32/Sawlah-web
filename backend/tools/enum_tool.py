from config import TOOL_PATHS


def build_enum_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "enum4linux":
        cmd = [TOOL_PATHS["enum4linux"]]
        if params.get("all"):
            cmd.append("-a")
        if params.get("users"):
            cmd.append("-U")
        if params.get("shares"):
            cmd.append("-S")
        if params.get("password_policy"):
            cmd.append("-P")
        if params.get("groups"):
            cmd.append("-G")
        if params.get("os_info"):
            cmd.append("-o")
        username = params.get("username", "").strip()
        password = params.get("password", "").strip()
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    elif tool_name == "smbclient":
        cmd = [TOOL_PATHS["smbclient"]]
        share = params.get("share", "").strip()
        if share:
            cmd.append(f"//{target}/{share}")
        else:
            cmd.extend(["-L", target])
        username = params.get("username", "").strip()
        password = params.get("password", "").strip()
        if username:
            cmd.extend(["-U", username])
        else:
            cmd.append("-N")
        if password:
            cmd.extend(["--password", password])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    return []
