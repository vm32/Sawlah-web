from config import TOOL_PATHS


def build_recon_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    if tool_name == "whois":
        cmd = [TOOL_PATHS["whois"]]
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    elif tool_name == "dig":
        cmd = [TOOL_PATHS["dig"]]
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

    return []
