import shutil
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
        if params.get("rid_brute"):
            cmd.append("-r")
        rid_range = params.get("rid_range", "").strip()
        if rid_range:
            cmd.extend(["-R", rid_range])
        workgroup = params.get("workgroup", "").strip()
        if workgroup:
            cmd.extend(["-w", workgroup])
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
        if params.get("max_protocol"):
            cmd.extend(["-m", params["max_protocol"]])
        if params.get("port"):
            cmd.extend(["-p", str(params["port"])])
        smb_cmd = params.get("smb_command", "").strip()
        if smb_cmd:
            cmd.extend(["-c", smb_cmd])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "rpcclient":
        binary = shutil.which("rpcclient")
        if not binary:
            return []
        cmd = [binary]
        username = params.get("username", "").strip()
        password = params.get("password", "").strip()
        if username:
            cmd.extend(["-U", f"{username}%{password}" if password else username])
        else:
            cmd.append("-N")
        rpc_cmd = params.get("rpc_command", "").strip()
        if rpc_cmd:
            cmd.extend(["-c", rpc_cmd])
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    elif tool_name == "ldapsearch":
        binary = shutil.which("ldapsearch")
        if not binary:
            return []
        cmd = [binary, "-x", "-H", f"ldap://{target}"]
        base_dn = params.get("base_dn", "").strip()
        if base_dn:
            cmd.extend(["-b", base_dn])
        bind_dn = params.get("bind_dn", "").strip()
        if bind_dn:
            cmd.extend(["-D", bind_dn])
        bind_pw = params.get("bind_password", "").strip()
        if bind_pw:
            cmd.extend(["-w", bind_pw])
        search_filter = params.get("search_filter", "").strip()
        if search_filter:
            cmd.append(search_filter)
        else:
            cmd.append("(objectClass=*)")
        attrs = params.get("attributes", "").strip()
        if attrs:
            cmd.extend(attrs.split(","))
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "snmpwalk":
        binary = shutil.which("snmpwalk")
        if not binary:
            return []
        version = params.get("version", "2c")
        community = params.get("community", "public").strip()
        cmd = [binary, "-v", version, "-c", community, target]
        oid = params.get("oid", "").strip()
        if oid:
            cmd.append(oid)
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        return cmd

    elif tool_name == "nbtscan":
        binary = shutil.which("nbtscan")
        if not binary:
            return []
        cmd = [binary]
        if params.get("verbose"):
            cmd.append("-v")
        if params.get("human_readable"):
            cmd.append("-h")
        extra = params.get("extra_flags", "").strip()
        if extra:
            cmd.extend(extra.split())
        cmd.append(target)
        return cmd

    return []
