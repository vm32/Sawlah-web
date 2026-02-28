from config import TOOL_PATHS


def build_nxc_command(tool_name: str, params: dict) -> list[str]:
    target = params.get("target", "").strip()
    if not target:
        return []

    protocol = params.get("protocol", "smb").lower()
    valid_protocols = ["smb", "ldap", "rdp", "winrm", "ssh", "ftp", "mssql", "wmi", "vnc", "nfs"]
    if protocol not in valid_protocols:
        protocol = "smb"

    cmd = [TOOL_PATHS["nxc"], protocol, target]

    username = params.get("username", "").strip()
    password = params.get("password", "").strip()
    nthash = params.get("hash", "").strip()

    if username:
        cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    if nthash:
        cmd.extend(["-H", nthash])

    if params.get("shares"):
        cmd.append("--shares")
    if params.get("users"):
        cmd.append("--users")
    if params.get("groups"):
        cmd.append("--groups")
    if params.get("sessions"):
        cmd.append("--sessions")
    if params.get("disks"):
        cmd.append("--disks")
    if params.get("loggedon"):
        cmd.append("--loggedon-users")
    if params.get("rid_brute"):
        cmd.append("--rid-brute")
    if params.get("pass_pol"):
        cmd.append("--pass-pol")
    if params.get("sam"):
        cmd.append("--sam")
    if params.get("lsa"):
        cmd.append("--lsa")
    if params.get("ntds"):
        cmd.append("--ntds")

    module = params.get("module", "").strip()
    if module:
        cmd.extend(["-M", module])
    elif params.get("spider_plus"):
        cmd.extend(["-M", "spider_plus"])

    if params.get("local_auth"):
        cmd.append("--local-auth")
    if params.get("laps"):
        cmd.append("--laps")
    if params.get("kerberoast"):
        cmd.append("--kerberoasting")

    ntds_method = params.get("ntds_method", "").strip()
    if ntds_method and params.get("ntds"):
        cmd.extend(["--ntds", ntds_method])

    exec_method = params.get("exec_method", "").strip()
    if exec_method:
        cmd.extend(["--exec-method", exec_method])

    exec_cmd = params.get("exec_cmd", "").strip()
    if exec_cmd:
        cmd.extend(["-x", exec_cmd])

    put_file = params.get("put_file", "").strip()
    if put_file:
        cmd.extend(["--put-file", put_file])

    get_file = params.get("get_file", "").strip()
    if get_file:
        cmd.extend(["--get-file", get_file])

    extra = params.get("extra_flags", "").strip()
    if extra:
        cmd.extend(extra.split())

    return cmd
