from config import TOOL_PATHS


def build_sqlmap_command(tool_name: str, params: dict) -> list[str]:
    cmd = [TOOL_PATHS["sqlmap"]]
    target = params.get("target", "").strip()
    if not target:
        return []

    cmd.extend(["-u", target])

    method = params.get("method", "GET").upper()
    if method == "POST":
        data = params.get("data", "")
        if data:
            cmd.extend(["--data", data])

    level = params.get("level", 1)
    if level and int(level) in range(1, 6):
        cmd.extend(["--level", str(level)])

    risk = params.get("risk", 1)
    if risk and int(risk) in range(1, 4):
        cmd.extend(["--risk", str(risk)])

    tamper = params.get("tamper", "")
    if tamper:
        cmd.extend(["--tamper", tamper])

    if params.get("dbs"):
        cmd.append("--dbs")
    if params.get("tables"):
        cmd.append("--tables")
    if params.get("columns"):
        cmd.append("--columns")
    if params.get("dump"):
        cmd.append("--dump")
    if params.get("current_db"):
        cmd.append("--current-db")
    if params.get("current_user"):
        cmd.append("--current-user")
    if params.get("is_dba"):
        cmd.append("--is-dba")

    db = params.get("database", "")
    if db:
        cmd.extend(["-D", db])

    table = params.get("table", "")
    if table:
        cmd.extend(["-T", table])

    if params.get("random_agent"):
        cmd.append("--random-agent")

    if params.get("threads"):
        cmd.extend(["--threads", str(params["threads"])])

    cookie = params.get("cookie", "").strip()
    if cookie:
        cmd.extend(["--cookie", cookie])

    user_agent = params.get("user_agent", "").strip()
    if user_agent:
        cmd.extend(["--user-agent", user_agent])

    proxy = params.get("proxy", "").strip()
    if proxy:
        cmd.extend(["--proxy", proxy])

    cmd.append("--batch")

    extra = params.get("extra_flags", "").strip()
    if extra:
        cmd.extend(extra.split())

    return cmd
