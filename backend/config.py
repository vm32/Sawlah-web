import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sawlah.db")
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
TEMPLATE_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

TOOL_PATHS = {
    "nmap": "/usr/bin/nmap",
    "sqlmap": "/usr/bin/sqlmap",
    "amass": "/usr/bin/amass",
    "gobuster": "/usr/bin/gobuster",
    "dnsenum": "/usr/bin/dnsenum",
    "nikto": "/usr/bin/nikto",
    "dirb": "/usr/bin/dirb",
    "ffuf": "/usr/bin/ffuf",
    "whatweb": "/usr/bin/whatweb",
    "wfuzz": "/usr/bin/wfuzz",
    "nxc": "/usr/bin/nxc",
    "enum4linux": "/usr/bin/enum4linux",
    "smbclient": "/usr/bin/smbclient",
    "searchsploit": "/usr/bin/searchsploit",
    "hydra": "/usr/bin/hydra",
    "john": "/usr/sbin/john",
    "hashcat": "/usr/bin/hashcat",
    "whois": "/usr/bin/whois",
    "dig": "/usr/bin/dig",
}
