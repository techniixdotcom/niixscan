#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║        NiiX Scan  —  Multi-Distro Security Framework  v4.0               ║
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
    "api_key"     : "",      # Anthropic API key
    "scan_results": {},      # tool_name → raw output
    "ai_report"   : None,    # last AI analysis dict
}

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
def clear(): os.system("clear")
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

def pause(): input(f"\n  {DIM}Press ENTER to continue …{R}")

def ask(prompt, default=""):
    v = input(f"  {CY}?{R} {prompt}{DIM} [{default}]{R}: ").strip()
    return v if v else default

def confirm(prompt):
    return input(f"  {YL}?{R} {prompt} {DIM}[y/N]{R}: ").strip().lower() in ("y","yes")

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
def run_scan(cmd, label, pct_fn=None, total_lines=0, show_output=True, capture_key=None):
    """
    Run cmd, show live progress bar/spinner, optionally store output in
    SESSION["scan_results"][capture_key] for later AI analysis.
    Returns (returncode, captured_output_str).
    """
    print(f"\n  {CY}►{R} {B}{label}{R}")
    print(hline())

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)

    use_bar = bool(pct_fn or total_lines)
    bar_w   = min(50, _W()-28)
    n_lines = 0; last_pct = 0
    captured = []

    try:
        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip()
            if not line: continue
            n_lines += 1
            captured.append(line)

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

    proc.stdout.close(); proc.wait()
    if use_bar:
        _draw_bar(100, "Complete ✔", bar_w); print()

    rc = proc.returncode
    if rc and rc != 0: msg_wrn(f"Process exited with code {rc}")
    print(hline())

    output_str = "\n".join(captured)
    if capture_key:
        SESSION["scan_results"][capture_key] = output_str
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
#  ██████████  CLAUDE AI ENGINE  ██████████
# ══════════════════════════════════════════════════════════════════════════════
ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL  = "claude-opus-4-6"

def _claude_request(system_prompt: str, user_msg: str,
                    max_tokens: int = 4096) -> str:
    """
    Send a request to the Anthropic Messages API.
    Returns the text content of the first content block.
    Raises RuntimeError on any failure.
    """
    api_key = SESSION.get("api_key","")
    if not api_key:
        raise RuntimeError("No API key set. Go to Settings → Set Claude API Key.")

    payload = json.dumps({
        "model"      : CLAUDE_MODEL,
        "max_tokens" : max_tokens,
        "system"     : system_prompt,
        "messages"   : [{"role": "user", "content": user_msg}],
    }).encode()

    req = urllib.request.Request(
        ANTHROPIC_API,
        data    = payload,
        method  = "POST",
        headers = {
            "Content-Type"      : "application/json",
            "x-api-key"         : api_key,
            "anthropic-version" : "2023-06-01",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"API HTTP {e.code}: {body[:300]}")
    except Exception as e:
        raise RuntimeError(f"API request failed: {e}")

    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected API response shape: {e}\n{data}")


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
    """Send scan output to Claude, get structured vulnerability analysis."""
    msg_ai(f"Sending {tool_name} output to Claude for analysis …")
    spinner_start("Analysing with Claude …")
    user_msg = (
        f"Tool: {tool_name}\nTarget: {target}\n\n"
        f"=== RAW SCAN OUTPUT ===\n{raw_output[:12000]}\n=== END OUTPUT ==="
    )
    try:
        raw_json = _claude_request(_SYS_ANALYST, user_msg, max_tokens=4096)
        # strip accidental markdown fences
        raw_json = re.sub(r"^```[a-z]*\n?", "", raw_json.strip())
        raw_json = re.sub(r"\n?```$", "", raw_json)
        result   = json.loads(raw_json)
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
    """Ask Claude to generate a Metasploit .rc file from an analysis dict."""
    msg_ai("Generating Metasploit resource script …")
    spinner_start("Claude is crafting the .rc script …")
    user_msg = (
        f"LHOST (attacker IP): {lhost}\n\n"
        f"VULNERABILITY ANALYSIS:\n{json.dumps(analysis, indent=2)}"
    )
    try:
        rc_content = _claude_request(_SYS_RC_GEN, user_msg, max_tokens=3000)
        spinner_stop("Resource script generated.")
        return rc_content
    except Exception as e:
        spinner_stop(f"RC generation failed: {e}")
        raise


def display_ai_analysis(analysis: dict):
    """Pretty-print the AI analysis to the terminal."""
    w = _W()
    print(f"\n{PU}{'─'*w}{R}")
    print(f"{PU}{B}  🤖  CLAUDE AI VULNERABILITY ANALYSIS{R}")
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
            print(f"      {GR}MSF Module:{R} {v['msf_module']}")
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
    """Ask Claude for a step-by-step plan + rc for a single vulnerability."""
    spinner_start(f"Claude planning exploit for {vuln.get('id','?')} …")
    user_msg = (
        f"LHOST: {lhost}\n"
        f"TARGET: {SESSION.get('target','unknown')}\n\n"
        f"VULNERABILITY:\n{json.dumps(vuln, indent=2)}"
    )
    try:
        raw = _claude_request(_SYS_STEP, user_msg, max_tokens=2500)
        raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw)
        result = json.loads(raw)
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
                msg_wrn("Claude will attempt to suggest the best available approach.")
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
        msg_err("No Claude API key. Go to Settings → Set Claude API Key."); pause(); return
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


def _get_local_ip() -> str:
    """Best-effort local IP detection."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "YOUR_IP"


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
    """Ask Claude to produce a full pentest report."""
    if not SESSION["api_key"]:
        raise RuntimeError("No API key.")
    user_msg = (
        f"Target: {target}\n"
        f"Assessment Date: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n"
        f"SCAN DATA SUMMARY:\n"
        + "\n".join(f"\n[{k}]\n{v[:3000]}" for k,v in scan_results.items())
        + f"\n\nSTRUCTURED ANALYSIS:\n{json.dumps(analysis, indent=2)[:6000]}"
    )
    spinner_start("Claude is writing the pentest report …")
    try:
        report = _claude_request(_SYS_REPORT, user_msg, max_tokens=8000)
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
        print(f"  {CY}1{R})  🔍  Analyse stored scans with Claude AI")
        print(f"  {CY}2{R})  📋  View last AI analysis report")
        print(f"  {CY}3{R})  ⚔   Step-through exploitation wizard  "
              f"{DIM}(picks each vuln, generates payload, runs MSF){R}")

        # Dynamic per-vuln quick-launch entries
        if vulns:
            print(f"\n  {DIM}── Quick exploit by vulnerability ──{R}")
            for i, v in enumerate(vulns, 1):
                sev = v.get("severity","info")
                sc  = {"critical":RD,"high":OR,"medium":YL,
                       "low":GR,"info":DIM}.get(sev, DIM)
                msf_tag = f"{GR}[MSF ✔]{R}" if v.get("msf_module") else f"{DIM}[no module]{R}"
                print(f"  {CY}{i+3:>2}{R})  {sc}{B}{sev.upper():<10}{R}  "
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

        elif ch.isdigit() and int(ch) >= 4:
            # Quick per-vuln exploit
            idx = int(ch) - 3  # maps option 4 → vuln[0], 5 → vuln[1], etc.
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


# ══════════════════════════════════════════════════════════════════════════════
#  TOOL BASE CLASS
# ══════════════════════════════════════════════════════════════════════════════
class Tool:
    name = "tool"; label = "Generic Tool"; desc = "No description."; color = CY

    def install(self): pass
    def is_installed(self): return bool(shutil.which(self.name))
    def run_interactive(self): raise NotImplementedError
    def header(self):
        banner(); print(f"\n  {self.color}{B}[ {self.label} ]{R}\n")

    def _post_scan_ai(self, raw_output: str, target: str):
        """Offer AI analysis after a scan completes."""
        if not SESSION["api_key"]: return
        if not raw_output.strip(): return
        print(f"\n  {PU}»{R} Scan complete. {B}Analyse with Claude?{R}")
        if confirm("Send results to Claude AI for vulnerability analysis"):
            try:
                analysis = ai_analyse_scan(raw_output, self.label, target)
                SESSION["ai_report"] = analysis
                # Merge into session results
                SESSION["scan_results"][self.name] = SESSION["scan_results"].get(
                    self.name, "") + "\n" + raw_output
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
        SESSION["target"] = target
        profile = self._profile()
        cmd = ["nmap", "-v", "--stats-every", "5s"] + profile + [target]
        rc, out = run_scan(cmd, f"Nmap → {target}", pct_fn=_pct_nmap,
                           capture_key="nmap")
        self._post_scan_ai(out, target); pause()

    def _profile(self):
        pr = {"1":(["-sV","-T4"],"Quick service scan"),
              "2":(["-sV","-sC","-T4"],"Default scripts + services"),
              "3":(["-p-","-sV","-T3"],"Full port scan (all 65535)"),
              "4":(["-sU","-T4"],"UDP scan"),
              "5":(["-A","-T4"],"Aggressive (OS+version+scripts)"),
              "6":(["-sn"],"Ping sweep / host discovery")}
        print(f"\n  {WH}Scan profiles:{R}")
        for k,(_,lbl) in pr.items(): print(f"    {CY}{k}{R}) {lbl}")
        return pr.get(ask("Profile","2"), pr["2"])[0]


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
            subprocess.run(["nuclei","-update-templates"],
                           capture_output=True, timeout=180, check=False)
        except Exception: pass
        spinner_stop("Templates ready.")

    def run_interactive(self):
        self.header()
        target = ask("Target URL or IP", SESSION["target"] or "")
        if not target: msg_err("No target."); pause(); return
        SESSION["target"] = target
        severity = ask("Severity filter", "critical,high")
        cmd = ["nuclei","-u",target,"-severity",severity,"-stats","-stats-interval","2"]
        rc, out = run_scan(cmd, f"Nuclei → {target}", pct_fn=_pct_nuclei,
                           capture_key="nuclei")
        self._post_scan_ai(out, target); pause()


class NiktoTool(Tool):
    name = "nikto"; label = "Nikto — Web Server Scanner"
    desc = "Web server misconfiguration & vulnerability checks"; color = YL

    def install(self): _apt_update(); install_pkg("nikto")

    def run_interactive(self):
        self.header()
        host = ask("Target host/URL", SESSION["target"] or "https://example.com")
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
        threads  = ask("Threads", "16")
        cmd = ["hydra","-L",userlist,"-P",passlist,"-t",threads,"-V",target,service]
        rc, out = run_scan(cmd, f"Hydra → {target} ({service})", pct_fn=_pct_hydra,
                           capture_key="hydra")
        self._post_scan_ai(out, target); pause()


class GobusterTool(Tool):
    name = "gobuster"; label = "Gobuster — Directory/DNS Brute-Forcer"
    desc = "Enumerate web directories, DNS subdomains & vhosts"; color = BL

    def install(self):
        _apt_update(); install_pkg("gobuster")
        if not shutil.which("gobuster"):
            install_github_binary("OJ/gobuster",
                r"gobuster_Linux_{arch}\.tar\.gz", "gobuster")

    def run_interactive(self):
        self.header()
        mode = ask("Mode: dir / dns / vhost","dir")
        url  = ask("Target URL (dir/vhost) or domain (dns)", SESSION["target"] or "")
        wl   = ask("Wordlist", "/usr/share/wordlists/dirb/common.txt")
        extras = ask("Extra flags","")
        if   mode=="dir":  cmd = ["gobuster","dir", "-u",url,"-w",wl,"--no-color"]
        elif mode=="dns":  cmd = ["gobuster","dns", "-d",url,"-w",wl,"--no-color"]
        else:              cmd = ["gobuster","vhost","-u",url,"-w",wl,"--no-color"]
        if extras: cmd += extras.split()
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
        ports  = ask("Port range","1-65535"); rate = ask("Packets/sec","1000")
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
            r"^subfinder_linux_{arch}\.zip$", "subfinder")

    def run_interactive(self):
        self.header()
        domain = ask("Target domain", SESSION["target"] or "example.com")
        output = ask("Output file (blank to skip)","")
        cmd = ["subfinder","-d",domain,"-v"]
        if output: cmd += ["-o",output]
        rc, out = run_scan(cmd, f"Subfinder → {domain}", total_lines=300,
                           capture_key="subfinder")
        self._post_scan_ai(out, domain); pause()


class ReconTool(Tool):
    name = "whois"; label = "Recon — WHOIS / DNS / Traceroute"
    desc = "Passive information gathering"; color = WH

    def install(self): _apt_update(); install_pkg("whois","dnsutils")

    def run_interactive(self):
        self.header()
        ops = {"1":"WHOIS lookup","2":"DNS lookup (A/MX/NS)",
               "3":"Reverse DNS","4":"Traceroute"}
        for k,lbl in ops.items(): print(f"    {CY}{k}{R}) {lbl}")
        choice = ask("Operation","1")
        target = ask("Target IP / domain", SESSION["target"] or "")
        print(hline())
        out = ""
        if choice=="1":
            r = subprocess.run(["whois",target], capture_output=True, text=True)
            out = r.stdout; print(out)
        elif choice=="2":
            r = subprocess.run(
                f"dig +short {target} A; dig +short {target} MX; dig +short {target} NS",
                shell=True, capture_output=True, text=True)
            out = r.stdout; print(out)
        elif choice=="3":
            r = subprocess.run(["host",target], capture_output=True, text=True)
            out = r.stdout; print(out)
        elif choice=="4":
            _run(["traceroute",target])
        print(hline())
        if out: SESSION["scan_results"]["recon"] = SESSION["scan_results"].get("recon","") + out
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
]

# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def install_single(tool):
    banner(); print(f"\n  {YL}{B}Installing {tool.label} …{R}\n")
    ensure_base()
    try:
        tool.install(); msg_ok(f"{tool.label} installed.")
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
        try: return json.loads(_CFG.read_text())
        except: pass
    return {}

def save_cfg(c):
    _CFG.parent.mkdir(parents=True, exist_ok=True)
    _CFG.write_text(json.dumps(c, indent=2))

def settings_menu():
    cfg = load_cfg()
    # Load saved API key into session
    if cfg.get("api_key") and not SESSION["api_key"]:
        SESSION["api_key"] = cfg["api_key"]

    while True:
        banner()
        print(f"\n  {MG}{B}⚙  Settings{R}\n")
        key_display = ("*"*8 + SESSION["api_key"][-4:]) if len(SESSION["api_key"]) > 8 else (SESSION["api_key"] or "not set")
        print(f"  {CY}1{R}) Claude API Key     : {GR if SESSION['api_key'] else RD}{key_display}{R}")
        print(f"  {CY}2{R}) Output directory   : {cfg.get('output_dir','~/niixscan-results')}")
        print(f"  {CY}3{R}) Default wordlist    : {cfg.get('wordlist','/usr/share/wordlists/rockyou.txt')}")
        print(f"  {CY}4{R}) Claude model        : {cfg.get('model', CLAUDE_MODEL)}")
        print(f"  {CY}5{R}) Test API connection")
        print(f"  {CY}0{R}) Back\n")
        ch = input(f"  {CY}»{R} ").strip()

        if ch == "1":
            key = ask("Paste Claude API key (input hidden on most terminals)","")
            if key:
                SESSION["api_key"] = key; cfg["api_key"] = key
                save_cfg(cfg); msg_ok("API key saved.")
        elif ch == "2":
            cfg["output_dir"] = ask("Output dir", cfg.get("output_dir","~/niixscan-results"))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "3":
            cfg["wordlist"] = ask("Wordlist", cfg.get("wordlist","/usr/share/wordlists/rockyou.txt"))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "4":
            cfg["model"] = ask("Model (e.g. claude-opus-4-6)", cfg.get("model", CLAUDE_MODEL))
            save_cfg(cfg); msg_ok("Saved.")
        elif ch == "5":
            if not SESSION["api_key"]:
                msg_err("No API key set."); time.sleep(1); continue
            spinner_start("Testing connection …")
            try:
                resp = _claude_request("You are a test assistant.",
                                       "Reply with only: OK", max_tokens=10)
                spinner_stop(f"Connection OK — model replied: {resp.strip()}")
            except Exception as e:
                spinner_stop(f"Failed: {e}")
            pause()
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
        print(f"  {PU}{B}10{R})  🤖  AI Analysis & Exploitation Centre")
        print(f"  {YL} I{R})  ⬇  Install ALL tools")
        print(f"  {MG} S{R})  ⚙  Settings  {DIM}(set Claude API key here){R}")
        print(f"  {RD} Q{R})  ✕  Quit")
        print(f"\n{hline()}")
        ch = input(f"\n  {CY}Select option{R}: ").strip().lower()

        if ch.isdigit():
            n = int(ch)
            if 1 <= n <= len(TOOLS):
                tool_submenu(TOOLS[n-1])
            elif n == 10:
                if not SESSION["authorized"]:
                    if not authorization_gate(): continue
                ai_analysis_menu()
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
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Interrupted.{R}\n"); sys.exit(0)
