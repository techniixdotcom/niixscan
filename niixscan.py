#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════╗
# ║          NiiX Scan  —  Multi-Distro Security Framework              ║
# ║          Created by: cuteLiLi / techniix                            ║
# ║          Supports: Arch · Debian/Ubuntu · Fedora/RHEL               ║
# ╚══════════════════════════════════════════════════════════════════════╝

import os
import sys
import re
import subprocess
import shutil
import json
import logging
import time
import platform
import tempfile
import threading
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# ─── ANSI colours ─────────────────────────────────────────────────────
R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"
CY  = "\033[38;5;51m"
GR  = "\033[38;5;82m"
YL  = "\033[38;5;220m"
RD  = "\033[38;5;196m"
MG  = "\033[38;5;213m"
BL  = "\033[38;5;33m"
WH  = "\033[97m"
OR  = "\033[38;5;208m"

logging.basicConfig(level=logging.WARNING,
                    format=f"{DIM}[%(asctime)s]{R} %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("niixscan")

# ══════════════════════════════════════════════════════════════════════
#  DISTRO DETECTION
# ══════════════════════════════════════════════════════════════════════
def detect_distro():
    if not sys.platform.startswith("linux"):
        sys.exit(f"{RD}[!]{R} NiiX Scan requires Linux.")
    info = {}
    osr  = Path("/etc/os-release")
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
        if shutil.which(pm):
            return "unknown", pm, cmd
    sys.exit(f"{RD}[!]{R} No supported package manager found.")

DISTRO_FAMILY, PKG_MGR, INSTALL_CMD = detect_distro()

# ══════════════════════════════════════════════════════════════════════
#  PACKAGE MAPS
# ══════════════════════════════════════════════════════════════════════
_PKG = {
    "git"      : {"arch":"git",               "debian":"git",           "fedora":"git"},
    "wget"     : {"arch":"wget",              "debian":"wget",          "fedora":"wget"},
    "curl"     : {"arch":"curl",              "debian":"curl",          "fedora":"curl"},
    "pip"      : {"arch":"python-pip",        "debian":"python3-pip",   "fedora":"python3-pip"},
    "nmap"     : {"arch":"nmap",              "debian":"nmap",          "fedora":"nmap"},
    "nikto"    : {"arch":"nikto",             "debian":"nikto",         "fedora":"nikto"},
    "whois"    : {"arch":"whois",             "debian":"whois",         "fedora":"whois"},
    "dnsutils" : {"arch":"bind",              "debian":"dnsutils",      "fedora":"bind-utils"},
    "hydra"    : {"arch":"hydra",             "debian":"hydra",         "fedora":"hydra"},
    "masscan"  : {"arch":"masscan",           "debian":"masscan",       "fedora":"masscan"},
    "gobuster" : {"arch":"gobuster",          "debian":"gobuster",      "fedora":"gobuster"},
    "unzip"    : {"arch":"unzip",             "debian":"unzip",         "fedora":"unzip"},
    "tar"      : {"arch":"tar",               "debian":"tar",           "fedora":"tar"},
}

def _pkg(key: str) -> str:
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
    if pkgs:
        _run_q(INSTALL_CMD + pkgs)

def ensure_base():
    _apt_update()
    install_pkg("git","wget","curl","pip","unzip","tar")

# ══════════════════════════════════════════════════════════════════════
#  TERMINAL HELPERS
# ══════════════════════════════════════════════════════════════════════
def _W():
    return shutil.get_terminal_size((100, 24)).columns

def clear():
    os.system("clear")

def hline(char="─", col=CY):
    return f"{col}{char*_W()}{R}"

def banner():
    clear()
    w = _W()
    dist_info = f"by cuteLiLi / techniix  ·  {DISTRO_FAMILY.upper()} / {PKG_MGR.upper()} detected"
    print(f"{CY}╔{'═'*(w-2)}╗{R}")
    print(f"{CY}║{R}{B}{WH}{'  NiiX Scan  ─  Multi-Distro Security Framework'.center(w-2)}{R}{CY}║{R}")
    print(f"{CY}║{R}{DIM}{dist_info.center(w-2)}{R}{CY}║{R}")
    print(f"{CY}╚{'═'*(w-2)}╝{R}")

def msg_ok(s):  print(f"  {GR}{B}✔{R} {s}")
def msg_err(s): print(f"  {RD}{B}✗{R} {s}")
def msg_inf(s): print(f"  {CY}{B}»{R} {s}")
def msg_wrn(s): print(f"  {YL}{B}!{R} {s}")

def pause():
    input(f"\n  {DIM}Press ENTER to continue …{R}")

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

# ══════════════════════════════════════════════════════════════════════
#  PROGRESS BAR  (real-time, in-place)
# ══════════════════════════════════════════════════════════════════════
def _draw_bar(pct: int, label: str = "", bar_w: int = 48):
    pct    = max(0, min(100, int(pct)))
    filled = int(bar_w * pct / 100)
    empty  = bar_w - filled
    bar    = f"{GR}{'█'*filled}{DIM}{'░'*empty}{R}"
    lbl    = (label[:50]+"…") if len(label) > 50 else label
    pct_s  = f"{CY}{B}{pct:>3}%{R}"
    print(f"\r  {bar} {pct_s}  {DIM}{lbl:<52}{R}", end="", flush=True)


# ── Spinner (indeterminate progress during installs) ──────────────────
_sp_active = False
_sp_thread = None
_sp_label  = ""
_SP_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

def _sp_worker():
    i = 0
    while _sp_active:
        f   = _SP_FRAMES[i % len(_SP_FRAMES)]
        lbl = (_sp_label[:65]+"…") if len(_sp_label)>65 else _sp_label
        print(f"\r  {CY}{f}{R}  {DIM}{lbl:<68}{R}", end="", flush=True)
        i  += 1
        time.sleep(0.09)

def spinner_start(label="Working …"):
    global _sp_active, _sp_thread, _sp_label
    _sp_label  = label
    _sp_active = True
    _sp_thread = threading.Thread(target=_sp_worker, daemon=True)
    _sp_thread.start()

def spinner_stop(ok_msg="Done."):
    global _sp_active
    _sp_active = False
    if _sp_thread:
        _sp_thread.join(timeout=0.5)
    print(f"\r  {GR}✔{R}  {ok_msg:<70}")


# ══════════════════════════════════════════════════════════════════════
#  GITHUB BINARY DOWNLOADER
#  Downloads pre-built release binaries — avoids Go/compiler issues
# ══════════════════════════════════════════════════════════════════════
def _arch():
    m = platform.machine().lower()
    if m in ("x86_64","amd64"): return "amd64"
    if m in ("aarch64","arm64"): return "arm64"
    if m in ("i386","i686"):    return "386"
    return "amd64"

def install_github_binary(repo: str, asset_pattern: str,
                           binary_name: str, dest: str = "/usr/local/bin"):
    """
    Fetch the latest GitHub release, match asset by regex (supports {arch}),
    download with a real % progress bar, extract and install `binary_name`.
    """
    arch    = _arch()
    pattern = asset_pattern.format(arch=arch)
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"

    msg_inf(f"Fetching latest release info for {repo} …")
    req = urllib.request.Request(
        api_url,
        headers={"Accept":"application/vnd.github+json","User-Agent":"niixscan/3"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"GitHub API error: {e}")

    tag        = data.get("tag_name","?")
    asset_url  = None
    asset_name = None
    for asset in data.get("assets",[]):
        if re.search(pattern, asset["name"], re.IGNORECASE):
            asset_url  = asset["browser_download_url"]
            asset_name = asset["name"]
            break

    if not asset_url:
        avail = [a["name"] for a in data.get("assets",[])]
        raise RuntimeError(
            f"No asset matching '{pattern}' in {repo} {tag}.\n"
            f"  Available: {avail}"
        )

    bar_w = min(44, _W()-30)

    def _hook(count, block, total):
        if total > 0:
            _draw_bar(min(int(count*block*100/total), 100),
                      f"↓ {asset_name}", bar_w)

    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, asset_name)
        print(f"  {CY}↓{R}  {asset_name}  {DIM}({tag}){R}")
        try:
            urllib.request.urlretrieve(asset_url, archive, reporthook=_hook)
        except Exception as e:
            raise RuntimeError(f"Download failed: {e}")
        print()  # end progress bar line

        # Extract archive
        if asset_name.endswith((".tar.gz",".tgz")):
            _run_q(["tar","-xzf", archive,"-C", tmp])
        elif asset_name.endswith(".zip"):
            _run_q(["unzip","-q", archive,"-d", tmp])

        # Find binary anywhere in extracted tree
        found = None
        for root, _dirs, files in os.walk(tmp):
            if binary_name in files:
                found = os.path.join(root, binary_name)
                break
        if not found:
            raise RuntimeError(f"'{binary_name}' not found in archive.")

        dest_path = os.path.join(dest, binary_name)
        _run(["sudo","cp",   found,     dest_path], check=True)
        _run(["sudo","chmod","+x",      dest_path], check=True)

    msg_ok(f"{binary_name} {tag} → {dest_path}")


# ══════════════════════════════════════════════════════════════════════
#  LIVE SCAN RUNNER  (streams output + real-time % progress bar)
# ══════════════════════════════════════════════════════════════════════
def run_scan(cmd: list, label: str,
             pct_fn=None, total_lines: int = 0, show_output: bool = True):
    """
    Execute `cmd` and stream its combined stdout/stderr.
      pct_fn(line) → int|None   extract exact % from a line
      total_lines               derive % from line count if no pct_fn match
      show_output               print every line when no bar is active
    """
    print(f"\n  {CY}►{R} {B}{label}{R}")
    print(hline())

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    use_bar  = bool(pct_fn or total_lines)
    bar_w    = min(50, _W()-28)
    n_lines  = 0
    last_pct = 0

    try:
        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip()
            if not line:
                continue
            n_lines += 1

            pct = None
            if pct_fn:
                pct = pct_fn(line)
            if pct is None and total_lines:
                pct = min(int(n_lines * 100 / total_lines), 99)

            if pct is not None:
                pct      = max(last_pct, min(int(pct), 100))
                last_pct = pct
                _draw_bar(pct, line[:55], bar_w)
            else:
                if use_bar:
                    trunc = (line[:_W()-8]+"…") if len(line) > _W()-8 else line
                    print(f"\r  {DIM}{trunc:<{_W()-4}}{R}", end="", flush=True)
                elif show_output:
                    print(f"  {DIM}{line}{R}")

    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n  {YL}Scan interrupted by user.{R}")

    proc.stdout.close()
    proc.wait()

    if use_bar:
        _draw_bar(100, "Complete ✔", bar_w)
        print()

    rc = proc.returncode
    if rc and rc != 0:
        msg_wrn(f"Process exited with code {rc}")
    print(hline())
    return rc


# ══════════════════════════════════════════════════════════════════════
#  PER-TOOL % EXTRACTORS
# ══════════════════════════════════════════════════════════════════════
def _pct_nmap(line):
    m = re.search(r"About\s+([\d.]+)%\s+done", line)
    return int(float(m.group(1))) if m else None

def _pct_masscan(line):
    m = re.search(r"([\d.]+)%\s+done", line)
    return int(float(m.group(1))) if m else None

def _pct_gobuster(line):
    m = re.search(r"Progress:\s*(\d+)\s*/\s*(\d+)", line)
    if m: return int(int(m.group(1))*100/max(int(m.group(2)),1))
    m = re.search(r"\(([\d.]+)%\)", line)
    return int(float(m.group(1))) if m else None

def _pct_hydra(line):
    # [STATUS] 256 tries completed, 4096 to go
    m = re.search(r"\[STATUS\]\s+(\d+)\s+tries.*?(\d+)\s+to go", line)
    if m:
        done = int(m.group(1)); left = int(m.group(2))
        total = done + left
        return int(done*100/total) if total else None
    return None

def _pct_sqlmap(line):
    phases = ["testing connection","fetching","testing if","heuristic detection",
              "checking","parsing error","retrieved","identified","target appears",
              "back-end DBMS"]
    ll = line.lower()
    for i, p in enumerate(phases):
        if p in ll:
            return int((i+1)*100/len(phases))
    return None

def _pct_nuclei(line):
    # nuclei -stats outputs: "Requests: 120/900"
    m = re.search(r"Requests:\s*(\d+)\s*/\s*(\d+)", line, re.IGNORECASE)
    if m:
        done = int(m.group(1)); total = int(m.group(2))
        return int(done*100/max(total,1))
    m2 = re.search(r"(\d{1,3})%", line)
    return int(m2.group(1)) if m2 else None

def _pct_nikto(line):
    m = re.search(r"(\d+)/(\d+)\s+items", line, re.IGNORECASE)
    if m: return int(int(m.group(1))*100/max(int(m.group(2)),1))
    return None


# ══════════════════════════════════════════════════════════════════════
#  TOOL BASE CLASS
# ══════════════════════════════════════════════════════════════════════
class Tool:
    name  = "tool"
    label = "Generic Tool"
    desc  = "No description."
    color = CY

    def install(self): pass

    def is_installed(self):
        return bool(shutil.which(self.name))

    def run_interactive(self):
        raise NotImplementedError

    def header(self):
        banner()
        print(f"\n  {self.color}{B}[ {self.label} ]{R}\n")


# ══════════════════════════════════════════════════════════════════════
#  TOOLS
# ══════════════════════════════════════════════════════════════════════

class NmapTool(Tool):
    name  = "nmap"
    label = "Nmap — Network Scanner"
    desc  = "Port scanning, OS detection, service fingerprinting"
    color = GR

    def install(self):
        _apt_update(); install_pkg("nmap")

    def run_interactive(self):
        self.header()
        target  = ask("Target IP / hostname / CIDR", "192.168.1.1")
        profile = self._profile()
        cmd     = ["nmap", "-v", "--stats-every", "5s"] + profile + [target]
        run_scan(cmd, f"Nmap → {target}", pct_fn=_pct_nmap)
        pause()

    def _profile(self):
        pr = {
            "1":(["-sV","-T4"],        "Quick service scan"),
            "2":(["-sV","-sC","-T4"],  "Default scripts + services"),
            "3":(["-p-","-sV","-T3"],  "Full port scan (all 65535)"),
            "4":(["-sU","-T4"],        "UDP scan"),
            "5":(["-A","-T4"],         "Aggressive (OS+version+scripts)"),
            "6":(["-sn"],              "Ping sweep / host discovery"),
        }
        print(f"\n  {WH}Scan profiles:{R}")
        for k,(_,lbl) in pr.items():
            print(f"    {CY}{k}{R}) {lbl}")
        return pr.get(ask("Profile","2"), pr["2"])[0]


class SQLMapTool(Tool):
    name  = "sqlmap"
    label = "SQLMap — SQL Injection Scanner"
    desc  = "Automatic SQL injection detection & exploitation"
    color = RD

    def install(self):
        dest = Path("/opt/sqlmap")
        ensure_base()
        if dest.exists():
            msg_inf("SQLMap present. Pulling updates …")
            _run(["sudo","git","-C",str(dest),"pull"], check=False,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            _run(["sudo","git","clone","--depth=1",
                  "https://github.com/sqlmapproject/sqlmap.git", str(dest)],
                 check=True)
        _run(["sudo","chmod","755",   str(dest/"sqlmap.py")], check=False)
        _run(["sudo","chown","-R",
              f"{os.environ.get('USER','root')}:", str(dest)], check=False)
        msg_ok("SQLMap installed at /opt/sqlmap")

    def is_installed(self):
        return Path("/opt/sqlmap/sqlmap.py").exists()

    def run_interactive(self):
        self.header()
        url = ask("Target URL (e.g. https://site.com/page?id=1)", "")
        if not validate_url(url):
            msg_err("Invalid URL."); pause(); return
        extras = ask("Extra flags (e.g. --level=3 --risk=2)", "")
        cmd = [sys.executable, "/opt/sqlmap/sqlmap.py",
               "-u", url, "--batch", "--output-dir=/tmp/sqlmap_out"]
        if extras: cmd += extras.split()
        run_scan(cmd, f"SQLMap → {url}", pct_fn=_pct_sqlmap)
        pause()


class NucleiTool(Tool):
    name  = "nuclei"
    label = "Nuclei — Vulnerability Scanner"
    desc  = "Template-based fast vulnerability scanner"
    color = MG

    def install(self):
        ensure_base()
        # ── Use pre-built binary from GitHub Releases ──────────────
        # Avoids `go install` compilation failures caused by Go version
        # mismatches (e.g. bytedance/sonic GoMapIterator undefined on Arch
        # with Go 1.26+).  The release asset name follows the pattern:
        #   nuclei_3.3.9_linux_amd64.zip
        install_github_binary(
            repo          = "projectdiscovery/nuclei",
            asset_pattern = r"^nuclei_[\d.]+_linux_{arch}\.zip$",
            binary_name   = "nuclei",
        )
        # Update templates after install
        msg_inf("Downloading Nuclei templates …")
        spinner_start("Fetching templates (this may take a minute) …")
        try:
            subprocess.run(["nuclei", "-update-templates"],
                           capture_output=True, timeout=180, check=False)
        except Exception:
            pass
        spinner_stop("Templates ready.")

    def run_interactive(self):
        self.header()
        target   = ask("Target URL or IP", "")
        if not target:
            msg_err("No target."); pause(); return
        severity = ask("Severity filter (critical,high,medium,low,info)", "critical,high")
        # -stats + -stats-interval emit "Requests: X/Y" lines our extractor reads
        cmd = ["nuclei", "-u", target,
               "-severity", severity,
               "-stats", "-stats-interval", "2"]
        run_scan(cmd, f"Nuclei → {target}", pct_fn=_pct_nuclei)
        pause()


class NiktoTool(Tool):
    name  = "nikto"
    label = "Nikto — Web Server Scanner"
    desc  = "Web server misconfiguration & vulnerability checks"
    color = YL

    def install(self):
        _apt_update(); install_pkg("nikto")

    def run_interactive(self):
        self.header()
        host   = ask("Target host/URL", "https://example.com")
        output = ask("Save report to file (blank to skip)", "")
        cmd    = ["nikto", "-h", host]
        if output: cmd += ["-output", output]
        run_scan(cmd, f"Nikto → {host}", pct_fn=_pct_nikto)
        pause()


class HydraTool(Tool):
    name  = "hydra"
    label = "Hydra — Brute-Force Tool"
    desc  = "Network login cracker (SSH, FTP, HTTP, etc.)"
    color = RD

    def install(self):
        _apt_update(); install_pkg("hydra")

    def run_interactive(self):
        self.header()
        msg_wrn("Only use against systems you own or have explicit permission to test.")
        if not confirm("I understand and have permission"): return
        target   = ask("Target IP / hostname", "")
        service  = ask("Service (ssh/ftp/http-post-form/…)", "ssh")
        userlist = ask("Userlist file", "/usr/share/wordlists/metasploit/unix_users.txt")
        passlist = ask("Passlist file", "/usr/share/wordlists/rockyou.txt")
        threads  = ask("Threads", "16")
        cmd = ["hydra", "-L", userlist, "-P", passlist,
               "-t", threads, "-V", target, service]
        run_scan(cmd, f"Hydra → {target} ({service})", pct_fn=_pct_hydra)
        pause()


class GobusterTool(Tool):
    name  = "gobuster"
    label = "Gobuster — Directory/DNS Brute-Forcer"
    desc  = "Enumerate web directories, DNS subdomains & vhosts"
    color = BL

    def install(self):
        _apt_update()
        install_pkg("gobuster")
        if not shutil.which("gobuster"):
            install_github_binary(
                repo          = "OJ/gobuster",
                asset_pattern = r"gobuster_Linux_{arch}\.tar\.gz",
                binary_name   = "gobuster",
            )

    def run_interactive(self):
        self.header()
        mode   = ask("Mode: dir / dns / vhost", "dir")
        url    = ask("Target URL (dir/vhost) or domain (dns)", "")
        wl     = ask("Wordlist", "/usr/share/wordlists/dirb/common.txt")
        extras = ask("Extra flags (optional)", "")
        if   mode == "dir":  cmd = ["gobuster","dir", "-u",url,"-w",wl,"--no-color"]
        elif mode == "dns":  cmd = ["gobuster","dns", "-d",url,"-w",wl,"--no-color"]
        else:                cmd = ["gobuster","vhost","-u",url,"-w",wl,"--no-color"]
        if extras: cmd += extras.split()
        run_scan(cmd, f"Gobuster {mode} → {url}", pct_fn=_pct_gobuster)
        pause()


class MasscanTool(Tool):
    name  = "masscan"
    label = "Masscan — Ultra-Fast Port Scanner"
    desc  = "Internet-speed port scanner"
    color = MG

    def install(self):
        _apt_update(); install_pkg("masscan")

    def run_interactive(self):
        self.header()
        target = ask("Target IP / CIDR", "192.168.1.0/24")
        ports  = ask("Port range", "1-65535")
        rate   = ask("Packets/sec", "1000")
        cmd    = ["sudo","masscan", target, f"-p{ports}", f"--rate={rate}"]
        run_scan(cmd, f"Masscan → {target}:{ports}", pct_fn=_pct_masscan)
        pause()


class SubfinderTool(Tool):
    name  = "subfinder"
    label = "Subfinder — Subdomain Enumeration"
    desc  = "Passive subdomain discovery"
    color = CY

    def install(self):
        ensure_base()
        install_github_binary(
            repo          = "projectdiscovery/subfinder",
            asset_pattern = r"^subfinder_linux_{arch}\.zip$",
            binary_name   = "subfinder",
        )

    def run_interactive(self):
        self.header()
        domain = ask("Target domain", "example.com")
        output = ask("Output file (blank to skip)", "")
        cmd    = ["subfinder", "-d", domain, "-v"]
        if output: cmd += ["-o", output]
        run_scan(cmd, f"Subfinder → {domain}", total_lines=300)
        pause()


class ReconTool(Tool):
    name  = "whois"
    label = "Recon — WHOIS / DNS / Traceroute"
    desc  = "Passive information gathering"
    color = WH

    def install(self):
        _apt_update(); install_pkg("whois","dnsutils")

    def run_interactive(self):
        self.header()
        ops = {"1":"WHOIS lookup","2":"DNS lookup (A/MX/NS)",
               "3":"Reverse DNS","4":"Traceroute"}
        for k,lbl in ops.items():
            print(f"    {CY}{k}{R}) {lbl}")
        choice = ask("Operation","1")
        target = ask("Target IP / domain","")
        print(hline())
        if   choice=="1": _run(["whois",    target])
        elif choice=="2": subprocess.run(
            f"dig +short {target} A; dig +short {target} MX; dig +short {target} NS",
            shell=True)
        elif choice=="3": _run(["host",      target])
        elif choice=="4": _run(["traceroute",target])
        print(hline())
        pause()


# ══════════════════════════════════════════════════════════════════════
#  TOOL REGISTRY
# ══════════════════════════════════════════════════════════════════════
TOOLS = [
    NmapTool(),
    SQLMapTool(),
    NucleiTool(),
    NiktoTool(),
    HydraTool(),
    GobusterTool(),
    MasscanTool(),
    SubfinderTool(),
    ReconTool(),
]


# ══════════════════════════════════════════════════════════════════════
#  INSTALL HELPERS
# ══════════════════════════════════════════════════════════════════════
def install_single(tool: Tool):
    banner()
    print(f"\n  {YL}{B}Installing {tool.label} …{R}\n")
    ensure_base()
    try:
        tool.install()
        msg_ok(f"{tool.label} installed.")
    except Exception as e:
        msg_err(f"Install failed: {e}")
    pause()


def install_all():
    banner()
    print(f"\n  {YL}{B}Installing all tools …{R}\n")
    ensure_base()
    total = len(TOOLS)
    bar_w = min(44, _W()-30)
    for idx, tool in enumerate(TOOLS, 1):
        _draw_bar(int((idx-1)*100/total), f"({idx}/{total}) {tool.label}", bar_w)
        try:
            tool.install()
        except Exception as e:
            print()
            msg_err(f"{tool.label}: {e}")
    _draw_bar(100, "All tools processed ✔", bar_w)
    print()
    msg_ok("Installation complete.")
    pause()


# ══════════════════════════════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════════════════════════════
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
    while True:
        banner()
        print(f"\n  {MG}{B}⚙  Settings{R}\n")
        print(f"  {CY}1{R}) Output directory  : {cfg.get('output_dir','~/niixscan-results')}")
        print(f"  {CY}2{R}) Default wordlist   : {cfg.get('wordlist','/usr/share/wordlists/rockyou.txt')}")
        print(f"  {CY}3{R}) Log level          : {cfg.get('log_level','INFO')}")
        print(f"  {CY}0{R}) Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if   ch == "1": cfg["output_dir"] = ask("Output dir",   cfg.get("output_dir","~/niixscan-results"))
        elif ch == "2": cfg["wordlist"]   = ask("Wordlist",     cfg.get("wordlist",  "/usr/share/wordlists/rockyou.txt"))
        elif ch == "3": cfg["log_level"]  = ask("Log level",    cfg.get("log_level", "INFO"))
        elif ch == "0": break
        save_cfg(cfg); msg_ok("Saved."); time.sleep(0.5)


# ══════════════════════════════════════════════════════════════════════
#  TOOL SUB-MENU
# ══════════════════════════════════════════════════════════════════════
def tool_submenu(tool: Tool):
    while True:
        banner()
        inst = tool.is_installed()
        st   = f"{GR}installed{R}" if inst else f"{RD}not installed{R}"
        print(f"\n  {tool.color}{B}[ {tool.label} ]{R}")
        print(f"  {DIM}{tool.desc}{R}")
        print(f"  Status: {st}\n")
        print(f"  {CY}1{R}) ▶  Run")
        print(f"  {CY}2{R}) ⬇  Install / update")
        print(f"  {CY}0{R}) ←  Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if ch == "1":
            if not inst:
                msg_wrn("Not installed. Installing first …")
                install_single(tool)
            if tool.is_installed():
                tool.run_interactive()
            else:
                msg_err("Install failed. Cannot run.")
                pause()
        elif ch == "2":
            install_single(tool)
        elif ch == "0":
            break


# ══════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════
def main_menu():
    while True:
        banner()
        w = _W()
        print(f"\n{CY}{'  MAIN MENU':^{w}}{R}\n")
        for i, tool in enumerate(TOOLS, 1):
            dot = f"{GR}●{R}" if tool.is_installed() else f"{RD}○{R}"
            print(f"  {CY}{i:>2}{R})  {dot}  {B}{tool.label:<42}{R} {DIM}{tool.desc}{R}")
        print()
        print(f"  {YL} I{R})  ⬇  Install ALL tools")
        print(f"  {MG} S{R})  ⚙  Settings")
        print(f"  {RD} Q{R})  ✕  Quit")
        print(f"\n{hline()}")
        ch = input(f"\n  {CY}Select option{R}: ").strip().lower()
        if ch.isdigit() and 1 <= int(ch) <= len(TOOLS):
            tool_submenu(TOOLS[int(ch)-1])
        elif ch == "i":  install_all()
        elif ch == "s":  settings_menu()
        elif ch in ("q","quit","exit"):
            banner()
            print(f"\n  {CY}Thank you for using NiiX Scan. Stay ethical.{R}\n")
            sys.exit(0)
        else:
            msg_err("Invalid option.")
            time.sleep(0.4)


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if sys.version_info < (3, 8):
        sys.exit("NiiX Scan requires Python 3.8+")
    if "--install-all" in sys.argv:
        install_all(); sys.exit(0)
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Interrupted.{R}\n")
        sys.exit(0)
