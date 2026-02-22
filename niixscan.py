#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║          NiiX Scan  —  Multi-Distro Security Framework          ║
# ║          Created by: cuteLiLi / techniix                        ║
# ║          Supports: Arch · Debian/Ubuntu · Fedora/RHEL            ║
# ╚══════════════════════════════════════════════════════════════════╝

import os
import sys
import subprocess
import shutil
import json
import logging
import time
import textwrap
from pathlib import Path
from urllib.parse import urlparse
from threading import Thread

# ─── Colour palette ───────────────────────────────────────────────
R  = "\033[0m"          # reset
B  = "\033[1m"          # bold
DIM= "\033[2m"
CY = "\033[38;5;51m"    # cyan
GR = "\033[38;5;82m"    # green
YL = "\033[38;5;220m"   # yellow
RD = "\033[38;5;196m"   # red
MG = "\033[38;5;213m"   # magenta
BL = "\033[38;5;27m"    # blue
WH = "\033[97m"         # white
BG = "\033[48;5;234m"   # dark bg

# ─── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format=f"{DIM}[%(asctime)s]{R} %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("niixscan")

# ─── OS / distro detection ────────────────────────────────────────
def detect_distro():
    """Return (family, pkg_manager, install_cmd_prefix)."""
    if not sys.platform.startswith("linux"):
        sys.exit(f"{RD}[!]{R} NiiX Scan requires Linux (Arch / Debian / Fedora).")

    os_release = Path("/etc/os-release")
    info = {}
    if os_release.exists():
        for line in os_release.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')

    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()

    if "arch" in ident or "manjaro" in ident or "endeavour" in ident:
        return ("arch", "pacman", ["sudo", "pacman", "-S", "--noconfirm", "--needed"])
    elif "fedora" in ident or "rhel" in ident or "centos" in ident or "rocky" in ident:
        mgr = "dnf" if shutil.which("dnf") else "yum"
        return ("fedora", mgr, ["sudo", mgr, "install", "-y"])
    elif "debian" in ident or "ubuntu" in ident or "mint" in ident or "kali" in ident:
        return ("debian", "apt", ["sudo", "apt-get", "install", "-y"])
    else:
        # best-effort fallback
        for pm, cmd in [("apt", ["sudo","apt-get","install","-y"]),
                        ("dnf", ["sudo","dnf","install","-y"]),
                        ("pacman", ["sudo","pacman","-S","--noconfirm","--needed"])]:
            if shutil.which(pm):
                return ("unknown", pm, cmd)
        sys.exit(f"{RD}[!]{R} Cannot detect package manager.")

DISTRO_FAMILY, PKG_MGR, INSTALL_CMD = detect_distro()

# ─── Package maps per distro family ───────────────────────────────
PKG_MAP = {
    # pkg-key  : {arch, debian, fedora}
    "python3"  : {"arch":"python",     "debian":"python3",          "fedora":"python3"},
    "pip"      : {"arch":"python-pip", "debian":"python3-pip",      "fedora":"python3-pip"},
    "git"      : {"arch":"git",        "debian":"git",              "fedora":"git"},
    "wget"     : {"arch":"wget",       "debian":"wget",             "fedora":"wget"},
    "curl"     : {"arch":"curl",       "debian":"curl",             "fedora":"curl"},
    "nmap"     : {"arch":"nmap",       "debian":"nmap",             "fedora":"nmap"},
    "go"       : {"arch":"go",         "debian":"golang",           "fedora":"golang"},
    "java"     : {"arch":"jre-openjdk","debian":"default-jre",      "fedora":"java-latest-openjdk"},
    "nikto"    : {"arch":"nikto",      "debian":"nikto",            "fedora":"nikto"},
    "whois"    : {"arch":"whois",      "debian":"whois",            "fedora":"whois"},
    "dnsutils" : {"arch":"bind",       "debian":"dnsutils",         "fedora":"bind-utils"},
    "netcat"   : {"arch":"openbsd-netcat","debian":"netcat-openbsd","fedora":"nmap-ncat"},
    "hydra"    : {"arch":"hydra",      "debian":"hydra",            "fedora":"hydra"},
    "masscan"  : {"arch":"masscan",    "debian":"masscan",          "fedora":"masscan"},
    "gobuster" : {"arch":"gobuster",   "debian":"gobuster",         "fedora":"gobuster"},
    "subfinder": {"arch":"subfinder",  "debian":"",                 "fedora":""},
    "httpx"    : {"arch":"",           "debian":"",                 "fedora":""},
}

def pkg_name(key):
    """Resolve package key to distro-specific name."""
    return PKG_MAP.get(key, {}).get(DISTRO_FAMILY, key) or key

def run(cmd, **kw):
    return subprocess.run(cmd, **kw)

def apt_update():
    if DISTRO_FAMILY == "debian":
        run(["sudo", "apt-get", "update", "-qq"], check=False)

def install_pkg(*keys):
    pkgs = [pkg_name(k) for k in keys if pkg_name(k)]
    pkgs = [p for p in pkgs if p]
    if pkgs:
        run(INSTALL_CMD + pkgs, check=False)

def pip_install(*packages):
    run([sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages",
         *packages], check=False)

# ─── Terminal helpers ──────────────────────────────────────────────
def clear():
    os.system("clear")

def width():
    return shutil.get_terminal_size((80, 24)).columns

def center(text, w=None):
    w = w or width()
    return text.center(w)

def hline(char="─", color=CY):
    return f"{color}{char * width()}{R}"

def banner():
    clear()
    w = width()
    logo = [
        f"{CY}╔{'═'*(w-2)}╗{R}",
        f"{CY}║{R}{B}{WH}{'  NiiX Scan  ─  Multi-Distro Security Framework'.center(w-2)}{R}{CY}║{R}",
        f"{CY}║{R}{DIM}{'by cuteLiLi / techniix  ·  '+DISTRO_FAMILY.upper()+' / '+PKG_MGR.upper()+' detected'.center(w-2)}{R}{CY}║{R}",
        f"{CY}╚{'═'*(w-2)}╝{R}",
    ]
    print("\n".join(logo))

def status(msg, color=GR):
    print(f"  {color}{B}»{R} {msg}")

def error(msg):
    print(f"  {RD}{B}✗{R} {msg}")

def success(msg):
    print(f"  {GR}{B}✔{R} {msg}")

def warn(msg):
    print(f"  {YL}{B}!{R} {msg}")

def pause():
    input(f"\n  {DIM}Press ENTER to continue …{R}")

def ask(prompt, default=""):
    val = input(f"  {CY}?{R} {prompt}{DIM} [{default}]{R}: ").strip()
    return val if val else default

def confirm(prompt):
    ans = input(f"  {YL}?{R} {prompt} {DIM}[y/N]{R}: ").strip().lower()
    return ans in ("y", "yes")

# ─── Dependency checker ────────────────────────────────────────────
def ensure_base_deps():
    """Make sure git, wget, curl, pip are available."""
    apt_update()
    install_pkg("git", "wget", "curl", "pip")

# ─── URL validator ────────────────────────────────────────────────
def validate_url(url):
    try:
        r = urlparse(url)
        return bool(r.scheme and r.netloc)
    except Exception:
        return False

# ─── Tool runners ─────────────────────────────────────────────────

class Tool:
    """Base class for all scanners."""
    name    = "tool"
    label   = "Generic Tool"
    desc    = "No description."
    color   = CY

    def install(self):
        pass

    def is_installed(self):
        return bool(shutil.which(self.name))

    def run_interactive(self):
        raise NotImplementedError

    def header(self):
        banner()
        print(f"\n  {self.color}{B}[ {self.label} ]{R}\n")


# ── Nmap ──────────────────────────────────────────────────────────
class NmapTool(Tool):
    name  = "nmap"
    label = "Nmap — Network Scanner"
    desc  = "Port scanning, OS detection, service fingerprinting"
    color = GR

    def install(self):
        apt_update(); install_pkg("nmap")

    def run_interactive(self):
        self.header()
        target = ask("Target IP / hostname / CIDR", "192.168.1.0/24")
        profile = self._choose_profile()
        cmd = ["nmap"] + profile + [target]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()

    def _choose_profile(self):
        profiles = {
            "1": (["-sV", "-T4"],                          "Quick service scan"),
            "2": (["-sV", "-sC", "-T4"],                   "Default scripts + services"),
            "3": (["-p-", "-sV", "-T3"],                   "Full port scan (slow)"),
            "4": (["-sU", "-T4"],                          "UDP scan"),
            "5": (["-A", "-T4"],                           "Aggressive (OS+version+scripts)"),
            "6": (["-sn"],                                 "Ping sweep / host discovery"),
        }
        print(f"\n  {WH}Scan profiles:{R}")
        for k, (_, lbl) in profiles.items():
            print(f"    {CY}{k}{R}) {lbl}")
        choice = ask("Profile", "2")
        return profiles.get(choice, profiles["2"])[0]


# ── SQLMap ────────────────────────────────────────────────────────
class SQLMapTool(Tool):
    name  = "sqlmap"
    label = "SQLMap — SQL Injection Scanner"
    desc  = "Automatic SQL injection detection & exploitation"
    color = RD

    def install(self):
        dest = Path("/opt/sqlmap")
        if dest.exists():
            status("SQLMap already cloned. Updating …")
            run(["git", "-C", str(dest), "pull"], check=False)
        else:
            ensure_base_deps()
            run(["sudo", "git", "clone", "--depth=1",
                 "https://github.com/sqlmapproject/sqlmap.git", str(dest)], check=True)
        os.chmod(str(dest / "sqlmap.py"), 0o755)
        success("SQLMap installed at /opt/sqlmap")

    def is_installed(self):
        return Path("/opt/sqlmap/sqlmap.py").exists()

    def run_interactive(self):
        self.header()
        url = ask("Target URL (e.g. https://site.com/page?id=1)", "")
        if not validate_url(url):
            error("Invalid URL."); pause(); return

        extras = ask("Extra flags (optional, e.g. --level=3 --risk=2)", "")
        cmd = [sys.executable, "/opt/sqlmap/sqlmap.py", "-u", url,
               "--batch"] + (extras.split() if extras else [])
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Nuclei ────────────────────────────────────────────────────────
class NucleiTool(Tool):
    name  = "nuclei"
    label = "Nuclei — Vulnerability Scanner"
    desc  = "Template-based fast vulnerability scanner"
    color = MG

    def install(self):
        install_pkg("go")
        env = os.environ.copy()
        gopath = Path.home() / "go"
        env["GOPATH"] = str(gopath)
        env["PATH"]   = str(gopath / "bin") + ":" + env["PATH"]
        run(["go", "install", "-v",
             "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
            env=env, check=False)
        # symlink
        nuclei_bin = gopath / "bin" / "nuclei"
        if nuclei_bin.exists() and not shutil.which("nuclei"):
            run(["sudo", "ln", "-sf", str(nuclei_bin), "/usr/local/bin/nuclei"], check=False)
        success("Nuclei installed.")

    def run_interactive(self):
        self.header()
        target = ask("Target URL or IP", "")
        if not target:
            error("No target."); pause(); return
        severity = ask("Severity filter (critical,high,medium,low,info)", "critical,high")
        cmd = ["nuclei", "-u", target, "-severity", severity, "-silent"]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Nikto ─────────────────────────────────────────────────────────
class NiktoTool(Tool):
    name  = "nikto"
    label = "Nikto — Web Server Scanner"
    desc  = "Web server misconfiguration & vulnerability checks"
    color = YL

    def install(self):
        apt_update(); install_pkg("nikto")

    def run_interactive(self):
        self.header()
        host = ask("Target host/URL", "https://example.com")
        output = ask("Save report to file (leave blank to skip)", "")
        cmd = ["nikto", "-h", host]
        if output:
            cmd += ["-output", output]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Hydra ─────────────────────────────────────────────────────────
class HydraTool(Tool):
    name  = "hydra"
    label = "Hydra — Brute-Force Tool"
    desc  = "Network login cracker (SSH, FTP, HTTP, etc.)"
    color = RD

    def install(self):
        apt_update(); install_pkg("hydra")

    def run_interactive(self):
        self.header()
        warn("Only use against systems you own or have explicit permission to test.")
        if not confirm("I understand and have permission"):
            return
        target  = ask("Target IP / hostname", "")
        service = ask("Service (ssh/ftp/http-post-form/…)", "ssh")
        userlist= ask("Userlist file path", "/usr/share/wordlists/metasploit/unix_users.txt")
        passlist= ask("Passlist file path", "/usr/share/wordlists/rockyou.txt")
        threads = ask("Threads", "16")
        cmd = ["hydra", "-L", userlist, "-P", passlist, "-t", threads,
               target, service]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Gobuster ──────────────────────────────────────────────────────
class GobusterTool(Tool):
    name  = "gobuster"
    label = "Gobuster — Directory/DNS Brute-Forcer"
    desc  = "Enumerate web directories, DNS subdomains & vhosts"
    color = BL

    def install(self):
        apt_update(); install_pkg("gobuster")

    def run_interactive(self):
        self.header()
        mode = ask("Mode: dir / dns / vhost", "dir")
        url  = ask("Target URL (for dir/vhost) or domain (for dns)", "")
        wl   = ask("Wordlist", "/usr/share/wordlists/dirb/common.txt")
        extras = ask("Extra flags (optional)", "")
        if mode == "dir":
            cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-q"]
        elif mode == "dns":
            cmd = ["gobuster", "dns", "-d", url, "-w", wl, "-q"]
        else:
            cmd = ["gobuster", "vhost", "-u", url, "-w", wl, "-q"]
        if extras:
            cmd += extras.split()
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Masscan ───────────────────────────────────────────────────────
class MasscanTool(Tool):
    name  = "masscan"
    label = "Masscan — Ultra-Fast Port Scanner"
    desc  = "Internet-speed port scanner"
    color = MG

    def install(self):
        apt_update(); install_pkg("masscan")

    def run_interactive(self):
        self.header()
        target = ask("Target IP / CIDR", "192.168.1.0/24")
        ports  = ask("Port range", "0-65535")
        rate   = ask("Packets per second", "1000")
        cmd = ["sudo", "masscan", target, f"-p{ports}", f"--rate={rate}"]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── Subfinder ─────────────────────────────────────────────────────
class SubfinderTool(Tool):
    name  = "subfinder"
    label = "Subfinder — Subdomain Enumeration"
    desc  = "Passive subdomain discovery"
    color = CY

    def install(self):
        install_pkg("go")
        env = os.environ.copy()
        gopath = Path.home() / "go"
        env["GOPATH"] = str(gopath)
        env["PATH"]   = str(gopath / "bin") + ":" + env["PATH"]
        run(["go", "install", "-v",
             "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            env=env, check=False)
        sub_bin = gopath / "bin" / "subfinder"
        if sub_bin.exists() and not shutil.which("subfinder"):
            run(["sudo", "ln", "-sf", str(sub_bin), "/usr/local/bin/subfinder"], check=False)
        success("Subfinder installed.")

    def run_interactive(self):
        self.header()
        domain = ask("Target domain", "example.com")
        output = ask("Output file (blank to skip)", "")
        cmd = ["subfinder", "-d", domain, "-silent"]
        if output:
            cmd += ["-o", output]
        status(f"Running: {' '.join(cmd)}")
        print(hline())
        run(cmd)
        print(hline())
        pause()


# ── WHOIS / DNS Recon ─────────────────────────────────────────────
class ReconTool(Tool):
    name  = "whois"
    label = "Recon — WHOIS / DNS / Traceroute"
    desc  = "Passive information gathering"
    color = WH

    def install(self):
        apt_update(); install_pkg("whois", "dnsutils")

    def run_interactive(self):
        self.header()
        ops = {
            "1": ("WHOIS lookup",    lambda t: run(["whois", t])),
            "2": ("DNS lookup (A/MX/NS)", lambda t: run(["dig", "+short", t, "A",
                                                          "&&", "dig", "+short", t, "MX"], shell=False)),
            "3": ("Reverse DNS",     lambda t: run(["host", t])),
            "4": ("Traceroute",      lambda t: run(["traceroute", t])),
        }
        for k, (lbl, _) in ops.items():
            print(f"    {CY}{k}{R}) {lbl}")
        choice = ask("Operation", "1")
        target = ask("Target IP / domain", "")
        if choice == "2":
            run(f"dig +short {target} A; dig +short {target} MX; dig +short {target} NS",
                shell=True)
        elif choice in ops:
            ops[choice][1](target)
        print(hline())
        pause()


# ─── Tool registry ────────────────────────────────────────────────
TOOLS: list[Tool] = [
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

# ─── Install all deps menu ────────────────────────────────────────
def install_all():
    banner()
    print(f"\n  {YL}{B}Installing all tools …{R}\n")
    ensure_base_deps()
    for tool in TOOLS:
        print(f"  {CY}►{R} Installing {B}{tool.label}{R} …", end=" ", flush=True)
        try:
            tool.install()
            print(f"{GR}done{R}")
        except Exception as e:
            print(f"{RD}failed ({e}){R}")
    success("Dependency installation complete.")
    pause()

def install_single(tool: Tool):
    banner()
    print(f"\n  {YL}{B}Installing {tool.label} …{R}\n")
    ensure_base_deps()
    try:
        tool.install()
        success(f"{tool.label} installed.")
    except Exception as e:
        error(f"Install failed: {e}")
    pause()

# ─── Settings / config ────────────────────────────────────────────
CONFIG_PATH = Path.home() / ".config" / "niixscan" / "config.json"

def load_config():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    return {}

def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

def settings_menu():
    cfg = load_config()
    while True:
        banner()
        print(f"\n  {MG}{B}⚙  Settings{R}\n")
        print(f"  {CY}1{R}) Output directory  : {cfg.get('output_dir', '~/niixscan-results')}")
        print(f"  {CY}2{R}) Default wordlist   : {cfg.get('wordlist', '/usr/share/wordlists/rockyou.txt')}")
        print(f"  {CY}3{R}) Log level          : {cfg.get('log_level', 'INFO')}")
        print(f"  {CY}0{R}) Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if ch == "1":
            cfg["output_dir"] = ask("Output directory", cfg.get("output_dir","~/niixscan-results"))
        elif ch == "2":
            cfg["wordlist"] = ask("Wordlist path", cfg.get("wordlist","/usr/share/wordlists/rockyou.txt"))
        elif ch == "3":
            cfg["log_level"] = ask("Log level (DEBUG/INFO/WARNING)", cfg.get("log_level","INFO"))
        elif ch == "0":
            break
        save_config(cfg)
        success("Settings saved.")
        time.sleep(0.6)

# ─── Main menu ────────────────────────────────────────────────────
def tool_submenu(tool: Tool):
    while True:
        banner()
        installed = tool.is_installed()
        status_str = f"{GR}installed{R}" if installed else f"{RD}not installed{R}"
        print(f"\n  {tool.color}{B}[ {tool.label} ]{R}")
        print(f"  {DIM}{tool.desc}{R}")
        print(f"  Status: {status_str}\n")
        print(f"  {CY}1{R}) Run {tool.label}")
        print(f"  {CY}2{R}) Install / update")
        print(f"  {CY}0{R}) Back\n")
        ch = input(f"  {CY}»{R} ").strip()
        if ch == "1":
            if not installed:
                warn("Tool not found. Installing first …")
                install_single(tool)
            if tool.is_installed():
                tool.run_interactive()
            else:
                error("Install failed. Cannot run.")
                pause()
        elif ch == "2":
            install_single(tool)
        elif ch == "0":
            break

def main_menu():
    while True:
        banner()
        w = width()
        print(f"\n{CY}{'  MAIN MENU':^{w}}{R}\n")

        for i, tool in enumerate(TOOLS, 1):
            installed = tool.is_installed()
            dot = f"{GR}●{R}" if installed else f"{RD}○{R}"
            num = f"{CY}{i:>2}{R}"
            print(f"  {num})  {dot}  {B}{tool.label:<38}{R} {DIM}{tool.desc}{R}")

        print()
        print(f"  {YL} I{R})  Install ALL tools at once")
        print(f"  {MG} S{R})  Settings")
        print(f"  {RD} Q{R})  Quit")
        print(f"\n{hline()}")

        ch = input(f"\n  {CY}Select option{R}: ").strip().lower()

        if ch.isdigit() and 1 <= int(ch) <= len(TOOLS):
            tool_submenu(TOOLS[int(ch) - 1])
        elif ch == "i":
            install_all()
        elif ch == "s":
            settings_menu()
        elif ch in ("q", "quit", "exit"):
            banner()
            print(f"\n  {CY}Thank you for using NiiX Scan. Stay ethical.{R}\n")
            sys.exit(0)
        else:
            error("Invalid option.")
            time.sleep(0.4)

# ─── Entry point ──────────────────────────────────────────────────
if __name__ == "__main__":
    # Require Python 3.8+
    if sys.version_info < (3, 8):
        sys.exit("NiiX Scan requires Python 3.8 or newer.")

    # Allow --install-all flag for non-interactive CI use
    if len(sys.argv) > 1 and sys.argv[1] == "--install-all":
        install_all()
        sys.exit(0)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Interrupted.{R}\n")
        sys.exit(0)
