# NiiX Scan — niixscan.py

> ⚠ **Legal Notice:** This tool is for authorised penetration testing and security research **only**. Unauthorised use against systems you do not own or have explicit written permission to test is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide. You accept full legal responsibility for your use.

A Python-based interactive security testing framework (v4.0) with an AI-assisted exploitation pipeline powered by the Kimi (Moonshot AI) API. It bundles nine common pentest tools into a single terminal UI, automates dependency installation across major Linux distros, and uses Kimi to analyse scan output, generate Metasploit resource scripts, and produce professional pentest reports.

*Created by: cuteLiLi / techniix / QuacK*

---

## Features

- **Interactive terminal UI** — colourful menu-driven interface with live progress bars and spinners, no CLI flags required for normal use.
- **Authorization consent gate** — requires explicit target entry and a typed confirmation phrase before any scanning can begin, enforcing a clear authorization checkpoint every session.
- **Nine integrated security tools** — each can be installed, updated, and run directly from the menu.
- **AI Analysis Centre** — sends raw scan output to Kimi for structured vulnerability analysis (severity, CVE IDs, Metasploit modules, attack path, and remediation).
- **Step-through exploitation wizard** — walks through each discovered vulnerability one at a time; Kimi generates a step-by-step plan and a ready-to-run Metasploit `.rc` resource script per vulnerability.
- **Metasploit integration** — generated `.rc` scripts can be reviewed, edited in `$EDITOR`, and executed via `msfconsole` directly from within the tool.
- **AI pentest report generator** — produces a formal, structured pentest report (Executive Summary, Findings, Risk Matrix, Remediation) saved as a plain-text file.
- **Automatic dependency management** — detects your Linux distro and installs missing tools via the native package manager without manual intervention.
- **Cross-distro support** — works on Arch/Manjaro, Debian/Ubuntu/Kali/Parrot, and Fedora/RHEL/Rocky out of the box.
- **Persistent settings** — API key, output directory, wordlist path, and Kimi model are saved to a config file and loaded automatically on next run.

---

## Integrated Tools

| # | Tool | Purpose |
|---|---|---|
| 1 | **nmap** | Port scanning and service/version detection |
| 2 | **Nikto** | Web server vulnerability scanning |
| 3 | **Gobuster** | Directory and file brute-forcing |
| 4 | **Hydra** | Network login brute-forcing |
| 5 | **Masscan** | High-speed large-scale port scanning |
| 6 | **whois / dig / nslookup** | Domain and DNS reconnaissance |
| 7 | **Metasploit Framework** | Exploitation framework and post-exploitation |
| 8 | **SQLMap** | Automated SQL injection detection and exploitation |
| 9 | **WPScan** | WordPress vulnerability scanning |

---

## Requirements

- **Linux only** (Arch, Debian/Ubuntu/Kali, Fedora/RHEL family — and derivatives)
- **Python 3.8+**
- **Kimi API key** (required for AI analysis, exploitation wizard, and report generation — optional for running tools standalone)

No additional Python packages are required beyond the standard library.

---

## Installation

No installation step is needed. Clone or download the script and run it directly:

```bash
git clone <your-repo>
cd <your-repo>
python3 niixscan.py
```

To pre-install all supported tools in one shot without entering the menu:

```bash
sudo python3 niixscan.py --install-all
```

---

## Usage

### Standard interactive run

```bash
python3 niixscan.py
```

On launch the tool will:
1. Detect your Linux distribution and package manager.
2. Display the main menu with installation status for each tool (`●` = installed, `○` = not installed).
3. Prompt for authorization before any scan is run.

### Main menu options

```
 1–9)  Individual tool sub-menus (run or install/update each tool)
  10)  AI Analysis & Exploitation Centre
   I)  Install ALL tools at once
   S)  Settings (set Kimi API key, output directory, wordlist, Kimi model, API endpoint)
   Q)  Quit
```

### Setting up the Kimi API key

Navigate to **Settings (S)** from the main menu and paste your Kimi API key (create one at https://platform.kimi.ai → API Keys; a $1 top-up unlocks the API). There is no browser/OAuth login for scripts — API-key auth only. The key is saved locally (config file is chmod 600) and loaded automatically on future runs. You can switch the endpoint between api.moonshot.ai (international) and api.moonshot.cn (China), and test the connection, from within the Settings menu.

---

## AI Workflow

### 1 — Run a scan

Select any tool from the main menu, authorize the session, enter the target, and let the scan complete. Output is automatically captured for AI analysis.

### 2 — Analyse with Kimi

Go to **option A → Analyse stored scans with Kimi AI**. Kimi returns a structured JSON report covering:
- Executive summary and OS guess
- Open ports and service versions with risk ratings
- Discovered vulnerabilities with severity, CVE IDs, evidence, and Metasploit module suggestions
- Recommended attack path narrative
- Actionable remediation steps

### 3 — Exploitation wizard

From the AI Analysis Centre, choose **Step-through exploitation wizard**. For each vulnerability Kimi generates:
- A numbered step-by-step exploitation plan
- A complete Metasploit `.rc` resource script ready to execute

At each vulnerability you can: view the plan, edit the `.rc` in your preferred editor, run it via `msfconsole`, or skip to the next one.

### 4 — Generate a pentest report

From the AI Analysis Centre, choose **Generate pentest report**. Kimi writes a formal report covering all findings, saved to the output directory as a timestamped `.txt` file.

---

## Output

All generated files are saved to `~/niixscan-results/` by default (configurable in Settings):

| File | Description |
|---|---|
| `niix_<timestamp>.rc` | Metasploit resource scripts generated per vulnerability |
| `pentest_report_<timestamp>.txt` | Full AI-written pentest report |
| `/tmp/niixscan_msf.log` | Live Metasploit session log (written by `.rc` scripts) |

---

## Notes

- The tool will not start on Windows or macOS.
- The Kimi API key is stored in the local config file (`~/.config/niixscan/config.json`), which the tool sets to owner-only permissions (chmod 600). On shared machines, still protect your home directory.
- Scans requiring raw socket access (e.g. masscan, nmap with OS detection) may need `sudo`.
- The exploitation wizard requires Metasploit to be installed — the tool will offer to install it automatically if `msfconsole` is not found when you attempt to run a `.rc` script.
- AI analysis truncates scan output to 12,000 characters per tool to stay within API limits. For very large scans, consider splitting by target.

---

## v5.0 — What's New

- **Auto Recon Pipeline (P)** — chained subfinder → httpx → nmap (XML) → nuclei → gobuster, all results parsed into a persistent SQLite findings DB.
- **FULL AUTO mode (F / `--auto <target>`)** — pipeline + AI triage + verified Metasploit module suggestions + TXT/HTML reports, one command. Cron-schedulable (`C`) via `--i-have-permission` with scope enforcement still active.
- **Findings Database (V)** — hosts, ports, vulns, cracked credentials in `~/.config/niixscan/findings.db`; feeds the AI, the exploitation wizard, and reports.
- **Scope enforcement** — `~/.config/niixscan/scope.txt` (includes + `!`exclusions); every tool checks every target before sending a single packet.
- **Scan intensity presets** — stealth / normal / aggressive (timing, rates, threads, delays) in Settings.
- **Credential reuse** — Hydra hits are stored and offered automatically to enum4linux-ng and the AI exploitation planner.
- **Ground-truthing** — suggested MSF modules verified against the local Metasploit install; exploit outcomes logged and fed back to the AI so it never repeats a failed approach.
- **Robustness** — per-scan timeouts, block/rate-limit detection, session checkpointing (R to restore), SHA-256 verification of downloaded binaries, install verification.
- **New tools** — httpx, ffuf, enum4linux-ng, testssl.sh (14 total).
- **Reports** — standalone HTML report alongside the AI text report.
- **Proxychains support** — one toggle in Settings.

---

## v5.5 — Max performance update

- **masscan → nmap handoff**: masscan sweeps up to 10k ports at preset rate; nmap `-sV` only touches confirmed-open ports (huge speed win).
- **Auto-escalation**: if the first nmap pass finds nothing, the pipeline automatically reruns a full 65535-port scan.
- **Targeted NSE pass**: `nmap --script vuln` runs against confirmed open ports, parsed into the findings DB.
- **Parallel web stage**: nuclei ∥ gobuster ∥ testssl run concurrently.
- **Targeted follow-ups**: auto-sqlmap on parameterized URLs seen in output, auto-WPScan when WordPress is fingerprinted, credential spraying of cracked creds against SSH/FTP.
- **Auto-exploit retry loop**: up to 3 attempts per vulnerability — every failure is fed back to Kimi, which must change payload/options/strategy before retrying. LPORT auto-selected from free ports; NAT warning when LHOST is private.
- **Stealth preset evasions**: nmap decoys (`-D RND:8`), scan-delay, fragmentation, source-port 53.
- **Run diff**: every pipeline run reports what's NEW (ports/findings/creds since the run started) — ideal for watch-style engagements.
- **Target-list files**: pipeline accepts a file with one target per line (scope-checked per target).
- **Webhook notifications**: Discord/Slack/generic POST on completion and on every opened session.

---

## v5.6 — Purple team update

**Detection Validation mode (main menu D)** — the defensive counterpart to
everything else: instead of attacking targets, it tests YOUR monitoring.

- **12 known, ATT&CK-mapped techniques**: SYN/slow/fragmented/decoy/FIN scans
  (T1046), service probing (T1595.001), HTTP beacon pattern (T1071.001),
  DNS-tunnel pattern (T1071.004), EICAR test-file download (T1105),
  reverse-shell traffic marker (T1059), SSH brute-force pattern (T1110.001),
  base64-encoded command execution (T1027). Techniques are fixed and
  documented by design — detection validation requires known attacks.
- **Unique marker per run** (`NIIXDET-<run>-<technique>`) embedded in the
  traffic — grep your SIEM/EDR/firewall logs for it.
- **Results matrix**: technique × ATT&CK × detected/MISSED/unknown, persisted
  in the findings DB and exported as a report.
- **AI detection-content helper**: for every MISSED technique, Kimi drafts a
  Sigma rule (+ Suricata rule where applicable), saved to your output dir.
- **The loop**: run → find gaps → deploy drafted rules → re-run → gaps should
  flip to 'detected'.
