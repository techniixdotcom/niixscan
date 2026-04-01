# NiiX Scan — niixscan.py

> ⚠ **Legal Notice:** This tool is for authorised penetration testing and security research **only**. Unauthorised use against systems you do not own or have explicit written permission to test is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide. You accept full legal responsibility for your use.

A Python-based interactive security testing framework (v4.0) with an AI-assisted exploitation pipeline powered by the Claude API. It bundles nine common pentest tools into a single terminal UI, automates dependency installation across major Linux distros, and uses Claude to analyse scan output, generate Metasploit resource scripts, and produce professional pentest reports.

*Created by: cuteLiLi / techniix / QuacK*

---

## Features

- **Interactive terminal UI** — colourful menu-driven interface with live progress bars and spinners, no CLI flags required for normal use.
- **Authorization consent gate** — requires explicit target entry and a typed confirmation phrase before any scanning can begin, enforcing a clear authorization checkpoint every session.
- **Nine integrated security tools** — each can be installed, updated, and run directly from the menu.
- **AI Analysis Centre** — sends raw scan output to Claude for structured vulnerability analysis (severity, CVE IDs, Metasploit modules, attack path, and remediation).
- **Step-through exploitation wizard** — walks through each discovered vulnerability one at a time; Claude generates a step-by-step plan and a ready-to-run Metasploit `.rc` resource script per vulnerability.
- **Metasploit integration** — generated `.rc` scripts can be reviewed, edited in `$EDITOR`, and executed via `msfconsole` directly from within the tool.
- **AI pentest report generator** — produces a formal, structured pentest report (Executive Summary, Findings, Risk Matrix, Remediation) saved as a plain-text file.
- **Automatic dependency management** — detects your Linux distro and installs missing tools via the native package manager without manual intervention.
- **Cross-distro support** — works on Arch/Manjaro, Debian/Ubuntu/Kali/Parrot, and Fedora/RHEL/Rocky out of the box.
- **Persistent settings** — API key, output directory, wordlist path, and Claude model are saved to a config file and loaded automatically on next run.

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
- **Claude API key** (required for AI analysis, exploitation wizard, and report generation — optional for running tools standalone)

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
   S)  Settings (set Claude API key, output directory, wordlist, Claude model)
   Q)  Quit
```

### Setting up the Claude API key

Navigate to **Settings (S)** from the main menu and paste your Anthropic API key. The key is saved locally and loaded automatically on future runs. You can test the connection from within the Settings menu.

---

## AI Workflow

### 1 — Run a scan

Select any tool from the main menu, authorize the session, enter the target, and let the scan complete. Output is automatically captured for AI analysis.

### 2 — Analyse with Claude

Go to **option 10 → Analyse stored scans with Claude AI**. Claude returns a structured JSON report covering:
- Executive summary and OS guess
- Open ports and service versions with risk ratings
- Discovered vulnerabilities with severity, CVE IDs, evidence, and Metasploit module suggestions
- Recommended attack path narrative
- Actionable remediation steps

### 3 — Exploitation wizard

From the AI Analysis Centre, choose **Step-through exploitation wizard**. For each vulnerability Claude generates:
- A numbered step-by-step exploitation plan
- A complete Metasploit `.rc` resource script ready to execute

At each vulnerability you can: view the plan, edit the `.rc` in your preferred editor, run it via `msfconsole`, or skip to the next one.

### 4 — Generate a pentest report

From the AI Analysis Centre, choose **Generate pentest report**. Claude writes a formal report covering all findings, saved to the output directory as a timestamped `.txt` file.

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
- The Claude API key is stored in plain text in the local config file (`~/.config/niixscan/config.json` or similar). Restrict access to that file on shared machines.
- Scans requiring raw socket access (e.g. masscan, nmap with OS detection) may need `sudo`.
- The exploitation wizard requires Metasploit to be installed — the tool will offer to install it automatically if `msfconsole` is not found when you attempt to run a `.rc` script.
- AI analysis truncates scan output to 12,000 characters per tool to stay within API limits. For very large scans, consider splitting by target.
