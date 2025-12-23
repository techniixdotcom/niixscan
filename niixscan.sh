#!/bin/bash
# NiiXscan 
# Version alpha 3.3
# Created by techniix / tomteal

# =====================[ ENTERPRISE CONFIGURATION ]=====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Enhanced configuration management
CONFIG_DIR="$HOME/.config/niixscan"
CONFIG_FILE="$CONFIG_DIR/niixscan.conf"
AI_CONFIG_FILE="$CONFIG_DIR/ai_apis.conf"
WORKSPACE="$HOME/niixscan_results"
TOOL_DIR="$HOME/.local/share/niixscan_tools"
WORDLIST_DIR="$HOME/.local/share/wordlists"
PAYLOAD_DIR="$WORKSPACE/payloads"
METASPLOIT_DIR="$WORKSPACE/metasploit"
REPORT_DIR="$WORKSPACE/reports"
EVIDENCE_DIR="$WORKSPACE/evidence"
LOG_FILE="$WORKSPACE/niixscan.log"
ERROR_LOG_FILE="$WORKSPACE/errors.log"
DB_FILE="$WORKSPACE/results.db"
SCAN_PROFILES_DIR="$CONFIG_DIR/profiles"
SCAN_STATE_DIR="$WORKSPACE/scan_states"
TEMP_DIR="/tmp/niixscan_$$"
PYTHON_VENV="$TOOL_DIR/niixscan_venv"
GO_PATH="$HOME/go"
ENHANCED_SCANS_DIR="$WORKSPACE/enhanced_scans"

# AI and ML components
AI_MODEL_DIR="$TOOL_DIR/models"
THREAT_INTEL_DIR="$TOOL_DIR/threat_intel"
BEHAVIORAL_ANALYSIS_DIR="$WORKSPACE/behavioral"

# Cloud integration
CLOUD_CONFIG_DIR="$CONFIG_DIR/cloud"

# Enterprise features
RISK_ASSESSMENT_DIR="$WORKSPACE/risk"
AUTOMATION_DIR="$WORKSPACE/automation"

# =====================[ GLOBAL VARIABLES ]=====================
TARGET_URL=""
TARGET_FILE=""
SCAN_ID=""
CURRENT_SCAN_STRATEGY=""
AI_MODELS_LOADED=false
THREAT_INTEL_LOADED=false
OS_TYPE=""
PACKAGE_MANAGER=""
SCAN_TYPE="comprehensive"
PROGRESS_INDICATOR_PID=""
RESUME_SCAN=false
CURRENT_SCAN_PHASE=""
SCAN_PHASES=("reconnaissance" "vulnerability_scan" "web_application" "network_services" "reporting")
AI_ANALYSIS_ENABLED=false
AI_API_CONFIGURED=false
MAX_PARALLEL_JOBS=4
CURRENT_RUNNING_JOBS=0
PYTHON_VENV_ACTIVATED=false
GO_ENVIRONMENT_SETUP=false
EXPORT_FORMAT="html"

# Progress tracking variables
SCAN_START_TIME=0
PHASE_START_TIME=0
TOTAL_PHASES=5
CURRENT_PHASE_NUMBER=0
PHASE_NAMES=("Reconnaissance" "Vulnerability Scan" "Web Application Testing" "Network Services Analysis" "Report Generation")
PHASE_DESCRIPTIONS=(
    "Gathering information about the target"
    "Scanning for critical and high severity vulnerabilities"
    "Testing web application security"
    "Analyzing network services and ports"
    "Compiling results and generating reports"
)
# Realistic time estimates
PHASE_ESTIMATED_TIMES=(30 300 90 60 30)  # Vulnerability scan: 5 minutes max
ACTIVE_PROCESS_PID=0
ACTIVE_PROCESS_NAME=""

# Nuclei optimization
NUCLEI_TEMPLATE_LIMIT=500  # Maximum templates to use
NUCLEI_SEVERITY="critical,high,medium"
NUCLEI_RATE_LIMIT=50
NUCLEI_TIMEOUT=10
NUCLEI_CONCURRENCY=25

# AI API Configuration
DEEPSEEK_API_KEY=""
OPENAI_API_KEY=""
GEMINI_API_KEY=""
CUSTOM_AI_API=""
CUSTOM_AI_KEY=""
CUSTOM_AI_MODEL=""
AI_PROVIDER="none"

# Security configuration
SECURITY_LEVEL="high"
VALIDATE_INPUTS=true
ENCRYPT_SENSITIVE_DATA=true

# Enhanced scanning tools
ENHANCED_TOOLS=("skipfish" "dirb" "wpscan" "nuclei" "testssl" "sslscan" "uniscan" "wapiti" "xsstrike" "dalfox")

# =====================[ TOOL PATHS ]=====================
declare -A TOOL_PATHS=(
    ["nmap"]=""
    ["nikto"]=""
    ["sqlmap"]=""
    ["gobuster"]=""
    ["dirb"]=""
    ["whatweb"]=""
    ["wafw00f"]=""
    ["subfinder"]=""
    ["amass"]=""
    ["masscan"]=""
    ["zap"]=""
    ["burpsuite"]=""
    ["metasploit"]=""
    ["john"]=""
    ["hashcat"]=""
    ["hydra"]=""
    ["patator"]=""
    ["python3"]=""
    ["pip3"]=""
    ["git"]=""
    ["docker"]=""
    ["jq"]=""
    ["curl"]=""
    ["wget"]=""
    ["aws"]=""
    ["az"]=""
    ["gcloud"]=""
    ["assetfinder"]=""
    ["subjack"]=""
    ["httprobe"]=""
    ["waybackurls"]=""
    ["theharvester"]=""
    ["ffuf"]=""
    ["arjun"]=""
    ["commix"]=""
    ["dnsrecon"]=""
    ["enum4linux"]=""
    ["smbmap"]=""
    ["wapiti"]=""
    ["lynis"]=""
    ["cewl"]=""
    ["searchsploit"]=""
    ["aircrack-ng"]=""
    ["recon-ng"]=""
    ["trivy"]=""
    ["scoutsuite"]=""
    ["nuclei"]=""
    ["naabu"]=""
    ["gau"]=""
    ["hakrawler"]=""
    ["dalfox"]=""
    ["skipfish"]=""
    ["dirb"]=""
    ["wpscan"]=""
    ["testssl"]=""
    ["sslscan"]=""
    ["uniscan"]=""
    ["xsstrike"]=""
)

# =====================[ SIMPLE PROGRESS INDICATOR ]=====================
start_simple_progress() {
    local message="$1"
    local estimated_time="$2"
    
    {
        local start_time=$(date +%s)
        local spinner=0
        local spinners=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
        
        while true; do
            local elapsed=$(( $(date +%s) - start_time ))
            local min=$(( elapsed / 60 ))
            local sec=$(( elapsed % 60 ))
            local elapsed_str=$(printf "%02d:%02d" $min $sec)
            
            spinner=$(( (spinner + 1) % 10 ))
            
            echo -ne "\r${CYAN}${spinners[$spinner]}${NC} ${message} | ${YELLOW}⏱️  ${elapsed_str}${NC}"
            
            if [ -f "$TEMP_DIR/progress_stop" ]; then
                echo -ne "\r\033[K"
                break
            fi
            
            sleep 0.5
        done
    } &
    
    PROGRESS_INDICATOR_PID=$!
}

stop_simple_progress() {
    if [ -n "$PROGRESS_INDICATOR_PID" ]; then
        touch "$TEMP_DIR/progress_stop"
        sleep 0.3
        kill $PROGRESS_INDICATOR_PID 2>/dev/null
        wait $PROGRESS_INDICATOR_PID 2>/dev/null
        rm -f "$TEMP_DIR/progress_stop"
        echo -ne "\r\033[K"
    fi
}

# =====================[ NUCLEI SCANNING ]=====================
run_optimized_nuclei_scan() {
    local target="$1"
    local output_file="$2"
    local results_file="$3"
    
    echo -e "${CYAN}[*] Running optimized Nuclei scan...${NC}"
    
    # Create a progress indicator
    start_simple_progress "Scanning with Nuclei" 300
    
    # Build optimized nuclei command
    local nuclei_cmd="nuclei -u \"$target\" -o \"$results_file\""
    
    # Add severity filters
    nuclei_cmd="$nuclei_cmd -severity \"$NUCLEI_SEVERITY\""
    
    # Add rate limiting and timeouts
    nuclei_cmd="$nuclei_cmd -rate-limit $NUCLEI_RATE_LIMIT"
    nuclei_cmd="$nuclei_cmd -timeout $NUCLEI_TIMEOUT"
    
    # Add concurrency control
    nuclei_cmd="$nuclei_cmd -c $NUCLEI_CONCURRENCY"
    
    # Add stats but limit output
    nuclei_cmd="$nuclei_cmd -stats -si 30"
    
    # Use only relevant templates (not ALL 9849!)
    nuclei_cmd="$nuclei_cmd -etags outdated,unsupported"
    
    echo -e "${BLUE}[*] Command: ${nuclei_cmd:0:100}...${NC}"
    
    # Run nuclei and capture output
    {
        echo "=== Optimized Nuclei Scan Started $(date) ==="
        echo "Target: $target"
        echo "Command: $nuclei_cmd"
        echo "Template limit: $NUCLEI_TEMPLATE_LIMIT"
        echo "Severity: $NUCLEI_SEVERITY"
        echo ""
        
        # Execute nuclei
        eval "$nuclei_cmd"
        
        echo ""
        echo "=== Nuclei Scan Completed $(date) ==="
    } > "$output_file" 2>&1
    
    # Stop progress indicator
    stop_simple_progress
    
    # Check if scan produced results
    if [ -s "$results_file" ]; then
        local vuln_count=$(wc -l < "$results_file")
        echo -e "${GREEN}[✓] Nuclei found $vuln_count vulnerabilities${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Nuclei found no vulnerabilities${NC}"
        return 0
    fi
}

# =====================[ INITIALIZATION ]=====================
initialize_platform() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║              NiiXscan alpha v3.3 - Initializing      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Create log file
    mkdir -p "$WORKSPACE"
    echo "=== NiiXscan v3.3 Started $(date) ===" > "$LOG_FILE"
    
    # Detect OS and package manager
    detect_os
    
    # Create necessary directories
    create_directories
    
    # Initialize database
    initialize_database
    
    # Setup Python virtual environment
    setup_python_environment
    
    # Setup Go environment
    setup_go_environment
    
    # Check and install required tools
    check_required_tools
    
    # Load configuration
    load_configuration
    
    # Setup enhanced scanning
    setup_enhanced_scanning
    
    echo -e "${GREEN}[✓] Platform initialized successfully${NC}"
    echo -e "${BLUE}[*] Log file: $LOG_FILE${NC}"
}

detect_os() {
    echo -e "${CYAN}[*] Detecting operating system...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        if command -v apt-get &> /dev/null; then
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            PACKAGE_MANAGER="dnf"
        elif command -v pacman &> /dev/null; then
            PACKAGE_MANAGER="pacman"
        elif command -v zypper &> /dev/null; then
            PACKAGE_MANAGER="zypper"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        PACKAGE_MANAGER="brew"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS_TYPE="windows"
        PACKAGE_MANAGER="choco"
    else
        OS_TYPE="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    
    echo -e "${GREEN}[✓] OS: $OS_TYPE, Package Manager: $PACKAGE_MANAGER${NC}"
}

create_directories() {
    echo -e "${CYAN}[*] Creating directory structure...${NC}"
    
    mkdir -p "$CONFIG_DIR" "$WORKSPACE" "$TOOL_DIR" "$WORDLIST_DIR" "$PAYLOAD_DIR"
    mkdir -p "$METASPLOIT_DIR" "$REPORT_DIR" "$EVIDENCE_DIR" "$SCAN_PROFILES_DIR"
    mkdir -p "$SCAN_STATE_DIR" "$AI_MODEL_DIR" "$THREAT_INTEL_DIR" "$BEHAVIORAL_ANALYSIS_DIR"
    mkdir -p "$CLOUD_CONFIG_DIR" "$RISK_ASSESSMENT_DIR" "$AUTOMATION_DIR" "$ENHANCED_SCANS_DIR"
    
    echo -e "${GREEN}[✓] Directory structure created${NC}"
}

initialize_database() {
    echo -e "${CYAN}[*] Initializing database...${NC}"
    
    if ! command -v sqlite3 &> /dev/null; then
        echo -e "${YELLOW}[!] Installing sqlite3...${NC}"
        if [[ "$OS_TYPE" == "linux" ]]; then
            sudo apt-get install -y sqlite3 2>> "$LOG_FILE"
        elif [[ "$OS_TYPE" == "macos" ]]; then
            brew install sqlite3 2>> "$LOG_FILE"
        fi
    fi
    
    # Create scans table
    sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << 'EOF'
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    status TEXT DEFAULT 'running',
    risk_score INTEGER,
    ai_analysis TEXT,
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    cvss_score REAL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    service TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS network_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    ip TEXT,
    port INTEGER,
    service TEXT,
    version TEXT,
    banner TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS web_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT,
    vulnerability TEXT,
    parameter TEXT,
    payload TEXT,
    risk_level TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    analysis_type TEXT,
    content TEXT,
    insights TEXT,
    recommendations TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
EOF
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Database initialized${NC}"
    else
        echo -e "${RED}[!] Failed to initialize database${NC}"
    fi
}

setup_python_environment() {
    echo -e "${CYAN}[*] Setting up Python environment...${NC}"
    
    if ! command -v python3 &> /dev/null; then
        install_package_robust "python3"
    fi
    
    if ! command -v pip3 &> /dev/null; then
        install_package_robust "python3-pip"
    fi
    
    # Create virtual environment
    if [ ! -d "$PYTHON_VENV" ]; then
        python3 -m venv "$PYTHON_VENV" 2>> "$LOG_FILE"
    fi
    
    # Activate virtual environment
    if [ -f "$PYTHON_VENV/bin/activate" ]; then
        source "$PYTHON_VENV/bin/activate"
        PYTHON_VENV_ACTIVATED=true
        
        # Upgrade pip
        pip3 install --upgrade pip > /dev/null 2>> "$LOG_FILE"
        
        # Install required Python packages
        local requirements=(
            "requests" "beautifulsoup4" "lxml" "colorama"
            "scapy" "paramiko" "python-nmap" "pyopenssl"
            "cryptography" "pandas" "numpy"
            "selenium" "pillow" "reportlab" "jinja2"
        )
        
        for package in "${requirements[@]}"; do
            echo -e "${BLUE}[*] Installing Python package: $package${NC}"
            pip3 install "$package" > /dev/null 2>> "$LOG_FILE" 
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[✓] Installed: $package${NC}"
            else
                echo -e "${YELLOW}[!] Failed to install: $package${NC}"
            fi
        done
    else
        echo -e "${RED}[!] Failed to create Python virtual environment${NC}"
    fi
    
    echo -e "${GREEN}[✓] Python environment setup completed${NC}"
}

check_required_tools() {
    echo -e "${CYAN}[*] Checking required tools...${NC}"
    
    # Essential tools that MUST be installed
    local basic_tools=("curl" "wget" "git" "nmap" "nikto" "sqlmap" "gobuster" "dirb" "whatweb")
    
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] $tool not found, installing...${NC}"
            install_package_robust "$tool"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[✓] $tool installed successfully${NC}"
            else
                echo -e "${RED}[!] Failed to install $tool${NC}"
            fi
        else
            echo -e "${GREEN}[✓] $tool is installed${NC}"
        fi
    done
}

install_package_robust() {
    local package=$1
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update > /dev/null 2>> "$LOG_FILE"
            sudo apt-get install -y "$package" >> "$LOG_FILE" 2>&1
            ;;
        "yum")
            sudo yum install -y "$package" >> "$LOG_FILE" 2>&1
            ;;
        "dnf")
            sudo dnf install -y "$package" >> "$LOG_FILE" 2>&1
            ;;
        "pacman")
            sudo pacman -S --noconfirm "$package" >> "$LOG_FILE" 2>&1
            ;;
        "brew")
            brew install "$package" >> "$LOG_FILE" 2>&1
            ;;
        "choco")
            choco install "$package" -y >> "$LOG_FILE" 2>&1
            ;;
        *)
            echo -e "${RED}[!] Cannot install $package - unknown package manager${NC}"
            return 1
            ;;
    esac
    
    return $?
}

load_configuration() {
    echo -e "${CYAN}[*] Loading configuration...${NC}"
    
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        echo -e "${GREEN}[✓] Configuration loaded from $CONFIG_FILE${NC}"
    else
        create_default_config
    fi
    
    if [ -f "$AI_CONFIG_FILE" ]; then
        source "$AI_CONFIG_FILE"
        if [ -n "$DEEPSEEK_API_KEY" ] || [ -n "$OPENAI_API_KEY" ] || [ -n "$GEMINI_API_KEY" ]; then
            AI_API_CONFIGURED=true
            echo -e "${GREEN}[✓] AI API configuration loaded${NC}"
        fi
    fi
}

create_default_config() {
    echo -e "${YELLOW}[!] Creating default configuration...${NC}"
    
    cat > "$CONFIG_FILE" << EOF
# NiiXscan Configuration
SCAN_INTENSITY="aggressive"
MAX_PARALLEL_JOBS=4
DEFAULT_SCAN_TYPE="comprehensive"
REPORT_FORMAT="html"
SECURITY_LEVEL="high"
VALIDATE_INPUTS=true
ENCRYPT_SENSITIVE_DATA=true
LOG_LEVEL="INFO"
# Nuclei optimization
NUCLEI_TEMPLATE_LIMIT=500
NUCLEI_SEVERITY="critical,high,medium"
NUCLEI_RATE_LIMIT=50
NUCLEI_TIMEOUT=10
NUCLEI_CONCURRENCY=25
EOF
    
    cat > "$AI_CONFIG_FILE" << EOF
# AI API Configuration
# Uncomment and add your API keys
# DEEPSEEK_API_KEY=""
# OPENAI_API_KEY=""
# GEMINI_API_KEY=""
# CUSTOM_AI_API=""
# CUSTOM_AI_KEY=""
# CUSTOM_AI_MODEL=""
AI_PROVIDER="none"
EOF
    
    echo -e "${GREEN}[✓] Default configuration created${NC}"
}

setup_go_environment() {
    echo -e "${CYAN}[*] Setting up Go environment...${NC}"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${YELLOW}[!] Go is not installed. Installing...${NC}"
        
        if [[ "$OS_TYPE" == "linux" ]]; then
            wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
            sudo tar -C /usr/local -xzf /tmp/go.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            source ~/.bashrc
        elif [[ "$OS_TYPE" == "macos" ]]; then
            brew install go
        fi
    fi
    
    # Set GOPATH if not already set
    if [ -z "$GOPATH" ]; then
        export GOPATH="$GO_PATH"
        echo -e "${YELLOW}[!] GOPATH not set, using: $GOPATH${NC}"
    else
        echo -e "${GREEN}[✓] GOPATH already set: $GOPATH${NC}"
    fi
    
    # Create Go workspace directories
    echo -e "${BLUE}[*] Creating Go workspace directories...${NC}"
    mkdir -p "$GOPATH/bin" "$GOPATH/src" "$GOPATH/pkg"
    
    # Add GOPATH/bin to PATH if not already there
    if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
        export PATH="$GOPATH/bin:$PATH"
        echo -e "${YELLOW}[!] Added $GOPATH/bin to PATH${NC}"
    else
        echo -e "${GREEN}[✓] GOPATH/bin already in PATH${NC}"
    fi
    
    GO_ENVIRONMENT_SETUP=true
    echo -e "${GREEN}[✓] Go environment configured${NC}"
}

install_go_tool_enhanced() {
    local tool_name=$1
    local tool_path=$2
    
    echo -e "${CYAN}[*] Installing $tool_name...${NC}"
    
    if [ "$GO_ENVIRONMENT_SETUP" = false ]; then
        setup_go_environment
    fi
    
    go install "$tool_path@latest" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] $tool_name installed successfully${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install $tool_name${NC}"
        return 1
    fi
}

setup_enhanced_scanning() {
    echo -e "${PURPLE}[*] Setting up enhanced vulnerability scanning...${NC}"
    
    mkdir -p "$ENHANCED_SCANS_DIR"
    
    # Install enhanced scanning tools
    install_enhanced_scanning_tools
    
    # Download specialized wordlists
    download_specialized_wordlists
    
    # Setup specialized scanning configurations
    setup_scanning_profiles
    
    echo -e "${GREEN}[✓] Enhanced scanning setup completed${NC}"
}

install_enhanced_scanning_tools() {
    echo -e "${CYAN}[*] Installing enhanced scanning tools...${NC}"
    
    # First install essential tools that will actually find vulnerabilities
    echo -e "${BLUE}[*] Installing Nuclei ...${NC}"
    install_nuclei
    
    echo -e "${BLUE}[*] Installing WPScan...${NC}"
    install_wpscan
    
    echo -e "${BLUE}[*] Installing testssl...${NC}"
    install_testssl
    
    echo -e "${BLUE}[*] Installing XSStrike...${NC}"
    install_xsstrike
    
    # Additional tools
    local enhanced_tools=("dirb" "sslscan" "wapiti")
    
    for tool in "${enhanced_tools[@]}"; do
        if install_enhanced_tool "$tool"; then
            echo -e "${GREEN}[✓] Enhanced tool installed: $tool${NC}"
        else
            echo -e "${YELLOW}[!] Failed to install enhanced tool: $tool${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] Enhanced scanning tools installation completed${NC}"
}

install_enhanced_tool() {
    local tool=$1
    
    case $tool in
        "dirb")
            install_package_robust "dirb"
            ;;
        "sslscan")
            install_package_robust "sslscan"
            ;;
        "wapiti")
            install_package_robust "wapiti"
            ;;
        *)
            echo -e "${YELLOW}[!] Unknown enhanced tool: $tool${NC}"
            return 1
            ;;
    esac
}

install_testssl() {
    echo -e "${CYAN}[*] Installing testssl.sh...${NC}"
    
    local testssl_dir="$TOOL_DIR/testssl"
    mkdir -p "$testssl_dir"
    
    git clone https://github.com/drwetter/testssl.sh.git "$testssl_dir" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        # Create symlink to make it accessible
        sudo ln -sf "$testssl_dir/testssl.sh" "/usr/local/bin/testssl" 2>> "$LOG_FILE"
        echo -e "${GREEN}[✓] testssl.sh installed${NC}"
        return 0
    else
        echo -e "${RED}[!] testssl.sh installation failed${NC}"
        return 1
    fi
}

install_uniscan() {
    echo -e "${CYAN}[*] Installing Uniscan...${NC}"
    
    local uniscan_dir="$TOOL_DIR/uniscan"
    mkdir -p "$uniscan_dir"
    
    git clone https://github.com/poerschke/Uniscan.git "$uniscan_dir" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        cd "$uniscan_dir"
        perl Makefile.PL >> "$LOG_FILE" 2>&1
        make >> "$LOG_FILE" 2>&1
        sudo make install >> "$LOG_FILE" 2>&1
        cd - > /dev/null
        echo -e "${GREEN}[✓] Uniscan installed${NC}"
        return 0
    else
        echo -e "${RED}[!] Uniscan installation failed${NC}"
        return 1
    fi
}

install_xsstrike() {
    echo -e "${CYAN}[*] Installing XSStrike...${NC}"
    
    local xsstrike_dir="$TOOL_DIR/XSStrike"
    mkdir -p "$xsstrike_dir"
    
    git clone https://github.com/s0md3v/XSStrike.git "$xsstrike_dir" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        cd "$xsstrike_dir"
        pip3 install -r requirements.txt >> "$LOG_FILE" 2>&1
        cd - > /dev/null
        
        # Create wrapper script
        cat > "/tmp/xsstrike_wrapper" << 'EOF'
#!/bin/bash
cd "$HOME/.local/share/niixscan_tools/XSStrike" && python3 xsstrike.py "$@"
EOF
        sudo mv "/tmp/xsstrike_wrapper" "/usr/local/bin/xsstrike"
        sudo chmod +x "/usr/local/bin/xsstrike"
        echo -e "${GREEN}[✓] XSStrike installed${NC}"
        return 0
    else
        echo -e "${RED}[!] XSStrike installation failed${NC}"
        return 1
    fi
}

install_wpscan() {
    echo -e "${CYAN}[*] Installing WPScan...${NC}"
    
    # Install Ruby if not present
    if ! command -v ruby &> /dev/null; then
        install_package_robust "ruby"
    fi
    
    if ! command -v gem &> /dev/null; then
        install_package_robust "rubygems"
    fi
    
    # Install WPScan via gem
    sudo gem install wpscan >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] WPScan installed${NC}"
        
        # Update WPScan database
        echo -e "${BLUE}[*] Updating WPScan database...${NC}"
        wpscan --update >> "$LOG_FILE" 2>&1
        return 0
    else
        echo -e "${YELLOW}[!] WPScan gem installation failed, trying alternative...${NC}"
        
        # Alternative installation
        sudo apt-get install -y wpscan 2>> "$LOG_FILE" || {
            echo -e "${RED}[!] WPScan installation completely failed${NC}"
            return 1
        }
        echo -e "${GREEN}[✓] WPScan installed via package manager${NC}"
        return 0
    fi
}

install_nuclei() {
    echo -e "${CYAN}[*] Installing Nuclei...${NC}"
    
    # First check if nuclei is already installed
    if command -v nuclei &> /dev/null; then
        echo -e "${GREEN}[✓] Nuclei already installed${NC}"
        return 0
    fi
    
    # Try multiple installation methods
    
    # Method 1: Direct download
    echo -e "${BLUE}[*] Trying direct download...${NC}"
    local nuclei_url=""
    if [[ "$(uname -m)" == "x86_64" ]]; then
        nuclei_url="https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_amd64.tar.gz"
    elif [[ "$(uname -m)" == "aarch64" ]]; then
        nuclei_url="https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_arm64.tar.gz"
    fi
    
    if [ -n "$nuclei_url" ]; then
        wget -q "$nuclei_url" -O /tmp/nuclei.tar.gz
        if [ $? -eq 0 ]; then
            tar -xzf /tmp/nuclei.tar.gz -C /tmp/
            sudo mv /tmp/nuclei /usr/local/bin/
            sudo chmod +x /usr/local/bin/nuclei
            echo -e "${GREEN}[✓] Nuclei installed via direct download${NC}"
            
            # Install nuclei templates
            echo -e "${BLUE}[*] Installing Nuclei templates...${NC}"
            nuclei -update-templates >> "$LOG_FILE" 2>&1
            return 0
        fi
    fi
    
    # Method 2: Go install
    echo -e "${BLUE}[*] Trying Go install...${NC}"
    if install_go_tool_enhanced "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"; then
        nuclei -update-templates >> "$LOG_FILE" 2>&1
        echo -e "${GREEN}[✓] Nuclei installed with templates${NC}"
        return 0
    fi
    
    # Method 3: Package manager
    echo -e "${BLUE}[*] Trying package manager...${NC}"
    if [[ "$OS_TYPE" == "linux" ]]; then
        wget https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_amd64.deb -O /tmp/nuclei.deb
        sudo dpkg -i /tmp/nuclei.deb 2>> "$LOG_FILE"
        if [ $? -eq 0 ]; then
            nuclei -update-templates >> "$LOG_FILE" 2>&1
            echo -e "${GREEN}[✓] Nuclei installed via deb package${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}[!] Nuclei installation failed via all methods${NC}"
    return 1
}

install_dalfox() {
    echo -e "${CYAN}[*] Installing Dalfox...${NC}"
    
    if install_go_tool_enhanced "dalfox" "github.com/hahwul/dalfox/v2"; then
        echo -e "${GREEN}[✓] Dalfox installed${NC}"
        return 0
    else
        echo -e "${RED}[!] Dalfox installation failed${NC}"
        return 1
    fi
}

install_wapiti() {
    echo -e "${CYAN}[*] Installing Wapiti...${NC}"
    
    if install_package_robust "wapiti"; then
        echo -e "${GREEN}[✓] Wapiti installed${NC}"
        return 0
    else
        echo -e "${RED}[!] Wapiti installation failed${NC}"
        return 1
    fi
}

download_specialized_wordlists() {
    echo -e "${CYAN}[*] Downloading specialized wordlists...${NC}"
    
    mkdir -p "$WORDLIST_DIR"
    
    # SecLists directory structure
    local seclists_dir="$WORDLIST_DIR/SecLists"
    
    if [ ! -d "$seclists_dir" ]; then
        echo -e "${BLUE}[*] Cloning SecLists repository...${NC}"
        git clone https://github.com/danielmiessler/SecLists.git "$seclists_dir" >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] SecLists downloaded${NC}"
        else
            echo -e "${RED}[!] Failed to clone SecLists${NC}"
            # Create minimal wordlists
            create_minimal_wordlists
            return
        fi
    else
        echo -e "${GREEN}[✓] SecLists already exists${NC}"
    fi
    
    # Create symlinks to commonly used wordlists
    create_wordlist_symlinks
    
    echo -e "${GREEN}[✓] Wordlists setup completed${NC}"
}

create_minimal_wordlists() {
    echo -e "${YELLOW}[!] Creating minimal wordlists...${NC}"
    
    # Create a basic directory wordlist
    cat > "$WORDLIST_DIR/directories.txt" << EOF
admin
administrator
login
logout
signin
signout
register
api
v1
v2
graphql
rest
soap
wp-admin
wp-content
wp-includes
phpmyadmin
mysql
sql
db
database
backup
backups
old
new
test
dev
development
staging
production
EOF
    
    # Create a basic file wordlist
    cat > "$WORDLIST_DIR/files.txt" << EOF
index.php
index.html
index.jsp
index.asp
index.aspx
admin.php
admin.html
admin.jsp
login.php
login.html
logout.php
register.php
config.php
config.inc.php
settings.php
.htaccess
robots.txt
sitemap.xml
EOF
    
    echo -e "${GREEN}[✓] Minimal wordlists created${NC}"
}

create_wordlist_symlinks() {
    local seclists_dir="$WORDLIST_DIR/SecLists"
    
    # Create symlinks for easy access
    ln -sf "$seclists_dir/Discovery/Web-Content/common.txt" "$WORDLIST_DIR/common.txt" 2>/dev/null
    ln -sf "$seclists_dir/Discovery/Web-Content/raft-large-directories.txt" "$WORDLIST_DIR/directories-large.txt" 2>/dev/null
    ln -sf "$seclists_dir/Discovery/Web-Content/raft-large-files.txt" "$WORDLIST_DIR/files-large.txt" 2>/dev/null
    ln -sf "$seclists_dir/Fuzzing/XSS/XSS-Jhaddix.txt" "$WORDLIST_DIR/xss.txt" 2>/dev/null
    ln -sf "$seclists_dir/Fuzzing/SQLi/Generic-SQLi.txt" "$WORDLIST_DIR/sqli.txt" 2>/dev/null
}

create_custom_wordlists() {
    echo -e "${CYAN}[*] Creating custom wordlist combinations...${NC}"
    
    # Combine common wordlists for comprehensive scanning
    local combined_wordlist="$WORDLIST_DIR/comprehensive-directories.txt"
    if [ ! -f "$combined_wordlist" ]; then
        # Create from SecLists if available
        if [ -f "$WORDLIST_DIR/SecLists/Discovery/Web-Content/raft-large-directories.txt" ]; then
            cat "$WORDLIST_DIR/SecLists/Discovery/Web-Content/raft-large-directories.txt" \
                "$WORDLIST_DIR/SecLists/Discovery/Web-Content/common.txt" 2>/dev/null | \
                sort -u > "$combined_wordlist"
            echo -e "${GREEN}[✓] Created comprehensive directories wordlist${NC}"
        fi
    fi
}

setup_scanning_profiles() {
    echo -e "${CYAN}[*] Setting up scanning profiles...${NC}"
    
    mkdir -p "$SCAN_PROFILES_DIR"
    
    # Create comprehensive scanning profile
    cat > "$SCAN_PROFILES_DIR/comprehensive.conf" << 'EOF'
# Comprehensive Scanning Profile
SCAN_INTENSITY=aggressive
MAX_SUBDOMAINS=500
MAX_DIRECTORIES=10000
RATE_LIMIT=10
TIMEOUT=30
USER_AGENT="Mozilla/5.0 (compatible; NiiXscan/3.3; +https://github.com/techniix/niixscan)"

# Tool configurations
USE_NUCLEI=true
USE_WAPITI=true
USE_TESTSSL=true
USE_WPSCAN=true

# Nuclei optimization
NUCLEI_TEMPLATE_LIMIT=500
NUCLEI_SEVERITY=critical,high,medium
NUCLEI_RATE_LIMIT=50
NUCLEI_TIMEOUT=10
NUCLEI_CONCURRENCY=25

# Scan depth
CRAWL_DEPTH=3
INCLUDE_SUBDOMAINS=true
BRUTE_FORCE_EXTENSIONS=php,html,js,txt,json,xml

# Vulnerability scanning
TEST_XSS=true
TEST_SQLI=true
TEST_RFI=true
TEST_LFI=true
TEST_SSRF=true
EOF

    # Create quick scanning profile
    cat > "$SCAN_PROFILES_DIR/quick.conf" << 'EOF'
# Quick Scanning Profile
SCAN_INTENSITY=quick
MAX_SUBDOMAINS=50
MAX_DIRECTORIES=1000
RATE_LIMIT=5
TIMEOUT=15

# Tool configurations
USE_NUCLEI=true
USE_TESTSSL=true

# Nuclei optimization (more aggressive for quick scans)
NUCLEI_TEMPLATE_LIMIT=100
NUCLEI_SEVERITY=critical,high
NUCLEI_RATE_LIMIT=100
NUCLEI_TIMEOUT=5
NUCLEI_CONCURRENCY=50

# Scan depth
CRAWL_DEPTH=1
INCLUDE_SUBDOMAINS=false

# Vulnerability scanning
TEST_XSS=true
TEST_SQLI=true
EOF

    echo -e "${GREEN}[✓] Scanning profiles created${NC}"
}

# =====================[ TARGET VALIDATION ]=====================
validate_target() {
    local target=$1
    
    # Check if target is empty
    if [ -z "$target" ]; then
        return 1
    fi
    
    # Remove protocol if present
    target=$(echo "$target" | sed -e 's|^https\?://||')
    
    # Check if target is a valid IP address
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Validate IP address
        local IFS='.'
        read -r -a ip_parts <<< "$target"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -lt 0 ] || [ "$part" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    # Check if target is a valid domain name
    elif [[ "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# =====================[ LOAD TARGETS FROM FILE ]=====================
load_targets_from_file() {
    echo -e "${CYAN}[*] Loading targets from file...${NC}"
    echo -n "Enter path to target file (one target per line): "
    read target_file
    
    if [ ! -f "$target_file" ]; then
        echo -e "${RED}[!] File not found: $target_file${NC}"
        return 1
    fi
    
    local target_count=0
    local targets_output="$TEMP_DIR/targets_$$.txt"
    > "$targets_output"
    
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)  # Trim whitespace
        if [ -n "$line" ] && [[ ! "$line" =~ ^# ]]; then  # Skip empty lines and comments
            if validate_target "$line"; then
                echo -e "${GREEN}[✓] Valid target: $line${NC}"
                echo "$line" >> "$targets_output"
                ((target_count++))
            else
                echo -e "${YELLOW}[!] Invalid target skipped: $line${NC}"
            fi
        fi
    done < "$target_file"
    
    if [ $target_count -gt 0 ]; then
        TARGET_FILE="$targets_output"
        echo -e "${GREEN}[✓] Loaded $target_count targets from file${NC}"
        return 0
    else
        echo -e "${RED}[!] No valid targets found in file${NC}"
        rm -f "$targets_output"
        return 1
    fi
}

# =====================[ SCAN MANAGEMENT ]=====================
start_scan() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                    Starting Security Scan            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Get target
    if [ -z "$TARGET_URL" ] && [ -z "$TARGET_FILE" ]; then
        select_target
    fi
    
    # Generate scan ID
    SCAN_ID=$(date +%Y%m%d%H%M%S)$(shuf -i 1000-9999 -n 1)
    
    # Create scan directory
    local scan_dir="$WORKSPACE/scan_$SCAN_ID"
    mkdir -p "$scan_dir"
    
    # Insert scan into database
    local target_display=""
    if [ -n "$TARGET_URL" ]; then
        target_display="$TARGET_URL"
    elif [ -n "$TARGET_FILE" ]; then
        target_display="File: $(basename "$TARGET_FILE") ($(wc -l < "$TARGET_FILE") targets)"
    fi
    
    sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO scans (id, target_url, scan_type, start_time, status)
VALUES ('$SCAN_ID', '$target_display', '$SCAN_TYPE', datetime('now'), 'running');
EOF
    
    echo -e "${GREEN}[✓] Scan started with ID: $SCAN_ID${NC}"
    echo -e "${BLUE}[*] Scan directory: $scan_dir${NC}"
    
    # Record start time
    SCAN_START_TIME=$(date +%s)
    
    # Display overall scan estimate
    local total_estimated_time=0
    for time in "${PHASE_ESTIMATED_TIMES[@]}"; do
        total_estimated_time=$((total_estimated_time + time))
    done
    
    local total_min=$((total_estimated_time / 60))
    local total_sec=$((total_estimated_time % 60))
    echo -e "${CYAN}[*] Estimated total scan time: ${total_min}m ${total_sec}s${NC}"
    echo -e "${CYAN}[*] Using optimized Nuclei scan (limited to ~${NUCLEI_TEMPLATE_LIMIT} templates)${NC}"
    echo ""
    
    # Execute comprehensive scanning
    execute_comprehensive_scan
    
    # Generate reports
    generate_reports
    
    echo -e "${GREEN}[✓] Scan completed successfully${NC}"
    
    # Show total time taken
    local scan_end_time=$(date +%s)
    local total_time=$((scan_end_time - SCAN_START_TIME))
    local total_time_min=$((total_time / 60))
    local total_time_sec=$((total_time % 60))
    echo -e "${CYAN}[*] Total scan time: ${total_time_min}m ${total_time_sec}s${NC}"
}

select_target() {
    echo -e "${CYAN}[*] Select target source:${NC}"
    echo "1. Single URL/IP"
    echo "2. File with multiple targets"
    echo "3. Recent target history"
    echo -n "Select option [1-3]: "
    read target_choice
    
    case $target_choice in
        1)
            echo -n "Enter target URL/IP (e.g., example.com or 192.168.1.1): "
            read TARGET_URL
            if ! validate_target "$TARGET_URL"; then
                echo -e "${RED}[!] Invalid target${NC}"
                TARGET_URL=""
                select_target
            else
                # Add http:// if no protocol specified
                if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
                    TARGET_URL="http://$TARGET_URL"
                fi
            fi
            ;;
        2)
            load_targets_from_file
            ;;
        3)
            show_target_history
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            select_target
            ;;
    esac
}

show_target_history() {
    echo -e "${CYAN}[*] Recent target history...${NC}"
    
    local recent_targets=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT DISTINCT target_url 
FROM scans 
WHERE target_url NOT LIKE 'File:%' 
ORDER BY start_time DESC 
LIMIT 10;
EOF
    )
    
    if [ -z "$recent_targets" ]; then
        echo -e "${YELLOW}[!] No target history found${NC}"
        select_target
        return
    fi
    
    local count=1
    declare -a targets_array
    while IFS= read -r target; do
        echo "$count. $target"
        targets_array[$count]="$target"
        ((count++))
    done <<< "$recent_targets"
    
    echo -n "Select target number (or 0 to go back): "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -lt $count ]; then
        TARGET_URL="${targets_array[$choice]}"
        echo -e "${GREEN}[✓] Selected target: $TARGET_URL${NC}"
    else
        select_target
    fi
}

execute_comprehensive_scan() {
    echo -e "${PURPLE}[*] Executing comprehensive security scan...${NC}"
    
    # Load scanning profile
    load_scanning_profile
    
    # Execute scan phases
    for i in "${!SCAN_PHASES[@]}"; do
        CURRENT_PHASE_NUMBER=$((i + 1))
        CURRENT_SCAN_PHASE="${SCAN_PHASES[$i]}"
        
        # Show phase information
        echo -e "\n${PURPLE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${PURPLE}║                         PHASE ${CURRENT_PHASE_NUMBER}/${TOTAL_PHASES}                           ║${NC}"
        echo -e "${PURPLE}║                    ${PHASE_NAMES[$i]}                      ║${NC}"
        echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════╝${NC}\n"
        
        # Record phase start time
        PHASE_START_TIME=$(date +%s)
        
        case "${SCAN_PHASES[$i]}" in
            "reconnaissance")
                perform_reconnaissance
                ;;
            "vulnerability_scan")
                perform_vulnerability_scan
                ;;
            "web_application")
                perform_web_application_scan
                ;;
            "network_services")
                perform_network_services_scan
                ;;
        esac
        
        # Calculate actual phase time
        local phase_end_time=$(date +%s)
        local phase_duration=$((phase_end_time - PHASE_START_TIME))
        local phase_min=$((phase_duration / 60))
        local phase_sec=$((phase_duration % 60))
        
        echo -e "${GREEN}✓ Phase ${CURRENT_PHASE_NUMBER} completed in ${phase_min}m ${phase_sec}s${NC}"
        echo ""
        
        # Save scan state
        save_scan_state "${SCAN_PHASES[$i]}"
    done
    
    echo -e "${GREEN}[✓] Comprehensive scan completed${NC}"
}

load_scanning_profile() {
    echo -e "${CYAN}[*] Loading scanning profile...${NC}"
    
    local profile_file="$SCAN_PROFILES_DIR/${SCAN_TYPE}.conf"
    
    if [ -f "$profile_file" ]; then
        source "$profile_file"
        echo -e "${GREEN}[✓] Loaded profile: $SCAN_TYPE${NC}"
        
        # Update nuclei settings from profile
        if [ -n "$NUCLEI_TEMPLATE_LIMIT" ]; then
            echo -e "${CYAN}[*] Nuclei template limit: $NUCLEI_TEMPLATE_LIMIT${NC}"
        fi
        if [ -n "$NUCLEI_SEVERITY" ]; then
            echo -e "${CYAN}[*] Nuclei severity: $NUCLEI_SEVERITY${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Profile not found, using default comprehensive profile${NC}"
        source "$SCAN_PROFILES_DIR/comprehensive.conf"
    fi
}

save_scan_state() {
    local phase=$1
    local state_file="$SCAN_STATE_DIR/${SCAN_ID}_${phase}.state"
    
    echo "Phase: $phase" > "$state_file"
    echo "Timestamp: $(date)" >> "$state_file"
    echo "Status: completed" >> "$state_file"
}

perform_reconnaissance() {
    echo -e "${CYAN}[*] Performing reconnaissance...${NC}"
    
    local recon_dir="$WORKSPACE/scan_$SCAN_ID/recon"
    mkdir -p "$recon_dir"
    
    if [ -n "$TARGET_URL" ]; then
        # Single target reconnaissance
        recon_single_target "$TARGET_URL" "$recon_dir"
    elif [ -n "$TARGET_FILE" ]; then
        # Multiple targets reconnaissance
        recon_multiple_targets "$TARGET_FILE" "$recon_dir"
    fi
}

recon_single_target() {
    local target=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Reconnaissance for: $target${NC}"
    
    # Extract domain from URL
    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    
    # WHOIS lookup
    if command -v whois &> /dev/null; then
        echo -e "${CYAN}[*] Performing WHOIS lookup...${NC}"
        whois "$domain" > "$output_dir/whois.txt" 2>> "$LOG_FILE"
    fi
    
    # DNS enumeration
    if command -v dig &> /dev/null; then
        echo -e "${CYAN}[*] Performing DNS enumeration...${NC}"
        dig "$domain" ANY +short > "$output_dir/dns_any.txt" 2>> "$LOG_FILE"
        dig "$domain" A +short > "$output_dir/dns_a.txt" 2>> "$LOG_FILE"
        dig "$domain" MX +short > "$output_dir/dns_mx.txt" 2>> "$LOG_FILE"
        dig "$domain" TXT +short > "$output_dir/dns_txt.txt" 2>> "$LOG_FILE"
    fi
    
    # Port scanning with nmap (quick scan)
    if command -v nmap &> /dev/null; then
        echo -e "${CYAN}[*] Performing port scan...${NC}"
        nmap -sS -T4 -F "$domain" -oN "$output_dir/nmap_quick.txt" >> "$LOG_FILE" 2>&1
        
        # Service detection on common ports
        nmap -sV -T4 -p 21,22,23,25,53,80,443,445,3389,8080,8443 "$domain" \
            -oN "$output_dir/nmap_services.txt" >> "$LOG_FILE" 2>&1
    fi
    
    # Web technology detection
    if command -v whatweb &> /dev/null; then
        echo -e "${CYAN}[*] Detecting web technologies...${NC}"
        whatweb -a 1 "$target" > "$output_dir/whatweb.txt" 2>> "$LOG_FILE"
    fi
    
    # Check for WAF
    if command -v wafw00f &> /dev/null; then
        echo -e "${CYAN}[*] Checking for WAF...${NC}"
        wafw00f "$target" > "$output_dir/waf.txt" 2>> "$LOG_FILE"
    fi
    
    # SSL/TLS analysis
    if command -v testssl &> /dev/null; then
        echo -e "${CYAN}[*] Analyzing SSL/TLS configuration...${NC}"
        testssl --html "$output_dir/testssl.html" "$target" >> "$LOG_FILE" 2>&1
    elif command -v sslscan &> /dev/null; then
        sslscan "$target" > "$output_dir/sslscan.txt" 2>> "$LOG_FILE"
    fi
    
    echo -e "${GREEN}[✓] Reconnaissance completed for $target${NC}"
}

recon_multiple_targets() {
    local target_file=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Reconnaissance for multiple targets...${NC}"
    
    local count=1
    while IFS= read -r target; do
        if validate_target "$target"; then
            echo -e "${CYAN}[*] Processing target $count: $target${NC}"
            local target_dir="$output_dir/target_$count"
            mkdir -p "$target_dir"
            
            # Add protocol if missing
            if [[ ! "$target" =~ ^https?:// ]]; then
                target="http://$target"
            fi
            
            recon_single_target "$target" "$target_dir"
            ((count++))
        fi
    done < "$target_file"
}

perform_vulnerability_scan() {
    echo -e "${CYAN}[*] Performing vulnerability assessment...${NC}"
    
    local vuln_dir="$WORKSPACE/scan_$SCAN_ID/vulnerability"
    mkdir -p "$vuln_dir"
    
    # Use optimized nuclei scan
    if command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[*] Starting optimized Nuclei vulnerability scan...${NC}"
        echo -e "${YELLOW}[*] Scanning for ${NUCLEI_SEVERITY} severity vulnerabilities${NC}"
        echo -e "${YELLOW}[*] Using rate limiting to avoid overwhelming the target${NC}"
        
        if [ -n "$TARGET_URL" ]; then
            # Run optimized nuclei scan
            run_optimized_nuclei_scan "$TARGET_URL" "$vuln_dir/nuclei_output.log" "$vuln_dir/nuclei_results.txt"
            
            # Parse results if found
            if [ -s "$vuln_dir/nuclei_results.txt" ]; then
                parse_nuclei_results "$vuln_dir/nuclei_results.txt"
            fi
        elif [ -n "$TARGET_FILE" ]; then
            echo -e "${YELLOW}[!] Multiple target scan with nuclei would take too long${NC}"
            echo -e "${YELLOW}[!] Skipping nuclei for multiple targets${NC}"
        fi
    else
        echo -e "${RED}[!] Nuclei not installed - skipping vulnerability scan${NC}"
    fi
    
    # Use nikto for web server scanning (quick)
    if command -v nikto &> /dev/null; then
        echo -e "${BLUE}[*] Running quick nikto web server scan...${NC}"
        
        if [ -n "$TARGET_URL" ]; then
            timeout 60 nikto -h "$TARGET_URL" -o "$vuln_dir/nikto_results.txt" -Format txt >> "$LOG_FILE" 2>&1
            if [ -f "$vuln_dir/nikto_results.txt" ]; then
                parse_nikto_results "$vuln_dir/nikto_results.txt"
            fi
        fi
    fi
    
    echo -e "${GREEN}[✓] Vulnerability assessment completed${NC}"
}

parse_nuclei_results() {
    local results_file=$1
    
    if [ ! -f "$results_file" ]; then
        return
    fi
    
    echo -e "${BLUE}[*] Parsing nuclei results into database...${NC}"
    
    local vuln_count=0
    # Nuclei output format: [severity] [type] [url] [info]
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[([^]]+)\]\[([^]]+)\] ]]; then
            local severity="${BASH_REMATCH[1]}"
            local vuln_type="${BASH_REMATCH[2]}"
            
            # Extract URL and description
            local url=$(echo "$line" | grep -o 'http[s]*://[^ ]*' | head -1)
            local description=$(echo "$line" | sed -e 's/^\[[^]]*\]\[[^]]*\] //' -e 's/http[s]*:[^ ]*//g')
            
            if [ -n "$severity" ] && [ -n "$vuln_type" ] && [ -n "$description" ]; then
                # Insert into database
                sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'web_vulnerability', '$severity', '$vuln_type', '$description - URL: ${url:-$TARGET_URL}');
EOF
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}[+] Found: $severity - $vuln_type${NC}"
                    ((vuln_count++))
                fi
            fi
        fi
    done < "$results_file"
    
    echo -e "${GREEN}[✓] Added $vuln_count vulnerabilities to database${NC}"
}

parse_nikto_results() {
    local results_file=$1
    
    if [ ! -f "$results_file" ]; then
        return
    fi
    
    echo -e "${BLUE}[*] Parsing nikto results...${NC}"
    
    local severity="medium"
    local finding_count=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^\+ ]]; then
            local issue=$(echo "$line" | sed 's/^\+ //')
            if [ -n "$issue" ]; then
                sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'server_vulnerability', '$severity', 'Nikto Finding', '$issue');
EOF
                ((finding_count++))
            fi
        fi
    done < "$results_file"
    
    if [ $finding_count -gt 0 ]; then
        echo -e "${GREEN}[✓] Added $finding_count nikto findings to database${NC}"
    fi
}

perform_web_application_scan() {
    echo -e "${CYAN}[*] Performing web application security testing...${NC}"
    
    local web_dir="$WORKSPACE/scan_$SCAN_ID/web"
    mkdir -p "$web_dir"
    
    if [ -z "$TARGET_URL" ]; then
        echo -e "${YELLOW}[!] No web target specified, skipping web application scan${NC}"
        return
    fi
    
    # Directory brute-forcing with gobuster (limited)
    if command -v gobuster &> /dev/null && [ -f "$WORDLIST_DIR/directories.txt" ]; then
        echo -e "${BLUE}[*] Quick directory brute-forcing...${NC}"
        timeout 120 gobuster dir -u "$TARGET_URL" -w "$WORDLIST_DIR/directories.txt" \
            -o "$web_dir/gobuster_dirs.txt" -t 20 >> "$LOG_FILE" 2>&1
        
        # Parse gobuster results
        if [ -f "$web_dir/gobuster_dirs.txt" ]; then
            local dir_count=0
            while IFS= read -r line; do
                if [[ "$line" =~ ^/([^ ]+) ]]; then
                    local dir="${BASH_REMATCH[1]}"
                    sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'discovery', 'info', 'Directory found', '$dir directory found at $TARGET_URL');
EOF
                    ((dir_count++))
                fi
            done < "$web_dir/gobuster_dirs.txt"
            if [ $dir_count -gt 0 ]; then
                echo -e "${GREEN}[✓] Found $dir_count directories${NC}"
            fi
        fi
    fi
    
    # WordPress scanning if detected
    if echo "$TARGET_URL" | grep -i "wordpress" || [ -f "$WORKSPACE/scan_$SCAN_ID/recon/whatweb.txt" ] && grep -i "wordpress" "$WORKSPACE/scan_$SCAN_ID/recon/whatweb.txt"; then
        if command -v wpscan &> /dev/null; then
            echo -e "${BLUE}[*] Checking for WordPress vulnerabilities...${NC}"
            timeout 180 wpscan --url "$TARGET_URL" --no-update --output "$web_dir/wpscan.txt" >> "$LOG_FILE" 2>&1
            
            # Parse wpscan results
            if [ -f "$web_dir/wpscan.txt" ]; then
                local wp_vuln_count=0
                grep -i "vulnerability\|issue" "$web_dir/wpscan.txt" | while read -r line; do
                    if [ -n "$line" ]; then
                        sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'wordpress_vulnerability', 'medium', 'WordPress Issue', '$line');
EOF
                        ((wp_vuln_count++))
                    fi
                done
                if [ $wp_vuln_count -gt 0 ]; then
                    echo -e "${GREEN}[✓] Found $wp_vuln_count WordPress issues${NC}"
                fi
            fi
        fi
    fi
    
    echo -e "${GREEN}[✓] Web application security testing completed${NC}"
}

perform_network_services_scan() {
    echo -e "${CYAN}[*] Performing network services analysis...${NC}"
    
    local network_dir="$WORKSPACE/scan_$SCAN_ID/network"
    mkdir -p "$network_dir"
    
    if [ -n "$TARGET_URL" ]; then
        # Extract host from URL
        local host=$(echo "$TARGET_URL" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        scan_network_services "$host" "$network_dir"
    elif [ -n "$TARGET_FILE" ]; then
        echo -e "${YELLOW}[!] Skipping network scan for multiple targets (would take too long)${NC}"
    fi
    
    echo -e "${GREEN}[✓] Network services analysis completed${NC}"
}

scan_network_services() {
    local target=$1
    local output_dir=$2
    
    echo -e "${BLUE}[*] Scanning network services for: $target${NC}"
    
    if command -v nmap &> /dev/null; then
        # Quick service detection on top 100 ports
        echo -e "${CYAN}[*] Running quick nmap service detection...${NC}"
        nmap -sV -T4 --top-ports 100 "$target" -oN "$output_dir/${target}_services.txt" >> "$LOG_FILE" 2>&1
        
        # Parse nmap results
        parse_nmap_services "$output_dir/${target}_services.txt" "$target"
    fi
}

parse_nmap_services() {
    local nmap_file=$1
    local target=$2
    
    if [ ! -f "$nmap_file" ]; then
        return
    fi
    
    echo -e "${BLUE}[*] Parsing nmap service results...${NC}"
    
    local service_count=0
    local current_port=""
    local current_service=""
    local current_version=""
    
    while IFS= read -r line; do
        # Match port/service lines
        if [[ "$line" =~ ^([0-9]+)/tcp\s+open\s+([^ ]+)(?:\s+(.+))?$ ]]; then
            current_port="${BASH_REMATCH[1]}"
            current_service="${BASH_REMATCH[2]}"
            current_version="${BASH_REMATCH[3]:-unknown}"
            
            # Insert into database
            sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO network_services (scan_id, ip, port, service, version)
VALUES ('$SCAN_ID', '$target', '$current_port', '$current_service', '$current_version');
EOF
            ((service_count++))
            
            # Check for potentially risky services
            if [[ "$current_service" =~ ^(ftp|telnet|rpcbind|vnc|snmp)$ ]] || [[ "$current_version" =~ (old|outdated|deprecated) ]]; then
                sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
INSERT INTO findings (scan_id, type, severity, description, evidence)
VALUES ('$SCAN_ID', 'service_risk', 'medium', 'Potentially Risky Service', 
        '$current_service on port $current_port: $current_version');
EOF
            fi
        fi
    done < "$nmap_file"
    
    echo -e "${GREEN}[✓] Found $service_count open ports${NC}"
}

# =====================[ REPORT GENERATION ]=====================
generate_reports() {
    echo -e "${PURPLE}[*] Generating comprehensive reports...${NC}"
    
    mkdir -p "$REPORT_DIR"
    
    # Update scan status
    sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
UPDATE scans 
SET end_time = datetime('now'), status = 'completed'
WHERE id = '$SCAN_ID';
EOF
    
    # Generate HTML report
    if [ "$EXPORT_FORMAT" = "html" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_html_report
    fi
    
    # Generate Markdown report
    if [ "$EXPORT_FORMAT" = "markdown" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_markdown_report
    fi
    
    # Generate JSON report
    if [ "$EXPORT_FORMAT" = "json" ] || [ "$EXPORT_FORMAT" = "all" ]; then
        generate_json_report
    fi
    
    # Generate executive summary
    generate_executive_summary "$SCAN_ID"
    
    echo -e "${GREEN}[✓] Reports generated successfully${NC}"
}

generate_html_report() {
    echo -e "${CYAN}[*] Generating HTML report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.html"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status
FROM scans 
WHERE id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status <<< "$scan_info"
    
    # Count findings
    local findings=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'info' THEN 1 END) as info
FROM findings 
WHERE scan_id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    # Create HTML report
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NiiXscan Security Report - Scan $SCAN_ID</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 30px;
        }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .severity-info { color: #17a2b8; font-weight: bold; }
        .stat-box {
            display: inline-block;
            padding: 15px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
            min-width: 120px;
            color: white;
        }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; }
        .low { background: #28a745; }
        .info { background: #17a2b8; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .summary {
            background: #e9ecef;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
        }
        .finding {
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid #ddd;
        }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 NiiXscan Security Assessment Report</h1>
            <p class="timestamp">Generated on $(date)</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <p><strong>Target:</strong> $target_url</p>
            <p><strong>Scan Type:</strong> $scan_type</p>
            <p><strong>Scan Period:</strong> $start_time to ${end_time:-In Progress}</p>
            <p><strong>Status:</strong> $status</p>
            <p><strong>Scan ID:</strong> $SCAN_ID</p>
        </div>
        
        <h2>📈 Vulnerability Statistics</h2>
        <div>
            <div class="stat-box critical">Critical: $critical</div>
            <div class="stat-box high">High: $high</div>
            <div class="stat-box medium">Medium: $medium</div>
            <div class="stat-box low">Low: $low</div>
            <div class="stat-box info">Info: $info</div>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
EOF
    
    # Check if there are findings
    if [ $((critical + high + medium + low + info)) -eq 0 ]; then
        echo "<p>No vulnerabilities found during this scan.</p>" >> "$report_file"
    else
        echo '<table><thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>Evidence</th></tr></thead><tbody>' >> "$report_file"
        
        # Get findings from database
        local findings_details=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    severity,
    type,
    description,
    evidence
FROM findings 
WHERE scan_id = '$SCAN_ID'
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
        ELSE 6
    END,
    type;
EOF
        )
        
        while IFS='|' read -r severity type description evidence; do
            echo "<tr><td><span class=\"severity-$severity\">$severity</span></td><td>$type</td><td>$description</td><td><small>$evidence</small></td></tr>" >> "$report_file"
        done <<< "$findings_details"
        
        echo '</tbody></table>' >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
        
        <h2>🌐 Network Services Discovered</h2>
EOF
    
    # Get network services from database
    local network_services=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    ip,
    port,
    service,
    version
FROM network_services 
WHERE scan_id = '$SCAN_ID'
ORDER BY ip, port;
EOF
    )
    
    if [ -n "$network_services" ]; then
        echo '<table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>' >> "$report_file"
        
        while IFS='|' read -r ip port service version; do
            echo "<tr><td>$ip</td><td>$port</td><td>$service</td><td>$version</td></tr>" >> "$report_file"
        done <<< "$network_services"
        
        echo '</tbody></table>' >> "$report_file"
    else
        echo '<p>No network services discovered or scanned.</p>' >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
        
        <div class="summary">
            <h2>✅ Recommendations</h2>
            <ul>
                <li>Immediately address all Critical and High severity vulnerabilities</li>
                <li>Schedule remediation for Medium severity vulnerabilities within 30 days</li>
                <li>Review Low severity findings for potential security improvements</li>
                <li>Implement regular security scanning and monitoring</li>
                <li>Keep all software and systems updated with the latest security patches</li>
            </ul>
        </div>
        
        <div class="timestamp">
            <p>Report generated by NiiXscan v3.3 - Optimized Nuclei Scanning Platform</p>
            <p>Scan ID: $SCAN_ID | Generated: $(date)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}[✓] HTML report generated: $report_file${NC}"
    
    # Update database with report path
    sqlite3 "$DB_FILE" 2>> "$LOG_FILE" << EOF
UPDATE scans 
SET report_path = '$report_file'
WHERE id = '$SCAN_ID';
EOF
}

generate_markdown_report() {
    echo -e "${CYAN}[*] Generating Markdown report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.md"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status
FROM scans 
WHERE id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status <<< "$scan_info"
    
    cat > "$report_file" << EOF
# NiiXscan Security Assessment Report

## 📋 Scan Information
- **Scan ID:** $SCAN_ID
- **Target:** $target_url
- **Scan Type:** $scan_type
- **Start Time:** $start_time
- **End Time:** ${end_time:-In Progress}
- **Status:** $status
- **Report Generated:** $(date)

## 📊 Vulnerability Summary
EOF
    
    # Count findings
    local findings=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'info' THEN 1 END) as info
FROM findings 
WHERE scan_id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    cat >> "$report_file" << EOF
### Severity Breakdown
- 🔴 **Critical:** $critical
- 🟠 **High:** $high
- 🟡 **Medium:** $medium
- 🟢 **Low:** $low
- 🔵 **Info:** $info

## 🔍 Detailed Findings
EOF
    
    # Check if there are findings
    if [ $((critical + high + medium + low + info)) -eq 0 ]; then
        echo "No vulnerabilities found during this scan." >> "$report_file"
    else
        # Get findings from database
        local findings_details=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    severity,
    type,
    description,
    evidence
FROM findings 
WHERE scan_id = '$SCAN_ID'
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
        ELSE 6
    END;
EOF
        )
        
        while IFS='|' read -r severity type description evidence; do
            cat >> "$report_file" << EOF
### $severity severity - $type
- **Description:** $description
- **Evidence:** $evidence

EOF
        done <<< "$findings_details"
    fi
    
    cat >> "$report_file" << EOF
## 🌐 Discovered Network Services
EOF
    
    # Get network services
    local network_services=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT ip, port, service, version 
FROM network_services 
WHERE scan_id = '$SCAN_ID'
ORDER BY ip, port;
EOF
    )
    
    if [ -n "$network_services" ]; then
        cat >> "$report_file" << EOF
| Host | Port | Service | Version |
|------|------|---------|---------|
EOF
        
        while IFS='|' read -r ip port service version; do
            cat >> "$report_file" << EOF
| $ip | $port | $service | $version |
EOF
        done <<< "$network_services"
    else
        echo "No network services discovered." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## 🎯 Recommendations

### Immediate Actions (Critical & High)
1. Patch all identified vulnerabilities immediately
2. Implement Web Application Firewall (WAF) if not present
3. Review and harden system configurations
4. Change default credentials if found

### Short-term Actions (Medium)
1. Schedule patching within 30 days
2. Implement security monitoring
3. Conduct regular vulnerability assessments
4. Update security policies

### Long-term Actions
1. Establish security training program
2. Implement DevSecOps practices
3. Regular security audits
4. Continuous security monitoring

---
*Report generated by NiiXscan v3.3 - Optimized Nuclei Scanning Platform*
EOF
    
    echo -e "${GREEN}[✓] Markdown report generated: $report_file${NC}"
}

generate_json_report() {
    echo -e "${CYAN}[*] Generating JSON report...${NC}"
    
    local report_file="$REPORT_DIR/report_${SCAN_ID}.json"
    
    # Get scan info
    local scan_info=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status,
    report_path
FROM scans 
WHERE id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r target_url scan_type start_time end_time status report_path <<< "$scan_info"
    
    # Get findings count
    local findings=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'info' THEN 1 END) as info
FROM findings 
WHERE scan_id = '$SCAN_ID';
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    # Get findings details
    local findings_json=$(sqlite3 -json "$DB_FILE" 2>/dev/null << EOF
SELECT 
    severity,
    type,
    description,
    evidence
FROM findings 
WHERE scan_id = '$SCAN_ID';
EOF
    )
    
    # Get network services
    local services_json=$(sqlite3 -json "$DB_FILE" 2>/dev/null << EOF
SELECT 
    ip,
    port,
    service,
    version
FROM network_services 
WHERE scan_id = '$SCAN_ID';
EOF
    )
    
    cat > "$report_file" << EOF
{
    "report": {
        "metadata": {
            "scan_id": "$SCAN_ID",
            "generator": "NiiXscan v3.3",
            "generated_date": "$(date -Iseconds)",
            "version": "3.3"
        },
        "scan_info": {
            "target": "$target_url",
            "scan_type": "$scan_type",
            "start_time": "$start_time",
            "end_time": "$end_time",
            "status": "$status"
        },
        "summary": {
            "vulnerability_counts": {
                "critical": $critical,
                "high": $high,
                "medium": $medium,
                "low": $low,
                "info": $info,
                "total": $((critical + high + medium + low + info))
            }
        },
        "findings": $findings_json,
        "network_services": $services_json
    }
}
EOF
    
    echo -e "${GREEN}[✓] JSON report generated: $report_file${NC}"
}

# =====================[ GENERATE EXECUTIVE SUMMARY ]=====================
generate_executive_summary() {
    local scan_id="$1"
    
    if [ -z "$scan_id" ]; then
        echo -e "${RED}[!] No scan ID provided${NC}"
        return 1
    fi
    
    echo -e "${CYAN}[*] Generating executive summary...${NC}"
    
    local report_file="$REPORT_DIR/executive_summary_${scan_id}_$(date +%Y%m%d).md"
    
    # Get scan details from database
    local scan_info=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status
FROM scans 
WHERE id = '$scan_id';
EOF
    )
    
    if [ -z "$scan_info" ]; then
        echo -e "${RED}[!] Scan ID $scan_id not found${NC}"
        return 1
    fi
    
    IFS='|' read -r target_url scan_type start_time end_time status <<< "$scan_info"
    
    # Count findings by severity
    local findings=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low,
    COUNT(CASE WHEN severity = 'info' THEN 1 END) as info
FROM findings 
WHERE scan_id = '$scan_id';
EOF
    )
    
    IFS='|' read -r critical high medium low info <<< "$findings"
    
    # Calculate risk score
    local risk_score=$((critical * 10 + high * 7 + medium * 4 + low * 1))
    if [ $risk_score -gt 100 ]; then
        risk_score=100
    fi
    
    # Determine risk level
    local risk_level=""
    if [ $risk_score -ge 80 ]; then
        risk_level="🔴 CRITICAL"
    elif [ $risk_score -ge 60 ]; then
        risk_level="🟠 HIGH"
    elif [ $risk_score -ge 40 ]; then
        risk_level="🟡 MEDIUM"
    elif [ $risk_score -ge 20 ]; then
        risk_level="🟢 LOW"
    else
        risk_level="🔵 INFO"
    fi
    
    # Create executive summary
    cat > "$report_file" << EOF
# 🎯 Executive Summary - Security Assessment

## 📋 Assessment Overview
- **Assessment ID:** $scan_id
- **Target:** $target_url
- **Assessment Type:** $scan_type
- **Assessment Period:** $start_time to ${end_time:-Ongoing}
- **Overall Status:** $status

## 📊 Risk Assessment
- **Overall Risk Score:** $risk_score/100
- **Risk Level:** $risk_level
- **Assessment Date:** $(date)

## 🚨 Key Findings Summary

### Vulnerability Distribution
- 🔴 **Critical:** $critical vulnerabilities
- 🟠 **High:** $high vulnerabilities  
- 🟡 **Medium:** $medium vulnerabilities
- 🟢 **Low:** $low vulnerabilities
- 🔵 **Info:** $info findings

## 🎯 Key Recommendations

### Immediate Actions (Within 24-48 Hours)
1. **Patch Critical Vulnerabilities:** Address all $critical critical vulnerabilities immediately
2. **Emergency Response:** Implement emergency patching procedures
3. **Monitoring Enhancement:** Increase security monitoring and alerting

### Short-term Actions (Within 2 Weeks)
1. **High Priority Remediation:** Resolve $high high severity vulnerabilities
2. **Security Hardening:** Implement additional security controls
3. **Access Review:** Review and tighten access controls

### Strategic Recommendations (Within 30 Days)
1. **Security Program Enhancement:** Establish continuous security assessment
2. **Training & Awareness:** Conduct security awareness training
3. **Policy Updates:** Review and update security policies

## 📈 Business Impact Analysis

### Technical Impact
- **System Availability:** $(if [ $critical -gt 0 ]; then echo "High risk of disruption"; else echo "Stable"; fi)
- **Data Confidentiality:** $(if [ $high -gt 2 ]; then echo "Significant exposure risk"; else echo "Moderately protected"; fi)
- **Data Integrity:** $(if [ $medium -gt 5 ]; then echo "Potential integrity issues"; else echo "Generally intact"; fi)

---
*This executive summary provides a high-level overview. Detailed technical findings are available in the full assessment report.*

**Generated by NiiXscan v3.3 - Optimized Nuclei Scanning Platform**
**Confidentiality: This document contains sensitive security information. Handle with appropriate care.**
EOF
    
    echo -e "${GREEN}[✓] Executive summary generated: $report_file${NC}"
    
    # Display summary in terminal
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                 EXECUTIVE SUMMARY                    ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║  Target: $target_url"
    echo "║  Risk Score: $risk_score/100 ($risk_level)"
    echo "║  Critical Findings: $critical"
    echo "║  High Findings: $high"
    echo "║  Report: $report_file"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    return 0
}

# =====================[ BROWSE ALL REPORTS ]=====================
browse_all_reports() {
    echo -e "${CYAN}[*] Browsing all reports...${NC}"
    
    if [ ! -d "$REPORT_DIR" ] || [ -z "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]; then
        echo -e "${YELLOW}[!] No reports found${NC}"
        return 1
    fi
    
    local reports=($(ls -1t "$REPORT_DIR"/*.html 2>/dev/null | head -20))
    local count=${#reports[@]}
    
    if [ $count -eq 0 ]; then
        echo -e "${YELLOW}[!] No HTML reports found${NC}"
        # Try to find any reports
        reports=($(ls -1t "$REPORT_DIR"/*.{html,md,json} 2>/dev/null | head -20))
        count=${#reports[@]}
        
        if [ $count -eq 0 ]; then
            return 1
        fi
    fi
    
    echo -e "${GREEN}[✓] Found $count reports${NC}"
    echo ""
    
    for i in "${!reports[@]}"; do
        local report="${reports[$i]}"
        local filename=$(basename "$report")
        local size=$(du -h "$report" 2>/dev/null | cut -f1 || echo "N/A")
        local date=$(stat -c %y "$report" 2>/dev/null | cut -d' ' -f1 || echo "N/A")
        
        echo "$((i+1)). $filename"
        echo "   Size: $size | Date: $date"
        echo ""
    done
    
    echo -n "Enter report number to view, or 0 to return: "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -le $count ]; then
        local selected_report="${reports[$((choice-1))]}"
        
        # Try to open in default browser
        if [[ "$selected_report" == *.html ]] && command -v xdg-open &> /dev/null; then
            xdg-open "$selected_report" 2>/dev/null
        elif [[ "$selected_report" == *.html ]] && command -v open &> /dev/null; then
            open "$selected_report" 2>/dev/null
        else
            echo -e "${YELLOW}[!] Report saved at: $selected_report${NC}"
        fi
    fi
    
    return 0
}

# =====================[ MAIN MENU ]=====================
show_main_menu() {
    while true; do
        clear
        echo -e "${PURPLE}"
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║              NiiXscan v3.3 - Main Menu              ║"
        echo "║          Optimized Nuclei Scanning Edition          ║"
        echo "╠══════════════════════════════════════════════════════╣"
        echo "║  1.  Start New Security Scan                    ║"
        echo "║  2.  Configure Scanning Options                ║"
        echo "║  3.  Browse All Reports                        ║"
        echo "║  4.  Generate Executive Summary               ║"
        echo "║  5. View Scan History                         ║"
        echo "║  6.  Tool Management                          ║"
        echo "║  7. System Information                        ║"
        echo "║  8.  Exit                                      ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        echo -n "Select option [1-8]: "
        read choice
        
        case $choice in
            1)
                start_scan
                pause
                ;;
            2)
                configure_scanning
                pause
                ;;
            3)
                browse_all_reports
                pause
                ;;
            4)
                select_scan_for_summary
                pause
                ;;
            5)
                view_scan_history
                pause
                ;;
            6)
                tool_management
                pause
                ;;
            7)
                show_system_info
                pause
                ;;
            8)
                cleanup_and_exit
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

configure_scanning() {
    echo -e "${CYAN}[*] Configuring scanning options...${NC}"
    
    echo "1. Select Scan Type"
    echo "2. Set Output Format"
    echo "3. Configure Security Level"
    echo "4. Set Nuclei Options"
    echo "5. Back to Main Menu"
    echo -n "Select option [1-5]: "
    read config_choice
    
    case $config_choice in
        1)
            select_scan_type
            ;;
        2)
            select_output_format
            ;;
        3)
            configure_security_level
            ;;
        4)
            configure_nuclei_options
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
}

select_scan_type() {
    echo -e "${CYAN}[*] Select scan type:${NC}"
    echo "1. Comprehensive (Full assessment)"
    echo "2. Quick Scan"
    echo "3. Web Application Only"
    echo "4. Network Services Only"
    echo -n "Select option [1-4]: "
    read scan_type_choice
    
    case $scan_type_choice in
        1) SCAN_TYPE="comprehensive" ;;
        2) SCAN_TYPE="quick" ;;
        3) SCAN_TYPE="web" ;;
        4) SCAN_TYPE="network" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Scan type set to: $SCAN_TYPE${NC}"
    
    # Update configuration file
    if [ -f "$CONFIG_FILE" ]; then
        sed -i "s/^DEFAULT_SCAN_TYPE=.*/DEFAULT_SCAN_TYPE=\"$SCAN_TYPE\"/" "$CONFIG_FILE"
    fi
}

select_output_format() {
    echo -e "${CYAN}[*] Select output format:${NC}"
    echo "1. HTML (Recommended)"
    echo "2. Markdown"
    echo "3. JSON"
    echo "4. All formats"
    echo -n "Select option [1-4]: "
    read format_choice
    
    case $format_choice in
        1) EXPORT_FORMAT="html" ;;
        2) EXPORT_FORMAT="markdown" ;;
        3) EXPORT_FORMAT="json" ;;
        4) EXPORT_FORMAT="all" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Output format set to: $EXPORT_FORMAT${NC}"
}

configure_security_level() {
    echo -e "${CYAN}[*] Configure security level:${NC}"
    echo "1. High (Safe, no exploitation)"
    echo "2. Medium (Limited testing)"
    echo "3. Low (Full testing - use with caution)"
    echo -n "Select option [1-3]: "
    read security_choice
    
    case $security_choice in
        1) SECURITY_LEVEL="high" ;;
        2) SECURITY_LEVEL="medium" ;;
        3) SECURITY_LEVEL="low" ;;
        *) 
            echo -e "${RED}[!] Invalid option${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}[✓] Security level set to: $SECURITY_LEVEL${NC}"
}

configure_nuclei_options() {
    echo -e "${CYAN}[*] Configure Nuclei options:${NC}"
    
    echo -n "Maximum templates to use (default: 500): "
    read template_limit
    if [[ $template_limit =~ ^[0-9]+$ ]] && [ $template_limit -gt 0 ]; then
        NUCLEI_TEMPLATE_LIMIT=$template_limit
        echo -e "${GREEN}[✓] Template limit set to: $NUCLEI_TEMPLATE_LIMIT${NC}"
    fi
    
    echo -n "Severity levels (critical,high,medium,low,info): "
    read severity
    if [ -n "$severity" ]; then
        NUCLEI_SEVERITY="$severity"
        echo -e "${GREEN}[✓] Severity set to: $NUCLEI_SEVERITY${NC}"
    fi
    
    echo -n "Rate limit (requests/second, default: 50): "
    read rate_limit
    if [[ $rate_limit =~ ^[0-9]+$ ]] && [ $rate_limit -gt 0 ]; then
        NUCLEI_RATE_LIMIT=$rate_limit
        echo -e "${GREEN}[✓] Rate limit set to: $NUCLEI_RATE_LIMIT${NC}"
    fi
    
    # Update configuration file
    if [ -f "$CONFIG_FILE" ]; then
        sed -i "s/^NUCLEI_TEMPLATE_LIMIT=.*/NUCLEI_TEMPLATE_LIMIT=$NUCLEI_TEMPLATE_LIMIT/" "$CONFIG_FILE"
        sed -i "s/^NUCLEI_SEVERITY=.*/NUCLEI_SEVERITY=\"$NUCLEI_SEVERITY\"/" "$CONFIG_FILE"
        sed -i "s/^NUCLEI_RATE_LIMIT=.*/NUCLEI_RATE_LIMIT=$NUCLEI_RATE_LIMIT/" "$CONFIG_FILE"
    fi
}

select_scan_for_summary() {
    echo -e "${CYAN}[*] Select scan for executive summary...${NC}"
    
    # Get recent scans
    local recent_scans=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT id, target_url, start_time, status 
FROM scans 
WHERE status = 'completed' 
ORDER BY start_time DESC 
LIMIT 10;
EOF
    )
    
    if [ -z "$recent_scans" ]; then
        echo -e "${YELLOW}[!] No completed scans found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[✓] Recent scans:${NC}"
    echo ""
    
    local count=1
    declare -a scan_array
    while IFS='|' read -r id target_url start_time status; do
        echo "$count. Scan ID: $id"
        echo "   Target: $target_url"
        echo "   Date: $start_time"
        echo "   Status: $status"
        echo ""
        scan_array[$count]="$id"
        ((count++))
    done <<< "$recent_scans"
    
    echo -n "Select scan number (or 0 to go back): "
    read choice
    
    if [[ $choice =~ ^[0-9]+$ ]] && [ $choice -ge 1 ] && [ $choice -lt $count ]; then
        local selected_scan="${scan_array[$choice]}"
        generate_executive_summary "$selected_scan"
    fi
}

view_scan_history() {
    echo -e "${CYAN}[*] Viewing scan history...${NC}"
    
    local history=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    id,
    target_url,
    scan_type,
    strftime('%Y-%m-%d %H:%M', start_time) as start_time,
    strftime('%Y-%m-%d %H:%M', end_time) as end_time,
    status
FROM scans 
ORDER BY start_time DESC 
LIMIT 20;
EOF
    )
    
    if [ -z "$history" ]; then
        echo -e "${YELLOW}[!] No scan history found${NC}"
        return
    fi
    
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│                           SCAN HISTORY                                      │${NC}"
    echo -e "${GREEN}├──────┬──────────────────────────┬────────────┬──────────────────┬───────────┤${NC}"
    echo -e "${GREEN}│  ID  │         Target          │    Type    │     Period       │  Status   │${NC}"
    echo -e "${GREEN}├──────┼──────────────────────────┼────────────┼──────────────────┼───────────┤${NC}"
    
    while IFS='|' read -r id target_url scan_type start_time end_time status; do
        # Trim target URL for display
        local display_target="$target_url"
        if [ ${#display_target} -gt 20 ]; then
            display_target="${display_target:0:17}..."
        fi
        
        # Trim scan type
        local display_type="$scan_type"
        if [ ${#display_type} -gt 8 ]; then
            display_type="${display_type:0:8}"
        fi
        
        # Format period
        local period="${start_time:5:11}"
        if [ -n "$end_time" ]; then
            period="$period"
        else
            period="$period (ongoing)"
        fi
        
        # Color code status
        local status_display=""
        case $status in
            "completed") status_display="${GREEN}completed${NC}" ;;
            "running") status_display="${YELLOW}running${NC}" ;;
            "failed") status_display="${RED}failed${NC}" ;;
            *) status_display="$status" ;;
        esac
        
        printf "${GREEN}│ ${NC}%-4s ${GREEN}│ ${NC}%-24s ${GREEN}│ ${NC}%-10s ${GREEN}│ ${NC}%-16s ${GREEN}│ ${NC}%-9s ${GREEN}│${NC}\n" \
            "${id: -4}" "$display_target" "$display_type" "$period" "$status_display"
    done <<< "$history"
    
    echo -e "${GREEN}└──────┴──────────────────────────┴────────────┴──────────────────┴───────────┘${NC}"
    echo ""
    
    echo -n "Enter Scan ID for details (or press Enter to return): "
    read scan_id
    
    if [ -n "$scan_id" ]; then
        view_scan_details "$scan_id"
    fi
}

view_scan_details() {
    local scan_id="$1"
    
    echo -e "${CYAN}[*] Details for Scan ID: $scan_id${NC}"
    
    # Get scan details
    local scan_info=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    target_url,
    scan_type,
    start_time,
    end_time,
    status,
    report_path
FROM scans 
WHERE id = '$scan_id';
EOF
    )
    
    if [ -z "$scan_info" ]; then
        echo -e "${RED}[!] Scan ID not found${NC}"
        return
    fi
    
    IFS='|' read -r target_url scan_type start_time end_time status report_path <<< "$scan_info"
    
    echo -e "${BLUE}Target:${NC} $target_url"
    echo -e "${BLUE}Type:${NC} $scan_type"
    echo -e "${BLUE}Start:${NC} $start_time"
    echo -e "${BLUE}End:${NC} ${end_time:-N/A}"
    echo -e "${BLUE}Status:${NC} $status"
    echo -e "${BLUE}Report:${NC} ${report_path:-N/A}"
    
    # Show findings summary
    local findings_summary=$(sqlite3 "$DB_FILE" 2>/dev/null << EOF
SELECT 
    'Critical: ' || COUNT(CASE WHEN severity = 'critical' THEN 1 END) || ', ' ||
    'High: ' || COUNT(CASE WHEN severity = 'high' THEN 1 END) || ', ' ||
    'Medium: ' || COUNT(CASE WHEN severity = 'medium' THEN 1 END) || ', ' ||
    'Low: ' || COUNT(CASE WHEN severity = 'low' THEN 1 END) || ', ' ||
    'Info: ' || COUNT(CASE WHEN severity = 'info' THEN 1 END)
FROM findings 
WHERE scan_id = '$scan_id';
EOF
    )
    
    echo -e "${BLUE}Findings:${NC} $findings_summary"
    
    # Show options
    echo ""
    echo "1. View Full Report"
    echo "2. Generate Executive Summary"
    echo "3. Return to History"
    echo -n "Select option [1-3]: "
    read option
    
    case $option in
        1)
            if [ -f "$report_path" ]; then
                if command -v xdg-open &> /dev/null; then
                    xdg-open "$report_path"
                elif command -v open &> /dev/null; then
                    open "$report_path"
                else
                    echo -e "${YELLOW}[!] Report: $report_path${NC}"
                fi
            else
                echo -e "${YELLOW}[!] Report not available${NC}"
            fi
            ;;
        2)
            generate_executive_summary "$scan_id"
            ;;
        3)
            return
            ;;
    esac
}

tool_management() {
    echo -e "${CYAN}[*] Tool Management${NC}"
    
    echo "1. Install Missing Tools"
    echo "2. Update All Tools"
    echo "3. Check Tool Status"
    echo "4. Install Nuclei (Most Important)"
    echo "5. Back to Main Menu"
    echo -n "Select option [1-5]: "
    read tool_choice
    
    case $tool_choice in
        1)
            install_missing_tools
            ;;
        2)
            update_all_tools
            ;;
        3)
            check_tool_status
            ;;
        4)
            install_nuclei
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
}

install_missing_tools() {
    echo -e "${CYAN}[*] Installing missing tools...${NC}"
    
    local required_tools=("nmap" "nikto" "sqlmap" "gobuster" "whatweb" "wafw00f" "testssl" "nuclei")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[!] Installing $tool...${NC}"
            install_package_robust "$tool"
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[✓] $tool installed successfully${NC}"
            else
                echo -e "${RED}[!] Failed to install $tool${NC}"
            fi
        else
            echo -e "${GREEN}[✓] $tool is installed${NC}"
        fi
    done
}

update_all_tools() {
    echo -e "${CYAN}[*] Updating all tools...${NC}"
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update && sudo apt-get upgrade -y
            ;;
        "yum")
            sudo yum update -y
            ;;
        "dnf")
            sudo dnf update -y
            ;;
        "brew")
            brew update && brew upgrade
            ;;
    esac
    
    echo -e "${GREEN}[✓] Tools updated${NC}"
}

check_tool_status() {
    echo -e "${CYAN}[*] Checking tool status...${NC}"
    
    local important_tools=(
        "nmap" "nikto" "sqlmap" "gobuster" "whatweb" 
        "wafw00f" "testssl" "sslscan" "nuclei" "wpscan"
    )
    
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│                       TOOL STATUS                          │${NC}"
    echo -e "${GREEN}├──────────────────────────────┬─────────────────────────────┤${NC}"
    echo -e "${GREEN}│           Tool               │           Status           │${NC}"
    echo -e "${GREEN}├──────────────────────────────┼─────────────────────────────┤${NC}"
    
    for tool in "${important_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            local version=""
            case $tool in
                "nmap")
                    version=$(nmap --version 2>/dev/null | head -1 | cut -d' ' -f3)
                    ;;
                "nikto")
                    version=$(nikto -v 2>/dev/null | grep "Version" | cut -d' ' -f2)
                    ;;
                "nuclei")
                    version=$(nuclei -version 2>/dev/null | head -1 | cut -d' ' -f2)
                    ;;
                *)
                    version=$($tool --version 2>/dev/null | head -1 | cut -d' ' -f2-3 | tr -d '\n')
                    ;;
            esac
            printf "${GREEN}│ ${NC}%-28s ${GREEN}│ ${GREEN}%-27s ${GREEN}│${NC}\n" "$tool" "${version:0:25}"
        else
            printf "${GREEN}│ ${NC}%-28s ${GREEN}│ ${RED}%-27s ${GREEN}│${NC}\n" "$tool" "NOT INSTALLED"
        fi
    done
    
    echo -e "${GREEN}└──────────────────────────────┴─────────────────────────────┘${NC}"
}

show_system_info() {
    echo -e "${CYAN}[*] System Information${NC}"
    
    echo -e "${BLUE}Operating System:${NC}"
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "  $PRETTY_NAME"
    elif command -v sw_vers &> /dev/null; then
        sw_vers
    else
        uname -a
    fi
    
    echo -e "${BLUE}Kernel:${NC} $(uname -r)"
    echo -e "${BLUE}Architecture:${NC} $(uname -m)"
    echo -e "${BLUE}CPU Cores:${NC} $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")"
    
    echo -e "${BLUE}NiiXscan Directories:${NC}"
    echo "  Config: $CONFIG_DIR"
    echo "  Workspace: $WORKSPACE"
    echo "  Tools: $TOOL_DIR"
    echo "  Reports: $REPORT_DIR"
    
    echo -e "${BLUE}Database Status:${NC}"
    if [ -f "$DB_FILE" ]; then
        local scan_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM scans;" 2>/dev/null)
        local finding_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM findings;" 2>/dev/null)
        echo "  Scans: $scan_count"
        echo "  Findings: $finding_count"
        echo "  Database: $DB_FILE"
    else
        echo "  Database not initialized"
    fi
    
    echo -e "${BLUE}Scan Status:${NC}"
    echo "  Security Level: $SECURITY_LEVEL"
    echo "  Scan Type: $SCAN_TYPE"
    echo "  Output Format: $EXPORT_FORMAT"
    echo "  Nuclei Template Limit: $NUCLEI_TEMPLATE_LIMIT"
    echo "  Nuclei Severity: $NUCLEI_SEVERITY"
}

pause() {
    echo ""
    echo -n "Press Enter to continue..."
    read
}

cleanup_and_exit() {
    echo -e "${CYAN}[*] Cleaning up...${NC}"
    
    # Stop progress indicator if running
    stop_simple_progress
    
    # Clean up temporary directory
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    echo -e "${GREEN}[✓] Cleanup completed${NC}"
    echo -e "${PURPLE}Thank you for using NiiXscan v3.3 - Optimized Nuclei Scanning!${NC}"
    exit 0
}

# =====================[ MAIN EXECUTION ]=====================
main() {
    # Create temporary directory
    mkdir -p "$TEMP_DIR"
    
    # Set trap for cleanup
    trap cleanup_and_exit INT TERM EXIT
    
    # Initialize platform
    initialize_platform
    
    # Show main menu
    show_main_menu
}

# Start the application
main "$@"
