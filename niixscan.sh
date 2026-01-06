import os
import subprocess
import sys
import argparse
import json
import logging
from threading import Thread
from urllib.parse import urlparse
import unittest
from io import StringIO

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for environment variables and configuration files
ENV_VAR_PREFIX = "NIX_"
CONFIG_FILE_PATH = os.getenv(f"{ENV_VAR_PREFIX}CONFIG", "config.json")

# Load configuration from a JSON file if it exists
def load_config():
    try:
        with open(CONFIG_FILE_PATH, 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        logger.warning("Configuration file not found. Using default settings.")
        return {}

config = load_config()

# Function to detect the OS type
def detect_os_type():
    if sys.platform.startswith('win'):
        return "windows"
    elif sys.platform.startswith('linux'):
        return "linux"
    elif sys.platform.startswith('darwin'):
        return "macos"
    else:
        raise ValueError("Unsupported operating system.")

# Install dependencies for a tool
def install_dependencies(tool, os_type):
    if tool == "wappalyzer":
        subprocess.run([sys.executable, "-m", "pip", "install", "Wappalyzer"], check=True)
    elif tool == "sqlmap":
        subprocess.run(["git", "clone", "--depth=1", "https://github.com/sqlmapproject/sqlmap.git", "/opt/sqlmap"])
        os.chmod("/opt/sqlmap/sqlmap.py", 0o755)
    elif tool == "nuclei":
        if os_type in ["linux", "macos"]:
            subprocess.run(["sudo", "apt-get", "update"], check=True) if os_type == "linux" else \
                subprocess.run(["brew", "update"], check=True)
            subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], check=True)
        else:
            logger.error(f"Nuclei is not supported on {os_type}")
    elif tool == "metasploit":
        if os_type in ["linux", "macos"]:
            subprocess.run(["sudo", "apt-get", "update"], check=True) if os_type == "linux" else \
                subprocess.run(["brew", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "metasploit-framework"], check=True) if os_type == "linux" else \
                subprocess.run(["brew", "install", "--cask", "metasploit"], check=True)
        else:
            logger.error(f"Metasploit is not supported on {os_type}")
    elif tool == "owasp-zap":
        if os_type in ["linux", "macos"]:
            subprocess.run(["sudo", "apt-get", "update"], check=True) if os_type == "linux" else \
                subprocess.run(["brew", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "zaproxy"], check=True) if os_type == "linux" else \
                subprocess.run(["brew", "install", "--cask", "zaproxy"], check=True)
        else:
            logger.error(f"OWASP ZAP is not supported on {os_type}")
    elif tool == "burp-suite":
        burp_url = os.getenv("NIX_BURP_URL") or config.get("BURP_URL", "https://portswigger.net/burp/releases/download?product=community&type=jar")
        burp_path = os.getenv("NIX_BURP_PATH") or config.get("BURP_PATH", "/opt/burpsuite_community.jar")
        subprocess.run(["wget", "-O", burp_path, burp_url], check=True)
        os.chmod(burp_path, 0o755)
    else:
        logger.error(f"Tool {tool} is not supported.")

# Validate URL
def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Run a tool in a separate thread
class ToolRunner(Thread):
    def __init__(self, tool, args):
        super().__init__()
        self.tool = tool
        self.args = args

    def run(self):
        try:
            logger.info(f"Starting {self.tool} with arguments: {self.args}")
            subprocess.run([sys.executable, f"/opt/{self.tool}/{self.tool}.py"] + self.args, check=True)
            logger.info(f"{self.tool} completed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"{self.tool} failed with error: {e}")

# Main function
def main():
    # Initialize logging
    log_level = os.getenv("NIX_LOG_LEVEL", "INFO").upper()
    numeric_log_level = getattr(logging, log_level, None)
    if not isinstance(numeric_log_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    logger.setLevel(numeric_log_level)

    # Interactive mode
    interactive = os.getenv("NIX_INTERACTIVE", "true").lower() == "true"
    if interactive:
        print("Welcome to the Nix Security Tool!")
        tools = ["wappalyzer", "sqlmap", "nuclei", "metasploit", "owasp-zap", "burp-suite"]
        selected_tools = input(f"Select tools to run (comma-separated, e.g., 'wappalyzer,sqlmap'): ").split(',')
        for tool in selected_tools:
            if tool.strip() not in tools:
                print(f"Invalid tool: {tool}")
                return
    else:
        parser = argparse.ArgumentParser(description="Nix Security Tool")
        parser.add_argument("--interactive", action="store_true", help="Run the script in interactive mode.")
        for tool in ["wappalyzer", "sqlmap", "nuclei", "metasploit", "owasp-zap", "burp-suite"]:
            group = parser.add_argument_group(tool)
            group.add_argument(f"--{tool}", action="store_true", help=f"Run {tool}")
            if tool == "sqlmap":
                group.add_argument("--sqlmap-args", nargs="+", help="Additional arguments for SQLmap")
                group.add_argument("--sqlmap-url", default=None, help="URL to scan with SQLmap")
        args = parser.parse_args()

    os_type = detect_os_type()
    tools_to_run = []

    if args.wappalyzer:
        install_dependencies("wappalyzer", os_type)
        tools_to_run.append(ToolRunner("wappalyzer", []))

    if args.sqlmap:
        install_dependencies("sqlmap", os_type)
        sqlmap_args = args.sqlmap_args or []
        if args.sqlmap_url and validate_url(args.sqlmap_url):
            sqlmap_args.append("-u")
            sqlmap_args.append(args.sqlmap_url)
        else:
            logger.error("Invalid URL provided for SQLmap. Please provide a valid URL.")
            return
        tools_to_run.append(ToolRunner("sqlmap", sqlmap_args))

    # Add similar checks and configurations for other tools...

    if tools_to_run:
        for tool_runner in tools_to_run:
            tool_runner.start()
        for tool_runner in tools_to_run:
            tool_runner.join()
    else:
        logger.info("No tools selected to run.")

# Unit Tests
class TestNixSecurityTool(unittest.TestCase):
    def setUp(self):
        self.capture_output = StringIO()
        self.log_capture = StringIO()
        sys.stdout = self.capture_output
        logging.getLogger().addHandler(logging.StreamHandler(self.log_capture))

    def tearDown(self):
        sys.stdout = sys.__stdout__
        logging.getLogger().removeHandler(logging.StreamHandler(self.log_capture))

    def test_validate_url(self):
        self.assertTrue(validate_url("https://example.com"))
        self.assertFalse(validate_url("example.com"))

    def test_install_dependencies(self):
        # Mock the subprocess.run function
        with unittest.mock.patch('subprocess.run') as mock_run:
            install_dependencies("wappalyzer", "linux")
            mock_run.assert_called_once_with([sys.executable, "-m", "pip", "install", "Wappalyzer"], check=True)

    def test_tool_runner(self):
        # Mock the subprocess.run function
        with unittest.mock.patch('subprocess.run') as mock_run:
            tool_runner = ToolRunner("wappalyzer", [])
            tool_runner.start()
            tool_runner.join()
            mock_run.assert_called_once_with([sys.executable, "/opt/wappalyzer/wappalyzer.py"], check=True)

# Run the script
if __name__ == "__main__":
    main()
