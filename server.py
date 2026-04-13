#!/usr/bin/env python3

# This script connect the MCP AI agent to kali linux terminal and API server.

# Custom MCP Pentest API Server
# Tools: nmap, dirb, gobuster, ffuf, nikto, whatweb, wafw00f, subfinder,
#        amass, sqlmap, whois, dig, curl, netstat, enum4linux, hydra,
#        john, metasploit, wpscan

import argparse
import logging
import os
import re
import shlex
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 3 minutes default timeout

app = Flask(__name__)


# ─────────────────────────────────────────────
#  Command Executor
# ─────────────────────────────────────────────

class CommandExecutor:
    """Handles command execution with timeout management and streaming output."""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.use_shell = isinstance(command, str)
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line

    def _read_stderr(self):
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing command: {self.command}")
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            t_out = threading.Thread(target=self._read_stdout, daemon=True)
            t_err = threading.Thread(target=self._read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                t_out.join()
                t_err.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout}s. Terminating.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("Force killing unresponsive process.")
                    self.process.kill()
                self.return_code = -1

            success = (
                True if self.timed_out and (self.stdout_data or self.stderr_data)
                else (self.return_code == 0)
            )
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data)
            }

        except Exception as e:
            logger.error(f"Execution error: {e}\n{traceback.format_exc()}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error: {e}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command) -> Dict[str, Any]:
    return CommandExecutor(command).execute()


# ─────────────────────────────────────────────
#  Generic Command Endpoint
# ─────────────────────────────────────────────

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any arbitrary command."""
    try:
        params = request.json or {}
        command = params.get("command", "")
        if not command:
            return jsonify({"error": "Command parameter is required"}), 400
        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  Recon / Discovery Tools
# ─────────────────────────────────────────────

@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Nmap port/service scanner."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["nmap"] + shlex.split(scan_type)
        if ports:
            command += ["-p", ports]
        if additional_args:
            command += shlex.split(additional_args)
        command.append(target)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/whois", methods=["POST"])
def whois():
    """WHOIS domain/IP lookup."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["whois"]
        if additional_args:
            command += shlex.split(additional_args)
        command.append(target)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/dig", methods=["POST"])
def dig():
    """DNS lookup using dig."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        record_type = params.get("record_type", "ANY")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["dig", target, record_type]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Subfinder passive subdomain enumeration."""
    try:
        params = request.json or {}
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400

        command = ["subfinder", "-d", domain]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Amass attack surface & subdomain mapping."""
    try:
        params = request.json or {}
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")          # enum | intel | db
        additional_args = params.get("additional_args", "")

        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        if mode not in ["enum", "intel", "db"]:
            return jsonify({"error": f"Invalid mode: {mode}. Must be enum|intel|db"}), 400

        command = ["amass", mode, "-d", domain]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """WhatWeb web technology fingerprinter."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["whatweb", target]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Wafw00f WAF detection tool."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["wafw00f", url]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/netstat", methods=["POST"])
def netstat():
    """Netstat network connection/port viewer."""
    try:
        params = request.json or {}
        additional_args = params.get("additional_args", "-tuln")

        command = ["netstat"] + shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/curl", methods=["POST"])
def curl():
    """Curl HTTP request tool."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        method = params.get("method", "GET")
        headers = params.get("headers", {})          # dict of header key/value
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["curl", "-s", "-X", method]

        for key, value in headers.items():
            command += ["-H", f"{key}: {value}"]

        if data:
            command += ["-d", data]

        if additional_args:
            command += shlex.split(additional_args)

        command.append(url)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  Web Directory / Fuzzing Tools
# ─────────────────────────────────────────────

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Gobuster directory/DNS/vhost brute-forcer."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            return jsonify({"error": f"Invalid mode: {mode}. Must be dir|dns|fuzz|vhost"}), 400

        command = ["gobuster", mode, "-u", url, "-w", wordlist]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Dirb web content scanner."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["dirb", url, wordlist]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Ffuf fast web fuzzer."""
    try:
        params = request.json or {}
        url = params.get("url", "")           # Must contain FUZZ keyword e.g. http://target/FUZZ
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required (include FUZZ keyword)"}), 400

        command = ["ffuf", "-u", url, "-w", wordlist]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Nikto web server vulnerability scanner."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["nikto", "-h", target]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  Exploitation Tools
# ─────────────────────────────────────────────

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """SQLmap SQL injection scanner."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["sqlmap", "-u", url, "--batch"]
        if data:
            command += ["--data", data]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Run a Metasploit module via resource script."""
    try:
        params = request.json or {}
        module = params.get("module", "")
        options = params.get("options", {})

        if not module:
            return jsonify({"error": "Module parameter is required"}), 400
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"error": "Invalid module name"}), 400

        resource_content = f"use {module}\n"
        for key, value in options.items():
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        result = execute_command(["msfconsole", "-q", "-r", resource_file])

        try:
            os.remove(resource_file)
        except Exception as cleanup_err:
            logger.warning(f"Could not remove temp resource file: {cleanup_err}")

        return jsonify(result)
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  Credential Attack Tools
# ─────────────────────────────────────────────

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Hydra online password cracker."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            return jsonify({"error": "Target and service parameters are required"}), 400
        if not (username or username_file) or not (password or password_file):
            return jsonify({"error": "Username/username_file and password/password_file are required"}), 400

        command = ["hydra", "-t", "4"]
        command += ["-l", username] if username else ["-L", username_file]
        command += ["-p", password] if password else ["-P", password_file]
        command += [target, service]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/john", methods=["POST"])
def john():
    """John the Ripper offline hash cracker."""
    try:
        params = request.json or {}
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            return jsonify({"error": "Hash file parameter is required"}), 400

        command = ["john"]
        if format_type:
            command.append(f"--format={format_type}")
        if wordlist:
            command.append(f"--wordlist={wordlist}")
        if additional_args:
            command += shlex.split(additional_args)
        command.append(hash_file)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  CMS / Specific Scanners
# ─────────────────────────────────────────────

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """WPScan WordPress vulnerability scanner."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["wpscan", "--url", url]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Enum4linux Windows/Samba enumeration."""
    try:
        params = request.json or {}
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["enum4linux"] + shlex.split(additional_args) + [target]

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500


# ─────────────────────────────────────────────
#  Health Check
# ─────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check — verifies all tools are available on the system."""
    all_tools = [
        "nmap", "dirb", "gobuster", "ffuf", "nikto", "whatweb",
        "wafw00f", "subfinder", "amass", "sqlmap", "whois", "dig",
        "curl", "netstat", "enum4linux", "hydra", "john", "msfconsole", "wpscan"
    ]
    tools_status = {}
    for tool in all_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception:
            tools_status[tool] = False

    return jsonify({
        "status": "healthy",
        "message": "Custom Pentest MCP API Server is running",
        "tools_status": tools_status,
        "all_tools_available": all(tools_status.values())
    })


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Custom Pentest MCP API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"API port (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="Bind IP (default: 127.0.0.1)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    if args.port != API_PORT:
        API_PORT = args.port
    logger.info(f"Starting Custom Pentest API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
