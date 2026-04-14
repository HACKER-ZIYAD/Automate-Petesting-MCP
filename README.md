# 🛡️ Automate-you're-Petesting-Using-MCP

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)
License](https://img.shields.io/badge/License-MIT-green?style=flat)

> Connect Claude AI to your Kali Linux machine via MCP (Model Context Protocol).  
> Let Claude plan, execute, and analyse penetration tests using real security tools — all from a chat window.

---

## 📋 Table of Contents

- [How It Works](#how-it-works)
- [Tools Available](#tools-available)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Step 1 — Install on Kali Linux (Server)](#step-1--install-on-kali-linux-server)
- [Step 2 — Install Security Tools on Kali](#step-2--install-security-tools-on-kali)
- [Step 3 — Start the API Server](#step-3--start-the-api-server)
- [Step 4 — Set Up the MCP Client Machine](#step-4--set-up-the-mcp-client-machine)
  - [Option A — Same Machine (Local)](#option-a--same-machine-local)
  - [Option C — Remote Machine Direct (Not Recommended)](#option-c--remote-machine-direct-not-recommended)
- [Step 5 — Windows Client Setup](#step-5--windows-client-setup)
- [Step 6 — Connect Claude Desktop](#step-6--connect-claude-desktop)
- [Step 7 — Verify Everything Works](#step-7--verify-everything-works)
- [Usage Examples](#usage-examples)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Security Warning](#security-warning)

---

## How It Works

```
┌─────────────────────┐        MCP Protocol        ┌──────────────────────┐
│                     │ ◄────────────────────────► │                      │
│   Claude Desktop    │                             │   client.py          │
│   (Your Machine)    │                             │   (MCP Server)       │
│                     │                             │                      │
└─────────────────────┘                             └──────────┬───────────┘
                                                               │
                                                     HTTP REST API
                                                  (localhost or SSH tunnel)
                                                               │
                                                    ┌──────────▼───────────┐
                                                    │                      │
                                                    │   server.py          │
                                                    │   (Flask API)        │
                                                    │   on Kali Linux      │
                                                    └──────────┬───────────┘
                                                               │
                                                       subprocess calls
                                                               │
                                        ┌──────────────────────▼──────────────────────┐
                                        │            Kali Linux Tools                 │
                                        │  nmap · dirb · gobuster · ffuf · nikto      │
                                        │  sqlmap · hydra · john · metasploit · ...   │
                                        └─────────────────────────────────────────────┘
```

**Flow:**
1. You chat with Claude in Claude Desktop
2. Claude calls a tool (e.g. `nmap_scan`) via MCP
3. `client.py` receives the call and sends an HTTP POST to `server.py`
4. `server.py` runs the real Kali tool as a subprocess
5. Output is returned back to Claude for analysis

---

## Tools Available

| Category | Tool | Description |
|---|---|---|
| **Recon** | `nmap` | Port scanning & service detection |
| **Recon** | `whois` | Domain / IP registration lookup |
| **Recon** | `dig` | DNS record queries (A, MX, TXT, ANY…) |
| **Recon** | `netstat` | View open ports & active connections |
| **Recon** | `curl` | HTTP requests with custom headers/body |
| **Subdomain** | `subfinder` | Passive subdomain enumeration |
| **Subdomain** | `amass` | Active + passive attack surface mapping |
| **Web Fingerprint** | `whatweb` | CMS, framework & server detection |
| **Web Fingerprint** | `wafw00f` | WAF detection |
| **Web Fuzzing** | `gobuster` | Directory / DNS / vhost brute-force |
| **Web Fuzzing** | `dirb` | Web content scanner |
| **Web Fuzzing** | `ffuf` | Fast web fuzzer (use `FUZZ` keyword in URL) |
| **Web Vuln** | `nikto` | Web server vulnerability scanner |
| **Exploitation** | `sqlmap` | SQL injection detection & exploitation |
| **Exploitation** | `metasploit` | Run any Metasploit module |
| **Credentials** | `hydra` | Online password brute-force |
| **Credentials** | `john` | Offline hash cracking |
| **CMS** | `wpscan` | WordPress vulnerability scanner |
| **Windows/SMB** | `enum4linux` | Windows / Samba enumeration |

---

## Prerequisites

| Requirement | Where to Get It |
|---|---|
| **Kali Linux** (VM, bare metal, or WSL) | [kali.org/get-kali](https://www.kali.org/get-kali/) |
| **Python 3.11+** on Kali | Pre-installed on Kali |
| **Claude Desktop** on your main machine | [claude.ai/download](https://claude.ai/download) |
| **Git** | Pre-installed on Kali |

> `server.py` and all security tools run **on your Kali machine**.  
> `client.py` runs on whichever machine has Claude Desktop — this can be the same Kali machine, or a separate Linux / macOS / Windows host.

---

## Project Structure

```
pentest-mcp/
├── server.py          # Flask API server — runs on Kali, executes tools
├── client.py          # MCP server — bridges Claude Desktop to the Flask API
└── requirements.txt   # Python dependencies (flask, mcp, requests)
```

---

## Step 1 — Install on Kali Linux (Server)

Open a terminal on your **Kali machine**.

### Method A — With Virtual Environment (Recommended)

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

# Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Method B — Without Virtual Environment

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
pip install -r requirements.txt
```

> Replace `YOUR_USERNAME/YOUR_REPO_NAME` with your actual GitHub repo path.

**Verify the install:**

```bash
pip show flask mcp requests
```

You should see version info for all three packages with no errors.

---

## Step 2 — Install Security Tools on Kali

Most tools are pre-installed on Kali. Run this block to install any that are missing:

```bash
sudo apt update && sudo apt install -y \
    nmap \
    dirb \
    gobuster \
    ffuf \
    nikto \
    whatweb \
    wafw00f \
    subfinder \
    amass \
    sqlmap \
    whois \
    dnsutils \
    curl \
    net-tools \
    enum4linux \
    hydra \
    john \
    metasploit-framework \
    wpscan
```

> `dnsutils` provides the `dig` command.  
> `net-tools` provides the `netstat` command.

**Confirm all tools are found:**

```bash
which nmap dirb gobuster ffuf nikto whatweb wafw00f subfinder amass \
      sqlmap whois dig curl netstat enum4linux hydra john msfconsole wpscan
```

Every line should print a path like `/usr/bin/nmap`. If any tool is missing, install it individually:

```bash
sudo apt install <toolname>
```

---

## Step 3 — Start the API Server

Run `server.py` on your **Kali machine** inside the project folder.  
If you used a venv in Step 1, activate it first: `source .venv/bin/activate`

```bash
# Default — binds to localhost:5000 (secure, recommended)
./server.py

# Custom port
./server.py --port 8080

# Bind to a specific IP and port
./server.py --ip 192.168.1.100 --port 8080

# Allow connections from any network interface (use with caution)
./server.py --ip 0.0.0.0

# Debug mode — verbose logging
./server.py --debug
```

**`--ip` options explained:**

| Value | Behaviour |
|---|---|
| `127.0.0.1` | Localhost only — only this machine can connect. **Secure. Default.** |
| `0.0.0.0` | All network interfaces — any machine on the network can connect. **Dangerous.** |
| `192.168.x.x` | Specific interface — only connections to that IP are accepted. |

You should see output like:

```
2025-xx-xx [INFO] Starting Custom Pentest API Server on 127.0.0.1:5000
 * Running on http://127.0.0.1:5000
```

**Keep this terminal open.** The API server must stay running during use.

**Test it in a second terminal:**

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{
  "status": "healthy",
  "message": "Custom Pentest MCP API Server is running",
  "tools_status": {
    "nmap": true,
    "gobuster": true,
    "ffuf": true
  },
  "all_tools_available": true
}
```

---

## Step 4 — Set Up the MCP Client Machine

The MCP client (`client.py`) runs on the machine where Claude Desktop is installed.  
Choose the option that matches your setup:

---

### Option A — Same Machine (Local)

If `client.py` and `server.py` are both running **on the same Kali machine**:

```bash
# With venv
source .venv/bin/activate
./client.py --server http://127.0.0.1:5000

# Without venv
python3 client.py --server http://127.0.0.1:5000
```

No extra configuration needed. Skip to [Step 6](#step-6--connect-claude-desktop).

---

### Option B — Remote Machine via SSH Tunnel ✅ Recommended

If `client.py` runs on a **separate machine** (your laptop/desktop) and `server.py` runs on a **remote Kali machine**, use an SSH tunnel. This is the most secure approach — traffic is encrypted and the Flask server stays on localhost only.

**Terminal 1 — on your client machine, open the SSH tunnel:**

```bash
# Replace LINUX_IP with your Kali machine's IP address
ssh -L 5000:localhost:5000 user@LINUX_IP

# Keep connection alive (add this flag to prevent tunnel from dropping)
ssh -L 5000:localhost:5000 -o ServerAliveInterval=60 user@LINUX_IP
```

Keep this terminal open. The tunnel is active as long as this SSH session is alive.

**Terminal 2 — clone and run the client on your client machine:**

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt

./client.py --server http://127.0.0.1:5000
```

Because of the SSH tunnel, `http://127.0.0.1:5000` on your local machine is forwarded securely to the remote Kali server.

---

### Option C — Remote Machine Direct (Not Recommended)

> ⚠️ **This exposes `server.py` directly over the network. Only use this in a trusted, isolated lab network. We strongly recommend Option B (SSH tunnel) instead.**

On your **Kali machine**, start the server bound to its network IP:

```bash
./server.py --ip 0.0.0.0 --port 5000
```

On your **client machine**, run:

```bash
./client.py --server http://LINUX_IP:5000
```

Replace `LINUX_IP` with the actual IP of your Kali machine (find it with `ip a` or `hostname -I`).

---

## Step 5 — Windows Client Setup

If your client machine is **Windows**, follow these steps to set up the Python virtual environment correctly.

**Open PowerShell and run:**

```powershell
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

python -m venv venv
```

**If you see a long red error about scripts being disabled**, PowerShell is blocking script execution. Fix it with:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Then activate the venv and install dependencies:**

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Run the client:**

```powershell
# Local (same machine as server)
python client.py --server http://127.0.0.1:5000

# Remote via SSH tunnel — open the tunnel first in a separate terminal:
# ssh -L 5000:localhost:5000 user@LINUX_IP
python client.py --server http://127.0.0.1:5000
```

> **SSH tunnel on Windows:**  
> Windows 10/11 includes OpenSSH by default. Open PowerShell or CMD and run:
> ```powershell
> ssh -L 5000:localhost:5000 user@LINUX_IP
> ```

---

## Step 6 — Connect Claude Desktop

Claude Desktop reads MCP server configuration from a JSON file on your machine.

### Find the config file

| OS | Config file location |
|---|---|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

### Edit the config file

Open the config file in any text editor and add the `mcpServers` block.

**Linux / macOS:**

```json
{
  "mcpServers": {
    "pentest-mcp": {
      "command": "python3",
      "args": [
        "/full/path/to/repo/client.py",
        "--server", "http://127.0.0.1:5000"
      ]
    }
  }
}
```

**Windows:**

```json
{
  "mcpServers": {
    "pentest-mcp": {
      "command": "C:\\path\\to\\repo\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\repo\\client.py",
        "--server", "http://127.0.0.1:5000"
      ]
    }
  }
}
```

> **Important:** Always use the **full absolute path** to `client.py`.  
> Linux example: `/home/kali/pentest-mcp/client.py`  
> Windows example: `C:\\Users\\YourName\\pentest-mcp\\client.py`

If you already have other MCP servers configured, add `pentest-mcp` alongside them:

```json
{
  "mcpServers": {
    "some-other-server": { "...": "..." },
    "pentest-mcp": {
      "command": "python3",
      "args": ["/home/kali/pentest-mcp/client.py", "--server", "http://127.0.0.1:5000"]
    }
  }
}
```

### Restart Claude Desktop

Fully quit and reopen Claude Desktop for the config to take effect.  
On macOS: `Cmd+Q` → reopen. On Windows: right-click taskbar icon → Quit → reopen.

---

## Step 7 — Verify Everything Works

In Claude Desktop, open a new chat and type:

```
Check the health of the pentest server
```

Claude should call `server_health` and show a table of all tools and their availability.

Then try a real test:

```
Run a whois lookup on example.com
```

Claude will call `whois_lookup` and return the domain registration info.

If both work — your full setup is complete. ✅

---

## Usage Examples

Once connected, talk to Claude naturally. Here are example prompts:

**Port Scanning**
```
Scan 10.10.10.5 for open ports and running services
```

**Subdomain Enumeration**
```
Find all subdomains of target.com using subfinder and amass
```

**Web Fingerprinting + WAF Detection**
```
Fingerprint the tech stack on http://10.10.10.5 with whatweb and check for a WAF with wafw00f
```

**Directory Brute-Force**
```
Run gobuster on http://10.10.10.5 using the common.txt wordlist
```

**Web Fuzzing with ffuf**
```
Fuzz http://10.10.10.5/FUZZ for hidden directories, filter out 404 responses
```

**SQL Injection Testing**
```
Test http://10.10.10.5/login.php?id=1 for SQL injection with sqlmap
```

**Password Cracking**
```
Crack the hashes in /home/kali/hashes.txt using rockyou.txt with john
```

**Full Recon Workflow**
```
Do a full recon on 10.10.10.5:
1. Nmap all ports
2. Detect tech with whatweb
3. Brute-force directories with gobuster
4. Scan for web vulnerabilities with nikto
Give me a summary of all findings at the end.
```

---

## Configuration Reference

### server.py options

| Argument | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | IP to bind (`127.0.0.1` = local only, `0.0.0.0` = all interfaces) |
| `--port` | `5000` | Port to listen on |
| `--debug` | off | Enable verbose debug logging |

### client.py options

| Argument | Default | Description |
|---|---|---|
| `--server` | `http://localhost:5000` | Full URL of the Flask API server |
| `--timeout` | `300` | Request timeout in seconds (5 min) |
| `--debug` | off | Enable verbose debug logging |

### Environment Variables (server.py)

| Variable | Default | Description |
|---|---|---|
| `API_PORT` | `5000` | Override the default port |
| `DEBUG_MODE` | `0` | Set to `1` to enable debug mode |

---

## Troubleshooting

**Claude Desktop does not show the pentest tools**
- Make sure `server.py` is running and reachable
- Double-check the absolute path to `client.py` in the Claude Desktop config
- Fully quit and reopen Claude Desktop (not just close the window)
- Test `client.py` manually in a terminal to see any startup errors:
  ```bash
  python3 client.py --debug
  ```

**`curl http://localhost:5000/health` returns connection refused**
- `server.py` is not running — start it with `python3 server.py`
- Check if port 5000 is already in use: `sudo ss -tlnp | grep 5000`
- Try a different port: `python3 server.py --port 8080`

**SSH tunnel drops or disconnects**
- Add `-o ServerAliveInterval=60` to keep the tunnel alive:
  ```bash
  ssh -L 5000:localhost:5000 -o ServerAliveInterval=60 user@LINUX_IP
  ```

**Tool shows `false` in health check**
- That tool is not installed — install it: `sudo apt install <toolname>`
- For `dig`: `sudo apt install dnsutils`
- For `netstat`: `sudo apt install net-tools`

**`mcp` module not found**
```bash
pip install "mcp[cli]"
```

**Timeout errors on long-running scans (nmap, amass, metasploit)**
```bash
python3 client.py --server http://127.0.0.1:5000 --timeout 600
```

**Permission denied running nmap SYN scans or metasploit**
```bash
sudo python3 server.py
```

**Windows — red error when activating venv**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

---

## Security Warning

> ⚠️ **Only use this tool against systems you own or have explicit written permission to test.**  
> Unauthorised scanning and exploitation is illegal in most countries.  
> This tool is intended for CTF challenges, home labs, and authorised penetration testing engagements only.

- **Always prefer `--ip 127.0.0.1` (default).** Keeps the API server accessible from localhost only.
- **Use SSH tunnels for remote setups.** Tunnelling encrypts traffic and avoids exposing the server to the network.
- **Never bind to `0.0.0.0` on a public or shared network.** Doing so exposes a remote code execution surface to anyone on that network.

---

## License

MIT — This project is for educational and authorised security testing purposes only.
