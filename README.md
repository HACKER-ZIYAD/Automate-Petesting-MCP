# Automate-Petesting-MCP


# 🛡️ Custom Pentest MCP Server

> Connect Claude AI to your Kali Linux machine via MCP (Model Context Protocol).  
> Let Claude plan, execute, and analyse penetration tests using real security tools — all from a chat window.

---

## 📋 Table of Contents

- [How It Works](#how-it-works)
- [Tools Available](#tools-available)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Step 1 — Clone the Repository](#step-1--clone-the-repository)
- [Step 2 — Install Python Dependencies](#step-2--install-python-dependencies)
- [Step 3 — Install Security Tools on Kali](#step-3--install-security-tools-on-kali)
- [Step 4 — Start the API Server](#step-4--start-the-api-server)
- [Step 5 — Configure the MCP Client](#step-5--configure-the-mcp-client)
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
                                                               │
                                                    ┌──────────▼───────────┐
                                                    │                      │
                                                    │   server.py          │
                                                    │   (Flask API)        │
                                                    │                      │
                                                    └──────────┬───────────┘
                                                               │
                                                        subprocess calls
                                                               │
                                        ┌──────────────────────▼──────────────────────┐
                                        │         Kali Linux Tools                    │
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

Before you begin, make sure you have:

| Requirement | Where to Get It |
|---|---|
| **Kali Linux** (VM, bare metal, or WSL) | [kali.org/get-kali](https://www.kali.org/get-kali/) |
| **Python 3.10+** on Kali | Pre-installed on Kali |
| **Claude Desktop** on your main machine | [claude.ai/download](https://claude.ai/download) |
| **Git** | Pre-installed on Kali |

> **Note:** `server.py` and the security tools run **on your Kali machine**.  
> `client.py` runs wherever Claude Desktop can reach it (can be the same Kali machine or a separate Linux/Mac/Windows host with Python).

---

## Project Structure

```
pentest-mcp/
├── server.py          # Flask API server — runs on Kali, executes tools
├── client.py          # MCP server — bridges Claude Desktop to the API
└── requirements.txt   # Python dependencies (flask, mcp, requests)
```

---

## Step 1 — Clone the Repository

Open a terminal on your **Kali machine** and run:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

> Replace `YOUR_USERNAME/YOUR_REPO_NAME` with your actual GitHub repo path.

---

## Step 2 — Install Python Dependencies

Still inside the project folder, run:

```bash
pip install -r requirements.txt
```

This installs:
- **flask** — runs the API server (`server.py`)
- **mcp[cli]** — provides FastMCP to expose tools to Claude (`client.py`)
- **requests** — lets `client.py` call `server.py` over HTTP

Verify the install:

```bash
pip show flask mcp requests
```

You should see version info for all three packages with no errors.

---

## Step 3 — Install Security Tools on Kali

Most tools are pre-installed on Kali. Run this to install any that are missing:

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

> **`dnsutils`** provides the `dig` command.  
> **`net-tools`** provides the `netstat` command.

Confirm all tools are found:

```bash
which nmap dirb gobuster ffuf nikto whatweb wafw00f subfinder amass \
      sqlmap whois dig curl netstat enum4linux hydra john msfconsole wpscan
```

Every line should print a path like `/usr/bin/nmap`. If any is missing, install it individually with `sudo apt install <toolname>`.

---

## Step 4 — Start the API Server

Run `server.py` on your Kali machine:

```bash
# Default — listens on localhost:5000 (safe, local only)
python3 server.py

# Custom port
python3 server.py --port 8080

# Allow connections from other machines on the network
# Use this if client.py runs on a different host than the Kali server
python3 server.py --ip 0.0.0.0 --port 5000

# Debug mode (verbose logging)
python3 server.py --debug
```

You should see:

```
2025-xx-xx [INFO] Starting Custom Pentest API Server on 127.0.0.1:5000
 * Running on http://127.0.0.1:5000
```

**Keep this terminal open.** The API server must stay running.

Test it in a second terminal:

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
    "dirb": true,
    "gobuster": true,
    ...
  },
  "all_tools_available": true
}
```

---

## Step 5 — Configure the MCP Client

Open `client.py` and update the server URL if needed:

```python
# Line 18 in client.py
DEFAULT_KALI_SERVER = "http://localhost:5000"
```

| Scenario | Value to set |
|---|---|
| `client.py` and `server.py` on the **same machine** | `http://localhost:5000` |
| `client.py` on your laptop, `server.py` on Kali VM | `http://KALI_IP:5000` (e.g. `http://192.168.1.50:5000`) |

> Find your Kali IP with: `ip a` or `hostname -I`

---

## Step 6 — Connect Claude Desktop

Claude Desktop reads MCP server configuration from a JSON file.

### Find the config file

| OS | Config file location |
|---|---|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

### Edit the config file

Open the config file in any text editor and add the `mcpServers` block:

```json
{
  "mcpServers": {
    "pentest-mcp": {
      "command": "python3",
      "args": [
        "/full/path/to/your/repo/client.py",
        "--server", "http://localhost:5000"
      ]
    }
  }
}
```

> **Important:** Replace `/full/path/to/your/repo/client.py` with the actual absolute path.  
> Example: `/home/kali/pentest-mcp/client.py`

If you already have other MCP servers in the config, add `pentest-mcp` alongside them:

```json
{
  "mcpServers": {
    "existing-server": { ... },
    "pentest-mcp": {
      "command": "python3",
      "args": ["/home/kali/pentest-mcp/client.py", "--server", "http://localhost:5000"]
    }
  }
}
```

### Restart Claude Desktop

Fully quit and reopen Claude Desktop for the config to take effect.

---

## Step 7 — Verify Everything Works

In Claude Desktop, open a new chat and type:

```
Check the health of the pentest server
```

Claude should call `server_health` and respond with a list of available tools and their status.

Then try a simple test:

```
Run a whois lookup on example.com
```

Claude will call `whois_lookup` and return the domain registration information.

If both work, your full setup is complete.

---

## Usage Examples

Once connected, just talk to Claude naturally. Here are some example prompts:

**Port Scanning**
```
Scan 10.10.10.5 for open ports and services
```

**Subdomain Enumeration**
```
Find all subdomains of target.com using subfinder and amass
```

**Web Recon**
```
Fingerprint the technology stack on http://10.10.10.5 using whatweb and check if there is a WAF
```

**Directory Brute-Force**
```
Run gobuster on http://10.10.10.5 using the common.txt wordlist
```

**Web Fuzzing with ffuf**
```
Fuzz http://10.10.10.5/FUZZ for hidden directories, filter out 404 responses
```

**SQL Injection**
```
Test http://10.10.10.5/login.php?id=1 for SQL injection using sqlmap
```

**Password Cracking**
```
Crack the hashes in /home/kali/hashes.txt using rockyou.txt with john
```

**Full Recon Workflow**
```
Do a full recon on 10.10.10.5:
1. Nmap scan all ports
2. Detect technologies with whatweb
3. Brute-force directories with gobuster
4. Scan for web vulnerabilities with nikto
Summarise the findings when done.
```

---

## Configuration Reference

### server.py options

| Argument | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | IP address to bind (use `0.0.0.0` for network access) |
| `--port` | `5000` | Port to listen on |
| `--debug` | off | Enable verbose debug logging |

### client.py options

| Argument | Default | Description |
|---|---|---|
| `--server` | `http://localhost:5000` | URL of the Flask API server |
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
- Make sure `server.py` is running and accessible
- Check the absolute path to `client.py` in the Claude Desktop config
- Fully restart Claude Desktop (quit completely, not just close the window)
- Run `client.py` manually in a terminal to see startup errors:
  ```bash
  python3 client.py --debug
  ```

**`curl http://localhost:5000/health` fails / connection refused**
- `server.py` is not running — start it with `python3 server.py`
- Check if something else is using port 5000: `sudo ss -tlnp | grep 5000`
- Try a different port: `python3 server.py --port 8080`

**Tool shows `false` in health check**
- The tool is not installed on Kali
- Install it: `sudo apt install <toolname>`
- For `dig` install `dnsutils`, for `netstat` install `net-tools`

**`mcp` module not found when running client.py**
```bash
pip install "mcp[cli]"
```

**Timeout errors on long scans (nmap, amass, metasploit)**
- Increase the timeout when starting `client.py`:
  ```bash
  python3 client.py --timeout 600
  ```
- Or set `COMMAND_TIMEOUT` in `server.py` to a higher value (default is 180 seconds)

**Permission denied running nmap or metasploit**
- Some nmap scan types require root:
  ```bash
  sudo python3 server.py
  ```

---

## Security Warning

> ⚠️ **Only use this tool against systems you own or have explicit written permission to test.**  
> Unauthorised scanning or exploitation is illegal in most countries.  
> This tool is intended for CTF challenges, home labs, and authorised penetration testing engagements only.

**Keep `server.py` on localhost (`127.0.0.1`) unless you fully understand the network exposure.**  
Binding to `0.0.0.0` exposes a remote code execution surface on your network.

---

## License

This project is for educational and authorised security testing purposes only.
