<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Firewall-iptables-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="iptables">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">🛡️ KaliWall</h1>

<p align="center">
  <strong>Linux Firewall Management System</strong><br>
  <em>Real-time dashboard • IP blocking • Website filtering • Threat intelligence • CLI & Web UI</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/VirusTotal-integrated-blue?style=flat-square" alt="VirusTotal">
  <img src="https://img.shields.io/badge/Chart.js-live%20charts-ff6384?style=flat-square" alt="Charts">
</p>

---

A web-based Linux firewall manager built with **Go**. Features a clean FortiGate-inspired dashboard for managing firewall rules, blocking IPs and websites, monitoring connections with live charts, and VirusTotal threat intelligence via both a **Web UI** and **CLI tool**.

## ✨ Features

### 🔥 Firewall Core
- **Rule Management** — Create, edit, toggle, and delete iptables rules via UI or API
- **IP Blocking** — One-click block/unblock IPs across INPUT, OUTPUT, and FORWARD chains
- **Website Blocking** — Domain-level filtering using iptables string matching
- **Persistent Storage** — JSON-backed database survives restarts — rules, blocks, and settings auto-restore

### 📊 Real-Time Monitoring
- **Live Bandwidth Charts** — RX/TX line graphs streamed via SSE (Server-Sent Events)
- **Protocol Breakdown** — Doughnut chart of TCP/UDP/ICMP distribution
- **Blocked vs Allowed** — Visual pie chart of firewall decisions
- **Top Talkers** — Horizontal bar chart of most active IPs
- **Active Connections** — Live `/proc/net/tcp` monitoring with threat indicators

### 🛡️ Threat Intelligence
- **VirusTotal Integration** — Automatic IP reputation lookups on active connections
- **Threat Dashboard** — Cached VT results with malicious/suspicious/safe counts, country, ASN, connection status
- **One-Click Block** — Block malicious IPs directly from the threat intel dashboard

### 🖥️ System Monitoring
- **CPU & Memory Gauges** — Real-time circular SVG gauges from `/proc/stat` and `/proc/meminfo`
- **Network Interfaces** — Per-interface RX/TX counters from `/proc/net/dev`
- **System Info** — Hostname, kernel version, uptime, load average

### ⌨️ CLI Tool
- **Full CLI Management** — `kaliwall-cli` for headless/scripted operation
- **All Features Accessible** — Rules, blocking, websites, threats, connections, logs
- **Daemon Mode** — Run as background service with PID management

## 🚀 Quick Start

### One-Line Setup

```bash
chmod +x setup.sh && ./setup.sh
```

### Start Firewall

```bash
chmod +x start.sh && ./start.sh
```

### Daemon Mode (Background)

```bash
sudo ./start.sh --daemon
```

### Deep Packet Inspection (DPI)

```bash
# Run with DPI enabled (requires root for pcap capture)
sudo ./kaliwall \
  --dpi \
  --dpi-interface eth0 \
  --dpi-rules configs/dpi-rules.yaml \
  --dpi-workers 8 \
  --dpi-promisc=true
```

Optional flags:

- `--dpi-bpf "tcp or udp port 53"` to reduce capture volume.
- `--dpi-rate 5000` to set per-source packet rate limiting.

### Logs and Status

```bash
# Show daemon status
./start.sh --status

# Show latest logs
./start.sh --logs

# Follow logs live
./start.sh --logs-follow

# Stop daemon
./start.sh --stop
```

### Systemd Service

```bash
sudo ./setup.sh --service
sudo ./start.sh --service
```

## 🔧 Manual Setup

```bash
# Install Go 1.21+ (https://go.dev/dl/)

# Download dependencies
go mod tidy

# Build daemon + CLI
go build -o kaliwall main.go
go build -o kaliwall-cli ./cmd/kaliwall-cli

# Run DPI unit tests
go test ./internal/dpi/...

# Run (foreground)
sudo ./kaliwall

# Or run as daemon
sudo ./kaliwall --daemon
```

Open **http://localhost:8080** in your browser.

## 🔬 DPI Architecture

KaliWall DPI uses a modular pipeline:

`Packet Capture -> Decode Layers -> Flow Tracking -> TCP Reassembly -> DPI Inspection -> Rule Engine -> Action`

Packages:

- `internal/dpi/capture` - live pcap capture, promiscuous mode, BPF filter support
- `internal/dpi/decode` - Ethernet/IPv4/TCP/UDP/DNS extraction with malformed packet safety
- `internal/dpi/flow` - 5-tuple tracking, expiration, optional per-source rate limit
- `internal/dpi/reassembly` - bounded TCP stream reassembly (out-of-order + retransmission safe)
- `internal/dpi/inspect` - HTTP method/host/url, DNS query, TLS SNI parsing, payload indicators
- `internal/dpi/rules` - YAML/JSON rule loading with `ALLOW/BLOCK/LOG` and optional regex rules
- `internal/dpi/action` - structured JSON decision logs and block/log side-effects
- `internal/dpi/pipeline` - worker pool orchestration and stage integration

Rule file example: `configs/dpi-rules.yaml`

## 📂 Project Structure

```
KaliWall/
├── main.go                          # Entry point — daemon, DB init, signal handling
├── go.mod                           # Go module (kaliwall)
├── setup.sh                         # Setup script (build + optional systemd install)
├── start.sh                         # Start script (foreground / daemon / systemd start)
├── cmd/
│   └── kaliwall-cli/
│       └── main.go                  # CLI tool — full firewall management
├── internal/
│   ├── api/
│   │   └── handlers.go              # REST API routes and handlers
│   ├── analytics/
│   │   └── analytics.go             # Bandwidth sampling & SSE streaming
│   ├── database/
│   │   └── database.go              # JSON-file persistent store
│   ├── firewall/
│   │   └── firewall.go              # Firewall engine — rules, IP/website blocking
│   ├── logger/
│   │   └── logger.go                # Traffic & event logger
│   ├── models/
│   │   └── models.go                # Shared data structures
│   ├── netmon/
│   │   └── netmon.go                # /proc/net/tcp connection parser
│   ├── sysinfo/
│   │   └── sysinfo.go               # CPU, memory, network from /proc
│   └── threatintel/
│       └── threatintel.go           # VirusTotal API integration
├── web/
│   ├── index.html                   # SPA — all pages (Dashboard, Rules, Blocked, Threats, Websites, Logs, Settings)
│   ├── css/
│   │   └── style.css                # FortiGate-inspired stylesheet
│   └── js/
│       └── app.js                   # Frontend application logic
├── data/
│   └── kaliwall.json                # Persistent database (auto-created)
└── logs/
    └── kaliwall.log                 # Traffic log output
```

## 🔌 REST API

### Core

| Method | Endpoint                | Description                     |
|--------|-------------------------|---------------------------------|
| GET    | `/api/v1/stats`         | Dashboard statistics            |
| GET    | `/api/v1/sysinfo`       | Real-time OS system info        |
| GET    | `/api/v1/connections`   | Active TCP/UDP connections      |
| GET    | `/api/v1/logs?limit=N`  | Recent traffic log entries      |
| GET    | `/api/v1/logs/stream`   | SSE real-time log stream        |
| GET    | `/api/v1/analytics`     | Bandwidth & chart data snapshot |
| GET    | `/api/v1/analytics/stream` | SSE live bandwidth stream    |

### Firewall Rules

| Method | Endpoint              | Description               |
|--------|-----------------------|---------------------------|
| GET    | `/api/v1/rules`       | List all firewall rules   |
| POST   | `/api/v1/rules`       | Create a new rule         |
| GET    | `/api/v1/rules/{id}`  | Get a specific rule       |
| PUT    | `/api/v1/rules/{id}`  | Update a rule             |
| DELETE | `/api/v1/rules/{id}`  | Delete a rule             |
| PATCH  | `/api/v1/rules/{id}`  | Toggle rule enabled state |

### IP Blocking

| Method | Endpoint               | Description           |
|--------|------------------------|-----------------------|
| GET    | `/api/v1/blocked`      | List blocked IPs      |
| POST   | `/api/v1/blocked`      | Block an IP           |
| DELETE | `/api/v1/blocked/{ip}` | Unblock an IP         |

### Website Blocking

| Method | Endpoint                    | Description             |
|--------|-----------------------------|-------------------------|
| GET    | `/api/v1/websites`          | List blocked websites   |
| POST   | `/api/v1/websites`          | Block a website         |
| DELETE | `/api/v1/websites/{domain}` | Unblock a website       |

### Threat Intelligence

| Method | Endpoint                      | Description                  |
|--------|-------------------------------|------------------------------|
| GET    | `/api/v1/threat/cache`        | All cached VT results        |
| GET    | `/api/v1/threat/check/{ip}`   | Check IP against VirusTotal  |
| POST   | `/api/v1/threat/apikey`       | Set VirusTotal API key       |
| GET    | `/api/v1/threat/apikey`       | Check API key status         |
| DELETE | `/api/v1/threat/apikey`       | Remove API key               |

## ⌨️ CLI Usage

```bash
# Check daemon status
./kaliwall-cli status

# List firewall rules
./kaliwall-cli rules list

# Add a rule
./kaliwall-cli rules add --chain INPUT --protocol tcp --dst-port 443 --action ACCEPT --comment "Allow HTTPS"

# Edit a rule
./kaliwall-cli rules update <id> --dst-port 8443 --comment "Updated port"

# Block an IP
./kaliwall-cli block 1.2.3.4 "Port scanner"

# Unblock an IP
./kaliwall-cli unblock 1.2.3.4

# List blocked IPs
./kaliwall-cli blocked

# Block a website
./kaliwall-cli website block example.com "Policy violation"

# List blocked websites
./kaliwall-cli websites

# Check threat intel for an IP
./kaliwall-cli threat 8.8.8.8

# View all cached threats
./kaliwall-cli threats

# View connections
./kaliwall-cli connections

# Tail logs
./kaliwall-cli logs --limit 50
```

## 📸 Screenshots
![KaliWall Screenshot](Screenshot%202026-03-12%20230832.png)
> The web UI features a FortiGate-inspired dark sidebar with a clean card-based layout including live bandwidth charts, CPU/memory gauges, threat intelligence dashboard, and full rule management.

## 🛡️ Security Notes

- Run with `sudo` for live firewall integration
- Without root, KaliWall operates in monitoring/demo mode
- VirusTotal API keys are stored locally in `data/kaliwall.json`
- All user inputs are validated and sanitized server-side
- No external database dependencies — fully self-contained

## 📋 Requirements

- **Go 1.21+**
- **Linux** (iptables, /proc filesystem)
- **Root/sudo** for firewall rule enforcement
- **VirusTotal API key** (optional, for threat intelligence)

---

<p align="center">
  made with &lt;3 by <strong>sujal lamichhane</strong>
</p>

<p align="center">
  <em>If you find this project useful, consider giving it a ⭐</em>
</p>
