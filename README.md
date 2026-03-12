# KaliWall — Linux Firewall Management

A professional, web-based Linux firewall manager built with Go. Provides a clean FortiGate-style dashboard for managing `iptables` firewall rules, monitoring active connections, and viewing traffic logs.

## Features

- **Firewall Rules Management** — Add, remove, toggle, and list rules via REST API or Web UI
- **iptables Integration** — Applies rules to the Linux kernel firewall when running as root
- **Active Connections** — Reads `/proc/net/tcp` for real-time connection monitoring
- **Traffic Logging** — Logs all configuration changes and traffic decisions to `logs/kaliwall.log`
- **Professional Web UI** — Card-based dashboard with FontAwesome icons, responsive layout
- **Demo Mode** — Runs on any system with sample data (no root required for testing)

## Quick Start (One-Line)

```bash
chmod +x setup.sh && ./setup.sh
```

This installs Go (if needed), downloads dependencies, builds, and starts the server.

## Manual Setup

```bash
# Install Go (if not installed)
# https://go.dev/dl/

# Download dependencies
go mod tidy

# Build
go build -o kaliwall main.go

# Run (demo mode)
./kaliwall

# Run with iptables (requires root)
sudo ./kaliwall
```

Open **http://localhost:8080** in your browser.

## Project Structure

```
KaliWall/
├── main.go                      # Entry point — daemon setup
├── go.mod                       # Go module definition
├── setup.sh                     # One-line setup script
├── internal/
│   ├── api/
│   │   └── handlers.go          # REST API routes and handlers
│   ├── firewall/
│   │   └── firewall.go          # iptables integration & rule engine
│   ├── logger/
│   │   └── logger.go            # Traffic & event logger
│   └── models/
│       └── models.go            # Shared data structures
├── web/
│   ├── index.html               # Dashboard UI
│   ├── css/
│   │   └── style.css            # FortiGate-inspired stylesheet
│   └── js/
│       └── app.js               # Frontend application logic
└── logs/
    └── kaliwall.log             # Traffic log output
```

## REST API

| Method | Endpoint               | Description               |
|--------|------------------------|---------------------------|
| GET    | `/api/v1/rules`        | List all firewall rules   |
| POST   | `/api/v1/rules`        | Add a new rule            |
| GET    | `/api/v1/rules/{id}`   | Get a specific rule       |
| DELETE | `/api/v1/rules/{id}`   | Delete a rule             |
| PATCH  | `/api/v1/rules/{id}`   | Toggle rule enabled state |
| GET    | `/api/v1/stats`        | Dashboard statistics      |
| GET    | `/api/v1/connections`  | Active TCP connections    |
| GET    | `/api/v1/logs?limit=N` | Recent traffic log entries|

### Example: Add a Rule

```bash
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "INPUT",
    "protocol": "tcp",
    "src_ip": "any",
    "dst_ip": "any",
    "src_port": "any",
    "dst_port": "8443",
    "action": "DROP",
    "comment": "Block port 8443",
    "enabled": true
  }'
```

### Example: List Rules

```bash
curl http://localhost:8080/api/v1/rules | jq
```

## Requirements

- **Linux** (for iptables integration; demo mode works anywhere)
- **Go 1.21+**
- **Root access** (for live firewall rule application)

## License

MIT
