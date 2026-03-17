<div align="center">

# KaliWall
### Linux Firewall Manager with Real-Time Dashboard and CLI

[![Go Version](https://img.shields.io/github/go-mod/go-version/lamic/KaliWall?style=for-the-badge&logo=go&logoColor=white&color=00ADD8)](https://golang.org)
[![License](https://img.shields.io/github/license/lamic/KaliWall?style=for-the-badge&color=1f6feb)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-f08c00?style=for-the-badge&logo=linux&logoColor=white)](https://www.linux.org)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-2ea043?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://opensource.org)

<br/>

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3czamx6NDZ2YmV6YmR4aDV2a3ZnOGZ5d3JrdGdqaDIzbGZ5djJ6OSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3o7bu3XilJ5BOiSGic/giphy.gif" alt="KaliWall dashboard preview" width="100%" style="border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.35);" />

<br/>

KaliWall is an open-source firewall platform for Linux. It combines live firewall control, traffic visibility, GeoIP telemetry, threat intelligence, and DPI controls through a web dashboard and CLI.

[Quick Start](#quick-start) • [Features](#features) • [API](#api-highlights) • [Open Source](#open-source)

</div>

---

## Features

### Core Firewall
- Rule lifecycle: create, update, validate, analyze, toggle, and delete rules.
- Multi-backend support: `iptables`, `nftables`, `ufw`, or memory fallback mode.
- Runtime backend switch via API/dashboard.
- Safe default rule seeding on first run.

### Blocklists and Access Control
- Block/unblock IP addresses with reasons and history.
- Block/unblock websites/domains.
- Persistent blocked entries via local database storage.

### Monitoring and Visibility
- Live traffic logs and streaming events (SSE).
- Active connection visibility and system health stats.
- Firewall event stream for near real-time UI updates.
- DNS visibility with cache stats, manual refresh, and cache clear endpoint.

### Analytics and Intelligence
- Bandwidth and analytics metrics with stream endpoint.
- VirusTotal integration for IP reputation lookups.
- Threat cache listing and API key management.
- GeoIP attack telemetry with stream support.

### GeoIP Support
- MaxMind `.mmdb` support (`GeoLite2-City.mmdb`).
- IP2Location CSV support (`IP2LOCATION-LITE-DB1.CSV`).
- Automatic Geo database path resolution and persistence.

### DPI Pipeline
- Optional DPI pipeline with runtime on/off controls.
- Configurable interface, workers, BPF filter, promiscuous mode, and rate limiting.
- DPI status endpoint for dashboard observability.

### UX and Tooling
- FortiGate-inspired web UI in plain HTML/CSS/JS.
- Full CLI client for rules, blocklists, status, logs, threats, and connections.
- Background daemon start support through startup script.

---

## Quick Start

### Prerequisites
- Linux host (Ubuntu/Debian recommended).
- Root privileges for live firewall backend operations.
- Go toolchain (for source builds).

### Setup

```bash
git clone https://github.com/sujallamichhane18/KaliWall.git
cd KaliWall
chmod +x setup.sh && ./setup.sh
```

### Run

Default background mode:

```bash
chmod +x start.sh && ./start.sh
```

Foreground mode:

```bash
./start.sh --foreground
```

Dashboard: `http://localhost:8080`

---

## API Highlights

Base URL: `http://localhost:8080/api/v1`

- Rules: `/rules`, `/rules/{id}`, `/rules/validate`, `/rules/analyze`
- Firewall engine: `/firewall/engine`, `/firewall/logs`
- Traffic and logs: `/logs`, `/logs/stream`, `/events`, `/events/stream`, `/traffic/visibility`
- Network/DNS: `/connections`, `/dns/stats`, `/dns/refresh`, `/dns/cache`
- Threat intel: `/threat/apikey`, `/threat/check/{ip}`, `/threat/cache`
- Analytics: `/analytics`, `/analytics/stream`
- Geo: `/geo/attacks`, `/geo/stream`
- DPI: `/dpi/status`, `/dpi/control`
- Blocklists: `/blocked`, `/blocked/{ip}`, `/websites`, `/websites/{domain}`

---

## Configuration

GeoIP files are auto-detected from common project paths. Supported files:

- `GeoLite2-City.mmdb`
- `IP2LOCATION-LITE-DB1.CSV`

You can also pass an explicit path with:

```bash
./kaliwall --geo-db /path/to/GeoLite2-City.mmdb
```

or

```bash
./kaliwall --geo-db /path/to/IP2LOCATION-LITE-DB1.CSV
```

---

## Open Source

KaliWall is an open-source project and welcomes contributions.

- Report issues and feature requests in GitHub Issues.
- Open pull requests for fixes, docs, and enhancements.
- Keep changes focused and tested.

---

<div align="center">
  <sub>Built for the open-source security community.</sub>
</div>
