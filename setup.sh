#!/usr/bin/env bash
# KaliWall — One-line setup script for Linux
# Usage: chmod +x setup.sh && ./setup.sh
#
# This script:
#   1. Installs Go (if not present)
#   2. Downloads the uuid dependency
#   3. Builds and starts the KaliWall daemon

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  KaliWall — Firewall Setup             ${NC}"
echo -e "${GREEN}========================================${NC}"

# 1. Check / Install Go
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Go not found. Installing Go 1.22...${NC}"
    GO_TAR="go1.22.0.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> ~/.bashrc
    rm -f "/tmp/${GO_TAR}"
    echo -e "${GREEN}[+] Go installed: $(go version)${NC}"
else
    echo -e "${GREEN}[+] Go already installed: $(go version)${NC}"
fi

# 2. Navigate to project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Download dependencies
echo -e "${YELLOW}[*] Downloading Go dependencies...${NC}"
go mod tidy

# 4. Build
echo -e "${YELLOW}[*] Building KaliWall...${NC}"
go build -o kaliwall main.go
echo -e "${GREEN}[+] Build complete: ./kaliwall${NC}"

# 5. Run
echo ""
echo -e "${GREEN}[+] Starting KaliWall daemon...${NC}"
echo -e "${GREEN}[+] Open http://localhost:8080 in your browser${NC}"
echo -e "${YELLOW}[!] Run with sudo for live iptables integration${NC}"
echo ""
./kaliwall
