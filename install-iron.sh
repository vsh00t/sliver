#!/bin/bash
# Sliver IronCybersec Fork — Installation Script
# Builds and installs sliver-server and sliver-client from the IronCybersec fork
# with expanded MCP (42 tools), advanced evasion, and LLM operation support.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/vsh00t/sliver/feature/mcp-evasion-llm/install-iron.sh | sudo bash
#
# Or clone and run manually:
#   git clone -b feature/mcp-evasion-llm https://github.com/vsh00t/sliver.git
#   cd sliver && sudo bash install-iron.sh

set -e

REPO_URL="https://github.com/vsh00t/sliver.git"
BRANCH="feature/mcp-evasion-llm"
INSTALL_DIR="/opt/sliver-ironcybersec"
BIN_DIR="/usr/local/bin"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Sliver C2 — IronCybersec Fork Installer        ║"
echo "║  42 MCP Tools · Advanced Evasion · LLM Support  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# --- Root check ---
if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run as root"
    exit 1
fi

# --- Dependencies ---
echo "[*] Checking dependencies..."

MISSING=()
for cmd in git go make; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING+=("$cmd")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[*] Installing missing dependencies: ${MISSING[*]}"
    if command -v apt-get &> /dev/null; then
        apt-get update -qq
        apt-get install -yqq "${MISSING[@]}" build-essential
    elif command -v yum &> /dev/null; then
        yum -y install "${MISSING[@]}" make gcc
    elif command -v pacman &>/dev/null; then
        pacman --noconfirm -S "${MISSING[@]}"
    else
        echo "[-] Cannot install dependencies. Please install: ${MISSING[*]}"
        exit 1
    fi
fi

# --- Go version check ---
GO_MAJOR=$(go version | cut -c14- | cut -d' ' -f1 | cut -d'.' -f2)
if [[ "$GO_MAJOR" -lt 25 ]]; then
    echo "[-] Go 1.25+ required (found 1.$GO_MAJOR). Installing Go 1.26..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GOARCH="amd64" ;;
        aarch64) GOARCH="arm64" ;;
        *) echo "[-] Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    cd /tmp
    curl -sLO "https://go.dev/dl/go1.26.0.linux-${GOARCH}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go1.26.0.linux-${GOARCH}.tar.gz"
    export PATH="/usr/local/go/bin:$PATH"
    rm -f "go1.26.0.linux-${GOARCH}.tar.gz"
    echo "[+] Go installed: $(go version)"
fi

# --- Clone or update ---
TEMP_BUILD="/tmp/sliver-iron-build"
if [[ -d "$TEMP_BUILD" ]]; then
    echo "[*] Updating existing clone..."
    cd "$TEMP_BUILD"
    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
else
    echo "[*] Cloning IronCybersec fork..."
    git clone --depth=1 -b "$BRANCH" "$REPO_URL" "$TEMP_BUILD"
    cd "$TEMP_BUILD"
fi

echo "[*] Repo: $(pwd)"
echo "[*] Branch: $(git branch --show-current)"
echo "[*] Commit: $(git log --oneline -1)"

# --- Build ---
echo ""
echo "[*] Building sliver-server and sliver-client..."
echo "    (this takes 3-10 minutes depending on hardware)"
echo ""

# Build both server and client
make clean 2>/dev/null || true
make linux-amd64 2>&1 | tail -5

# Verify binaries
if [[ ! -f "sliver-server" || ! -f "sliver-client" ]]; then
    echo "[-] Build failed — sliver-server or sliver-client not found"
    echo "[*] Check build output above"
    exit 1
fi

echo ""
echo "[+] Build successful!"

# --- Install ---
echo "[*] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

cp sliver-server "$INSTALL_DIR/"
cp sliver-client "$INSTALL_DIR/"

# Symlinks
ln -sf "$INSTALL_DIR/sliver-server" "$BIN_DIR/sliver-server"
ln -sf "$INSTALL_DIR/sliver-client" "$BIN_DIR/sliver"

# --- MCP Server config ---
echo "[*] Creating MCP server configuration..."
mkdir -p "$INSTALL_DIR/config"
cat > "$INSTALL_DIR/config/mcp.json" << 'MCPCONF'
{
    "server_name": "sliver-ironcybersec",
    "server_version": "1.0.0-mcp-evasion",
    "transport": "stdio",
    "auth_token": "",
    "safety": {
        "require_confirmation": true,
        "max_ops_per_minute": 10,
        "max_concurrent_destructive": 3,
        "auto_approve_read": true
    }
}
MCPCONF

echo "[*] Setting up systemd service (optional)..."
cat > /etc/systemd/system/sliver-iron.service << 'SVCEOF'
[Unit]
Description=Sliver C2 Server (IronCybersec Fork)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sliver-server daemon
Restart=on-failure
RestartSec=5
WorkingDirectory=/opt/sliver-ironcybersec

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
echo "[+] Service installed: systemctl start sliver-iron"

# --- Cleanup ---
echo ""
echo "[+] Installation complete!"
echo ""
echo "    Binaries:"
echo "      Server: $BIN_DIR/sliver-server"
echo "      Client: $BIN_DIR/sliver (sliver-client)"
echo ""
echo "    MCP Config: $INSTALL_DIR/config/mcp.json"
echo ""
echo "    Quick start:"
echo "      sliver-server daemon          # Start C2 server"
echo "      sliver                        # Connect with client"
echo ""
echo "    MCP mode (for LLM operation):"
echo "      sliver mcp-server             # Start MCP server for LLM"
echo ""
echo "    Features in this fork:"
echo "      • 42 MCP tools (was 12)"
echo "      • HellsGate/HalosGate indirect syscalls"
echo "      • Ekko-style sleep mask"
echo "      • Dynamic AMSI/ETW bypass (hash-based)"
echo "      • Thread stack spoofing"
echo "      • Safety middleware (rate limit, audit, confirmation)"
echo ""
