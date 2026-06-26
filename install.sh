#!/bin/bash
set -e

# Sliver IronCybersec Fork — Installation Script
# Downloads pre-built binaries from GitHub releases (no compilation needed)
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/vsh00t/sliver/feature/mcp-evasion-llm/install.sh | sudo bash
#
# Based on the official Sliver install script pattern

SLIVER_VERSION="v1.0.0-ironcybersec"
SLIVER_REPO="vsh00t/sliver"
SLIVER_PLATFORM="linux"

if [[ "$EUID" -ne 0 ]];then
    echo "Please run as root"
    exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        SLIVER_PLATFORM="linux-amd64"
        ;;
    aarch64|arm64)
        SLIVER_PLATFORM="linux-arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Sliver C2 — IronCybersec Fork ${SLIVER_VERSION}           ║"
echo "║  42 MCP Tools · Advanced Evasion · LLM Support      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Install dependencies (only curl needed for download-only install)
if command -v apt-get &> /dev/null; then
    echo "[*] Ensuring curl is installed..."
    DEBIAN_FRONTEND=noninteractive apt-get install -yqq curl > /dev/null 2>&1
elif command -v yum &> /dev/null; then
    yum -y install curl > /dev/null 2>&1
elif command -v pacman &>/dev/null; then
    pacman --noconfirm -S curl > /dev/null 2>&1
fi

# Verify curl is available
if ! command -v curl &> /dev/null; then
    echo "[-] curl is required but not installed"
    exit 1
fi

cd /root || exit
echo "[*] Working directory: $(pwd)"

# --- Stop existing sliver if running ---
stop_existing_sliver() {
    local existing=""
    if test -x /root/sliver-server; then
        existing="/root/sliver-server"
    elif command -v sliver-server &> /dev/null; then
        existing="$(command -v sliver-server)"
    fi

    if [[ -z "$existing" ]]; then
        return 0
    fi

    echo "[*] Existing Sliver detected at $existing, stopping..."
    if command -v systemctl &> /dev/null && test -f /etc/systemd/system/sliver.service; then
        if systemctl is-active --quiet sliver; then
            systemctl stop sliver
        fi
    fi
    if command -v systemctl &> /dev/null && test -f /etc/systemd/system/sliver-iron.service; then
        if systemctl is-active --quiet sliver-iron; then
            systemctl stop sliver-iron
        fi
    fi
    if pgrep -f "sliver-server daemon" > /dev/null 2>&1; then
        pkill -f "sliver-server daemon"
    fi
}

# --- Download binaries from GitHub release ---
RELEASE_BASE="https://github.com/${SLIVER_REPO}/releases/download/${SLIVER_VERSION}"

echo "[*] Downloading sliver-server (${SLIVER_PLATFORM})..."
curl --silent -L "${RELEASE_BASE}/sliver-server.gz" --output /root/sliver-server.gz
if [[ ! -s /root/sliver-server.gz ]]; then
    echo "[-] Failed to download sliver-server.gz"
    exit 1
fi
echo "[+] Downloaded sliver-server.gz ($(du -h /root/sliver-server.gz | cut -f1))"

echo "[*] Downloading sliver-client (${SLIVER_PLATFORM})..."
curl --silent -L "${RELEASE_BASE}/sliver-client.gz" --output /root/sliver-client.gz
if [[ ! -s /root/sliver-client.gz ]]; then
    echo "[-] Failed to download sliver-client.gz"
    exit 1
fi
echo "[+] Downloaded sliver-client.gz ($(du -h /root/sliver-client.gz | cut -f1))"

# --- Decompress ---
echo "[*] Decompressing binaries..."
gunzip -f /root/sliver-server.gz
gunzip -f /root/sliver-client.gz

# --- Stop before replacing ---
stop_existing_sliver

# --- Install server ---
echo "[*] Installing sliver-server..."
chmod 755 /root/sliver-server
echo "[+] Running unpack..."
/root/sliver-server unpack --force

# --- Install client ---
echo "[*] Installing sliver-client..."
chmod 755 /root/sliver-client
cp -v /root/sliver-client /usr/local/bin/sliver-client
ln -sf /usr/local/bin/sliver-client /usr/local/bin/sliver
chmod 755 /usr/local/bin/sliver

# --- systemd service ---
echo "[*] Configuring systemd service..."
cat > /etc/systemd/system/sliver-iron.service << 'EOF'
[Unit]
Description=Sliver C2 Server (IronCybersec Fork)
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=root
ExecStart=/root/sliver-server daemon

[Install]
WantedBy=multi-user.target
EOF
chown root:root /etc/systemd/system/sliver-iron.service
chmod 600 /etc/systemd/system/sliver-iron.service

# --- Generate operator configs ---
echo "[*] Generating operator configs..."
mkdir -p /root/.sliver-client/configs
/root/sliver-server operator --name root --lhost 127.0.0.1 --permissions all --save /root/.sliver-client/configs
chown -R root:root /root/.sliver-client/

USER_DIRS=(/home/*)
for USER_DIR in "${USER_DIRS[@]}"; do
    USER=$(basename "$USER_DIR")
    if id -u "$USER" >/dev/null 2>&1; then
        echo "[*] Generating configs for user: $USER"
        mkdir -p "$USER_DIR/.sliver-client/configs"
        /root/sliver-server operator --name "$USER" --lhost 127.0.0.1 --permissions all --save "$USER_DIR/.sliver-client/configs"
        chown -R "$USER":"$(id -gn "$USER")" "$USER_DIR/.sliver-client/"
    fi
done

# --- Start service ---
echo "[*] Starting Sliver service..."
systemctl daemon-reload
systemctl start sliver-iron

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅ Installation Complete                            ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Server:  /root/sliver-server                        ║"
echo "║  Client:  /usr/local/bin/sliver                      ║"
echo "║  Service: systemctl status sliver-iron               ║"
echo "║                                                      ║"
echo "║  Quick start:                                        ║"
echo "║    sliver                                            ║"
echo "║                                                      ║"
echo "║  MCP mode (LLM operation):                           ║"
echo "║    sliver-server mcp-server                          ║"
echo "║                                                      ║"
echo "║  Features:                                           ║"
echo "║    • 42 MCP tools (was 12)                           ║"
echo "║    • HellsGate/HalosGate indirect syscalls           ║"
echo "║    • Ekko-style sleep mask                           ║"
echo "║    • Dynamic AMSI/ETW bypass                         ║"
echo "║    • Thread stack spoofing                           ║"
echo "║    • Safety middleware (audit, rate limit)            ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
