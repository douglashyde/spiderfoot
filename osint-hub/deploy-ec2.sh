#!/bin/bash
# OSINT Hub - One-shot EC2 deployment script
# Run on a fresh Ubuntu 24.04 EC2 instance:
#   curl -sSL <raw-url>/deploy-ec2.sh | bash
#
# Or clone and run:
#   git clone <repo> && cd osint-hub && bash deploy-ec2.sh

set -e

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   OSINT Hub - EC2 Deployment                 ║"
echo "  ║   Setting up Docker + launching              ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# Step 1: Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq ca-certificates curl
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo usermod -aG docker $USER
    echo "  [+] Docker installed"
else
    echo "  [+] Docker already installed"
fi

# Step 2: Install docker-compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "[*] Installing docker-compose..."
    sudo apt-get install -y -qq docker-compose-plugin
    echo "  [+] docker-compose installed"
fi

# Step 3: Get the code
DEPLOY_DIR="$HOME/osint-hub-deploy"

if [ -f "./Dockerfile" ] && [ -f "./app.py" ]; then
    echo "[*] Using current directory..."
    DEPLOY_DIR="$(pwd)"
elif [ -d "$DEPLOY_DIR" ]; then
    echo "[*] Using existing $DEPLOY_DIR..."
    cd "$DEPLOY_DIR"
else
    echo "[*] Cloning OSINT Hub..."
    # Clone from any of the repos that have osint-hub
    git clone --depth 1 -b claude/install-dependencies-rAKAC \
        https://github.com/douglashyde/spiderfoot.git "$DEPLOY_DIR-tmp" 2>/dev/null || true
    if [ -d "$DEPLOY_DIR-tmp/osint-hub" ]; then
        mv "$DEPLOY_DIR-tmp/osint-hub" "$DEPLOY_DIR"
        rm -rf "$DEPLOY_DIR-tmp"
    fi
    cd "$DEPLOY_DIR"
fi

cd "$DEPLOY_DIR"

# Step 4: Build and run
echo ""
echo "[*] Building Docker image (this takes 5-10 min first time)..."
sudo docker compose down 2>/dev/null || true
sudo docker compose up -d --build

echo ""
echo "[*] Waiting for container to be healthy..."
sleep 10

# Check if running
if sudo docker compose ps | grep -q "Up"; then
    # Get the public IP
    PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "YOUR_EC2_IP")

    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   OSINT Hub is LIVE!                              ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║                                                   ║"
    echo "  ║   Local:   http://localhost                       ║"
    echo "  ║   Public:  http://$PUBLIC_IP                      ║"
    echo "  ║                                                   ║"
    echo "  ║   API:     http://$PUBLIC_IP/api/tools            ║"
    echo "  ║   Scan:    http://$PUBLIC_IP/scan                 ║"
    echo "  ║                                                   ║"
    echo "  ║   26 tools | 28 finding types | 4-phase correlator║"
    echo "  ║                                                   ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  Logs:    sudo docker compose logs -f"
    echo "  Stop:    sudo docker compose down"
    echo "  Restart: sudo docker compose restart"
    echo ""
else
    echo "[!] Container may still be starting. Check with:"
    echo "    sudo docker compose logs -f"
fi
