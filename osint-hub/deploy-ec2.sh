#!/bin/bash
# ============================================================
# OSINT Hub V6 - EC2 Deployment Script
# ============================================================
# Run on your Ubuntu 24.04 EC2 instance:
#
#   Option A (one-liner):
#     curl -sSL https://raw.githubusercontent.com/douglashyde/spiderfoot/claude/install-dependencies-rAKAC/osint-hub/deploy-ec2.sh | bash
#
#   Option B (clone first):
#     git clone -b claude/install-dependencies-rAKAC https://github.com/douglashyde/spiderfoot.git
#     cd spiderfoot/osint-hub
#     bash deploy-ec2.sh
# ============================================================

set -e

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   OSINT Hub V6 - EC2 Deployment              ║"
echo "  ║   41 tools | Kimi AI | Full data pull         ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ----------------------------------------------------------
# Step 0: System updates
# ----------------------------------------------------------
echo "[*] Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
echo "  [+] System updated"

# ----------------------------------------------------------
# Step 1: Install Docker if not present
# ----------------------------------------------------------
if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
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

# ----------------------------------------------------------
# Step 2: Install docker compose plugin if not present
# ----------------------------------------------------------
if ! docker compose version &> /dev/null 2>&1; then
    echo "[*] Installing docker compose plugin..."
    sudo apt-get install -y -qq docker-compose-plugin
    echo "  [+] docker compose installed"
else
    echo "  [+] docker compose already installed"
fi

# ----------------------------------------------------------
# Step 3: Get the code
# ----------------------------------------------------------
DEPLOY_DIR="$HOME/osint-hub"

if [ -f "./Dockerfile" ] && [ -f "./app.py" ]; then
    echo "[*] Using current directory..."
    DEPLOY_DIR="$(pwd)"
elif [ -d "$DEPLOY_DIR" ]; then
    echo "[*] Updating existing $DEPLOY_DIR..."
    cd "$DEPLOY_DIR"
    git pull origin claude/install-dependencies-rAKAC 2>/dev/null || true
else
    echo "[*] Cloning OSINT Hub from GitHub..."
    git clone --depth 1 -b claude/install-dependencies-rAKAC \
        https://github.com/douglashyde/spiderfoot.git "$HOME/spiderfoot-tmp"
    cp -r "$HOME/spiderfoot-tmp/osint-hub" "$DEPLOY_DIR"
    rm -rf "$HOME/spiderfoot-tmp"
    echo "  [+] Code cloned to $DEPLOY_DIR"
fi

cd "$DEPLOY_DIR"

# ----------------------------------------------------------
# Step 4: Configure firewall (allow HTTP)
# ----------------------------------------------------------
echo "[*] Configuring firewall..."
sudo ufw allow 80/tcp 2>/dev/null || true
sudo ufw allow 443/tcp 2>/dev/null || true
echo "  [+] Ports 80 and 443 allowed"

# ----------------------------------------------------------
# Step 5: Build and run with Docker
# ----------------------------------------------------------
echo ""
echo "[*] Building Docker image (first build takes 5-10 min)..."
sudo docker compose down 2>/dev/null || true
sudo docker compose up -d --build

echo ""
echo "[*] Waiting for container to start..."
sleep 15

# ----------------------------------------------------------
# Step 6: Verify and display info
# ----------------------------------------------------------
if sudo docker compose ps | grep -q "Up\|running"; then
    # Get the public IP (EC2 metadata endpoint)
    PUBLIC_IP=$(curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "YOUR_EC2_IP")

    # Test the API
    TOOL_COUNT=$(curl -s --connect-timeout 5 http://localhost:80/api/tools 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?")

    echo ""
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║                                                       ║"
    echo "  ║   OSINT Hub V6 is LIVE!                               ║"
    echo "  ║                                                       ║"
    echo "  ╠══════════════════════════════════════════════════════╣"
    echo "  ║                                                       ║"
    echo "  ║   Local:    http://localhost                           ║"
    echo "  ║   Public:   http://$PUBLIC_IP                         ║"
    echo "  ║                                                       ║"
    echo "  ║   Dashboard: http://$PUBLIC_IP/                       ║"
    echo "  ║   Scan:      http://$PUBLIC_IP/scan                   ║"
    echo "  ║   Results:   http://$PUBLIC_IP/results                ║"
    echo "  ║   Graph:     http://$PUBLIC_IP/graph                  ║"
    echo "  ║   API:       http://$PUBLIC_IP/api/tools              ║"
    echo "  ║                                                       ║"
    echo "  ║   Tools: $TOOL_COUNT | Kimi AI | Full data pull       ║"
    echo "  ║                                                       ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "  IMPORTANT: Make sure your EC2 Security Group allows"
    echo "  inbound traffic on port 80 (HTTP) from your IP!"
    echo ""
    echo "  Commands:"
    echo "    Logs:      sudo docker compose logs -f"
    echo "    Stop:      sudo docker compose down"
    echo "    Restart:   sudo docker compose restart"
    echo "    Update:    git pull && sudo docker compose up -d --build"
    echo ""
    echo "  Set Kimi API key (optional):"
    echo "    sudo docker compose down"
    echo "    echo 'KIMI_API_KEY=your-key-here' >> .env"
    echo "    sudo docker compose up -d"
    echo ""
else
    echo "[!] Container may still be starting. Check with:"
    echo "    sudo docker compose logs -f"
fi
