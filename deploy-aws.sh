#!/bin/bash
# ============================================
# OSINT Hub - AWS EC2 Deploy Script
# ============================================
#
# STEP 1: Launch an EC2 instance
#   - Go to AWS Console > EC2 > Launch Instance
#   - Choose: Ubuntu 22.04 LTS (t2.medium or larger)
#   - Storage: 30GB+
#   - Security Group: open port 5000 (or 80 if using nginx)
#   - Download your .pem key file
#
# STEP 2: SSH into your instance
#   ssh -i your-key.pem ubuntu@<your-ec2-public-ip>
#
# STEP 3: Run this script on the EC2 instance
#   curl -sSL https://raw.githubusercontent.com/douglashyde/spiderfoot/claude/install-dependencies-rAKAC/deploy-aws.sh | bash
#
#   OR copy this script and run it:
#   chmod +x deploy-aws.sh && ./deploy-aws.sh
#
# ============================================

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     OSINT Hub - AWS Deployment           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# System deps
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv git curl wget unzip > /dev/null 2>&1
echo "  Done."

# Clone repo
echo "[2/6] Cloning OSINT Hub monorepo..."
cd /home/ubuntu 2>/dev/null || cd ~
if [ -d "spiderfoot" ]; then
    cd spiderfoot
    git pull origin claude/install-dependencies-rAKAC
else
    git clone -b claude/install-dependencies-rAKAC https://github.com/douglashyde/spiderfoot.git
    cd spiderfoot
fi
echo "  Done."

# Create virtual environment
echo "[3/6] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install flask requests > /dev/null 2>&1
echo "  Done."

# Install tool dependencies
echo "[4/6] Installing tool dependencies..."

# holehe
pip install holehe 2>/dev/null || true

# maigret
pip install maigret 2>/dev/null || true

# sherlock
pip install sherlock-project 2>/dev/null || true

# theHarvester
if [ -d "tools-repos/theHarvester" ] && [ -f "tools-repos/theHarvester/requirements.txt" ]; then
    pip install -r tools-repos/theHarvester/requirements.txt 2>/dev/null || true
fi

# Cr3dOv3r
if [ -d "tools-repos/Cr3dOv3r" ] && [ -f "tools-repos/Cr3dOv3r/requirements.txt" ]; then
    pip install -r tools-repos/Cr3dOv3r/requirements.txt 2>/dev/null || true
fi

# h8mail
pip install h8mail 2>/dev/null || true

# phoneinfoga (Go binary)
if ! command -v phoneinfoga &> /dev/null; then
    curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install | bash
    sudo mv phoneinfoga /usr/local/bin/ 2>/dev/null || true
fi

# social-analyzer
pip install social-analyzer 2>/dev/null || true

echo "  Done."

# Update config for AWS paths
echo "[5/6] Configuring paths..."
DEPLOY_DIR=$(pwd)
cat > osint-hub/config.py << PYEOF
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)
TOOLS_DIR = os.path.join(REPO_ROOT, "tools-repos")
HOME_DIR = os.path.expanduser("~")


def _tool_path(dirname):
    mono = os.path.join(TOOLS_DIR, dirname)
    if os.path.isdir(mono):
        return mono
    home = os.path.join(HOME_DIR, dirname)
    if os.path.isdir(home):
        return home
    return mono


TOOL_PATHS = {
    "sherlock": _tool_path("sherlock"),
    "maigret": _tool_path("maigret"),
    "holehe": _tool_path("holehe"),
    "social_analyzer": _tool_path("social-analyzer"),
    "blackbird": _tool_path("blackbird"),
    "nexfil": _tool_path("nexfil"),
    "phoneinfoga": _tool_path("phoneinfoga"),
    "spiderfoot": REPO_ROOT,
    "theharvester": _tool_path("theHarvester"),
    "osintgram": _tool_path("Osintgram"),
    "ghunt": _tool_path("GHunt"),
    "x_osint": _tool_path("X-osint"),
    "leaksearch": _tool_path("LeakSearch"),
    "leaklooker": _tool_path("LeakLooker"),
    "cr3dov3r": _tool_path("Cr3dOv3r"),
    "comb2passlist": _tool_path("comb2passlist"),
    "oblivion": _tool_path("Oblivion"),
    "h8mail": _tool_path("h8mail"),
    "whatbreach": _tool_path("WhatBreach"),
    "findpeopleinfo": _tool_path("findpeopleinfo"),
}

DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SCAN_TIMEOUT = 300
MAX_CHAIN_DEPTH = 3
PYEOF
echo "  Done."

# Create systemd service for auto-start
echo "[6/6] Setting up service..."
sudo tee /etc/systemd/system/osint-hub.service > /dev/null << EOF
[Unit]
Description=OSINT Hub
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${DEPLOY_DIR}/osint-hub
ExecStart=${DEPLOY_DIR}/venv/bin/python3 ${DEPLOY_DIR}/osint-hub/app.py
Restart=always
RestartSec=5
Environment=PORT=5000
Environment=HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable osint-hub
sudo systemctl start osint-hub
echo "  Done."

# Get public IP
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "YOUR_EC2_IP")

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     OSINT Hub is LIVE!                   ║"
echo "╠══════════════════════════════════════════╣"
echo "║                                          ║"
echo "  URL: http://${PUBLIC_IP}:5000"
echo "║                                          ║"
echo "║  Commands:                               ║"
echo "║  sudo systemctl status osint-hub         ║"
echo "║  sudo systemctl restart osint-hub        ║"
echo "║  sudo journalctl -u osint-hub -f         ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "IMPORTANT: Make sure port 5000 is open in"
echo "your EC2 Security Group inbound rules!"
echo ""
