#!/bin/bash
# OSINT Hub - Full Setup & Launch Script
# Run: chmod +x setup_and_launch.sh && ./setup_and_launch.sh

set -e
HOME_DIR="$HOME"
cd "$HOME_DIR"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   OSINT Hub - Full Setup & Launch            ║"
echo "  ║   Installing all tools + dependencies        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# System deps
echo "[*] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv git curl wget > /dev/null 2>&1
echo "  [+] System deps OK"

# Create a venv for osint-hub
echo "[*] Setting up Python virtual environment..."
if [ ! -d "$HOME_DIR/osint-hub/venv" ]; then
    python3 -m venv "$HOME_DIR/osint-hub/venv"
fi
source "$HOME_DIR/osint-hub/venv/bin/activate"
pip install --quiet --upgrade pip

# Install flask for the hub
pip install --quiet flask requests

# ─── Clone & install tools ────────────────────────────────────

clone_tool() {
    local name="$1"
    local repo="$2"
    local dir="$HOME_DIR/$name"
    if [ -d "$dir" ]; then
        echo "  [+] $name (already exists)"
    else
        echo "  [~] Cloning $name..."
        git clone --depth 1 --quiet "$repo" "$dir" 2>/dev/null || echo "  [-] Failed to clone $name"
    fi
}

echo ""
echo "[*] Cloning OSINT tools..."

# Username search tools
clone_tool "sherlock" "https://github.com/sherlock-project/sherlock.git"
clone_tool "maigret" "https://github.com/soxoj/maigret.git"
clone_tool "blackbird" "https://github.com/p1ngul1n0/blackbird.git"
clone_tool "nexfil" "https://github.com/thewhiteh4t/nexfil.git"

# Email OSINT
clone_tool "holehe" "https://github.com/megadose/holehe.git"
clone_tool "theHarvester" "https://github.com/laramies/theHarvester.git"
clone_tool "GHunt" "https://github.com/mxrch/GHunt.git"

# Phone OSINT
clone_tool "phoneinfoga" "https://github.com/sundowndev/phoneinfoga.git"

# Social
clone_tool "social-analyzer" "https://github.com/qeeqbox/social-analyzer.git"

# Breach tools
clone_tool "h8mail" "https://github.com/khast3x/h8mail.git"
clone_tool "WhatBreach" "https://github.com/Ekultek/WhatBreach.git"
clone_tool "LeakSearch" "https://github.com/JoelGMSec/LeakSearch.git"
clone_tool "Cr3dOv3r" "https://github.com/D4Vinci/Cr3dOv3r.git"
clone_tool "comb2passlist" "https://github.com/JoelGMSec/comb2passlist.git"

# Frameworks - spiderfoot should already exist
clone_tool "spiderfoot" "https://github.com/smicallef/spiderfoot.git"

echo ""
echo "[*] Installing Python dependencies for tools..."

# Sherlock
if [ -d "$HOME_DIR/sherlock" ]; then
    pip install --quiet sherlock-project 2>/dev/null && echo "  [+] sherlock deps" || echo "  [-] sherlock deps failed"
fi

# Maigret
if [ -d "$HOME_DIR/maigret" ]; then
    pip install --quiet maigret 2>/dev/null && echo "  [+] maigret deps" || echo "  [-] maigret deps failed"
fi

# Holehe
if [ -d "$HOME_DIR/holehe" ]; then
    pip install --quiet holehe 2>/dev/null && echo "  [+] holehe deps" || echo "  [-] holehe deps failed"
fi

# Social Analyzer
if [ -d "$HOME_DIR/social-analyzer" ]; then
    pip install --quiet social-analyzer 2>/dev/null && echo "  [+] social-analyzer deps" || echo "  [-] social-analyzer deps failed"
fi

# Blackbird
if [ -d "$HOME_DIR/blackbird" ]; then
    (cd "$HOME_DIR/blackbird" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] blackbird deps" || echo "  [-] blackbird deps failed"
fi

# NexFil
if [ -d "$HOME_DIR/nexfil" ]; then
    (cd "$HOME_DIR/nexfil" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] nexfil deps" || echo "  [-] nexfil deps failed"
fi

# theHarvester
if [ -d "$HOME_DIR/theHarvester" ]; then
    pip install --quiet theHarvester 2>/dev/null || \
    (cd "$HOME_DIR/theHarvester" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] theHarvester deps" || echo "  [-] theHarvester deps failed"
fi

# h8mail
if [ -d "$HOME_DIR/h8mail" ]; then
    pip install --quiet h8mail 2>/dev/null && echo "  [+] h8mail deps" || echo "  [-] h8mail deps failed"
fi

# WhatBreach
if [ -d "$HOME_DIR/WhatBreach" ]; then
    (cd "$HOME_DIR/WhatBreach" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] WhatBreach deps" || echo "  [-] WhatBreach deps failed"
fi

# LeakSearch
if [ -d "$HOME_DIR/LeakSearch" ]; then
    (cd "$HOME_DIR/LeakSearch" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] LeakSearch deps" || echo "  [-] LeakSearch deps failed"
fi

# Cr3dOv3r
if [ -d "$HOME_DIR/Cr3dOv3r" ]; then
    (cd "$HOME_DIR/Cr3dOv3r" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] Cr3dOv3r deps" || echo "  [-] Cr3dOv3r deps failed"
fi

# GHunt
if [ -d "$HOME_DIR/GHunt" ]; then
    pip install --quiet ghunt 2>/dev/null || \
    (cd "$HOME_DIR/GHunt" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] GHunt deps" || echo "  [-] GHunt deps failed"
fi

# SpiderFoot
if [ -d "$HOME_DIR/spiderfoot" ]; then
    (cd "$HOME_DIR/spiderfoot" && pip install --quiet -r requirements.txt 2>/dev/null) && echo "  [+] spiderfoot deps" || echo "  [-] spiderfoot deps failed"
fi

# ─── Launch ───────────────────────────────────────────────────

echo ""
echo "[*] Setup complete! Launching OSINT Hub..."
echo ""

cd "$HOME_DIR/osint-hub"
source "$HOME_DIR/osint-hub/venv/bin/activate"

PORT=${1:-5000}
HOST=0.0.0.0

echo "  ╔══════════════════════════════════════════════╗"
echo "  ║          OSINT Hub v1.0                      ║"
echo "  ║   Unified OSINT Intelligence Platform        ║"
echo "  ╠══════════════════════════════════════════════╣"
echo "  ║   http://$HOST:$PORT                        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

PORT=$PORT HOST=$HOST python app.py
