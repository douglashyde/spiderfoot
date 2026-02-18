#!/bin/bash
# OSINT Hub - Startup Script
# Usage: ./run.sh [port]

PORT=${1:-5000}
HOST=${HOST:-0.0.0.0}
DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║          OSINT Hub v1.0                  ║"
echo "  ║   Unified OSINT Intelligence Platform    ║"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║   Starting on port $PORT                  ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check tools
echo "[*] Checking installed tools..."
TOOLS_FOUND=0
for tool_dir in sherlock maigret holehe social-analyzer blackbird nexfil phoneinfoga theHarvester Cr3dOv3r LeakSearch comb2passlist h8mail WhatBreach Oblivion GHunt spiderfoot; do
    if [ -d "$HOME/$tool_dir" ]; then
        echo "  [+] $tool_dir"
        TOOLS_FOUND=$((TOOLS_FOUND + 1))
    else
        echo "  [-] $tool_dir (not found)"
    fi
done
echo "[*] $TOOLS_FOUND tools available"
echo ""

# Install requirements if needed
pip install -q flask 2>/dev/null

# Start
cd "$DIR"
PORT=$PORT HOST=$HOST python app.py
