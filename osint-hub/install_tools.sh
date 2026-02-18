#!/usr/bin/env bash
# OSINT Hub - Install all tool dependencies
# Run from the osint-hub directory: bash install_tools.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$REPO_ROOT/tools-repos"

echo "=== OSINT Hub Tool Installer ==="
echo "Tools directory: $TOOLS_DIR"
mkdir -p "$TOOLS_DIR"

# ---- Pip packages ----
echo ""
echo "[*] Installing pip packages..."
pip install -q phonenumbers theHarvester 2>/dev/null || pip3 install -q phonenumbers theHarvester 2>/dev/null || true

# ---- Git-clone tools ----
clone_tool() {
    local name="$1"
    local url="$2"
    local dir="$TOOLS_DIR/$name"
    if [ -d "$dir" ]; then
        echo "[OK] $name already cloned"
    else
        echo "[>>] Cloning $name ..."
        git clone --depth 1 "$url" "$dir" 2>/dev/null && echo "[OK] $name cloned" || echo "[--] $name clone failed"
    fi
    # Install requirements if present
    if [ -f "$dir/requirements.txt" ]; then
        pip install -q -r "$dir/requirements.txt" 2>/dev/null || pip3 install -q -r "$dir/requirements.txt" 2>/dev/null || true
    fi
}

clone_tool "blackbird"      "https://github.com/p1ngul1n0/blackbird.git"
clone_tool "nexfil"          "https://github.com/thewhiteh4t/nexfil.git"
clone_tool "LeakSearch"      "https://github.com/JoelGMSec/LeakSearch.git"
clone_tool "Cr3dOv3r"        "https://github.com/D4Vinci/Cr3dOv3r.git"
clone_tool "comb2passlist"   "https://github.com/jsavargas/comb2passlist.git"
clone_tool "Oblivion"        "https://github.com/loseys/Oblivion.git"
clone_tool "Osintgram"       "https://github.com/Datalux/Osintgram.git"
clone_tool "X-osint"         "https://github.com/TermuxHackz/X-osint.git"
clone_tool "GHunt"           "https://github.com/mxrch/GHunt.git"
clone_tool "LeakLooker"      "https://github.com/woj-ciech/LeakLooker.git"
clone_tool "findpeopleinfo"  "https://github.com/p1ngul1n0/findpeopleinfo.git"
clone_tool "WhatBreach"      "https://github.com/Ekultek/WhatBreach.git"

echo ""
echo "=== Installation complete ==="
echo "Restart the OSINT Hub to see updated tool availability."
