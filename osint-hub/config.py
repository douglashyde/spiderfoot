import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(BASE_DIR)  # spiderfoot monorepo root
TOOLS_DIR = os.path.join(REPO_ROOT, "tools-repos")
HOME_DIR = "/home/user"


def _tool_path(dirname):
    """Resolve tool path: prefer monorepo tools-repos/, fallback to ~/."""
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

SCAN_TIMEOUT = 300  # seconds per tool
MAX_CHAIN_DEPTH = 3  # how many levels deep the correlator will chase new leads
