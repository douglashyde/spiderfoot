import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOME_DIR = "/home/user"

TOOL_PATHS = {
    "sherlock": os.path.join(HOME_DIR, "sherlock"),
    "maigret": os.path.join(HOME_DIR, "maigret"),
    "holehe": os.path.join(HOME_DIR, "holehe"),
    "social_analyzer": os.path.join(HOME_DIR, "social-analyzer"),
    "blackbird": os.path.join(HOME_DIR, "blackbird"),
    "nexfil": os.path.join(HOME_DIR, "nexfil"),
    "phoneinfoga": os.path.join(HOME_DIR, "phoneinfoga"),
    "spiderfoot": os.path.join(HOME_DIR, "spiderfoot"),
    "theharvester": os.path.join(HOME_DIR, "theHarvester"),
    "osintgram": os.path.join(HOME_DIR, "Osintgram"),
    "ghunt": os.path.join(HOME_DIR, "GHunt"),
    "x_osint": os.path.join(HOME_DIR, "X-osint"),
    "leaksearch": os.path.join(HOME_DIR, "LeakSearch"),
    "leaklooker": os.path.join(HOME_DIR, "LeakLooker"),
    "cr3dov3r": os.path.join(HOME_DIR, "Cr3dOv3r"),
    "comb2passlist": os.path.join(HOME_DIR, "comb2passlist"),
    "oblivion": os.path.join(HOME_DIR, "Oblivion"),
    "h8mail": os.path.join(HOME_DIR, "h8mail"),
    "whatbreach": os.path.join(HOME_DIR, "WhatBreach"),
    "findpeopleinfo": os.path.join(HOME_DIR, "findpeopleinfo"),
}

DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SCAN_TIMEOUT = 300  # seconds per tool
MAX_CHAIN_DEPTH = 3  # how many levels deep the correlator will chase new leads
