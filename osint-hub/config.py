import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOME_DIR = os.environ.get("OSINT_HOME", os.path.expanduser("~"))

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
    # New tools - V2
    "photon": os.path.join(HOME_DIR, "Photon"),
    "ignorant": os.path.join(HOME_DIR, "ignorant"),
    "socialscan": os.path.join(HOME_DIR, "socialscan"),
    # Web-based tools (no local path needed, use requests)
    "breachdirectory": os.path.join(HOME_DIR, "osint-hub"),
    "hudsonrock": os.path.join(HOME_DIR, "osint-hub"),
    "leakcheck": os.path.join(HOME_DIR, "osint-hub"),
    "dehashed_free": os.path.join(HOME_DIR, "osint-hub"),
    "emailrep": os.path.join(HOME_DIR, "osint-hub"),
    "intelx_phonebook": os.path.join(HOME_DIR, "osint-hub"),
    "psbdmp": os.path.join(HOME_DIR, "osint-hub"),
    # V3 - Deep OSINT (web-based tools, no local path needed)
    "google_dorking": os.path.join(HOME_DIR, "osint-hub"),
    "deep_paste": os.path.join(HOME_DIR, "osint-hub"),
    "darkweb_search": os.path.join(HOME_DIR, "osint-hub"),
    "wayback": os.path.join(HOME_DIR, "osint-hub"),
    "code_search": os.path.join(HOME_DIR, "osint-hub"),
    "forum_search": os.path.join(HOME_DIR, "osint-hub"),
    "document_search": os.path.join(HOME_DIR, "osint-hub"),
    "dns_recon": os.path.join(HOME_DIR, "osint-hub"),
    "public_records": os.path.join(HOME_DIR, "osint-hub"),
    "messaging_search": os.path.join(HOME_DIR, "osint-hub"),
}

DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SCAN_TIMEOUT = 300  # seconds per tool
MAX_CHAIN_DEPTH = 3  # how many levels deep the correlator will chase new leads
