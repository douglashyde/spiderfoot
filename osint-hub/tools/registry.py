"""Tool registry - central place to discover and access all tools."""
from .sherlock_tool import SherlockTool
from .maigret_tool import MaigretTool
from .holehe_tool import HoleheTool
from .social_analyzer_tool import SocialAnalyzerTool
from .blackbird_tool import BlackbirdTool
from .nexfil_tool import NexfilTool
from .phoneinfoga_tool import PhoneInfogaTool
from .theharvester_tool import TheHarvesterTool
from .xposedornot_tool import XposedOrNotTool
from .h8mail_tool import H8mailTool
from .whatbreach_tool import WhatBreachTool
from .leaksearch_tool import LeakSearchTool
from .cr3dov3r_tool import Cr3dOv3rTool
from .comb2passlist_tool import Comb2PasslistTool
from .ghunt_tool import GHuntTool
from .spiderfoot_tool import SpiderfootTool
# New tools - V2
from .ignorant_tool import IgnorantTool
from .socialscan_tool import SocialscanTool
from .photon_tool import PhotonTool
from .breachdirectory_tool import BreachDirectoryTool
from .intelx_phonebook_tool import IntelxPhonebookTool
from .psbdmp_tool import PasteDumpTool
from .emailrep_tool import EmailRepTool
from .hudsonrock_tool import HudsonRockTool
from .leakcheck_tool import LeakCheckTool
from .dehashed_free_tool import DehashedFreeTool


ALL_TOOLS = {
    # Username search tools
    "sherlock": SherlockTool,
    "maigret": MaigretTool,
    "blackbird": BlackbirdTool,
    "nexfil": NexfilTool,
    "social_analyzer": SocialAnalyzerTool,
    "socialscan": SocialscanTool,

    # Email OSINT tools
    "holehe": HoleheTool,
    "theharvester": TheHarvesterTool,
    "ghunt": GHuntTool,
    "emailrep": EmailRepTool,

    # Phone OSINT
    "phoneinfoga": PhoneInfogaTool,
    "ignorant": IgnorantTool,

    # Breach / credential tools
    "xposedornot": XposedOrNotTool,
    "h8mail": H8mailTool,
    "whatbreach": WhatBreachTool,
    "leaksearch": LeakSearchTool,
    "cr3dov3r": Cr3dOv3rTool,
    "comb2passlist": Comb2PasslistTool,
    "breachdirectory": BreachDirectoryTool,
    "hudsonrock": HudsonRockTool,
    "leakcheck": LeakCheckTool,
    "dehashed_free": DehashedFreeTool,

    # Intelligence / paste search
    "intelx_phonebook": IntelxPhonebookTool,
    "psbdmp": PasteDumpTool,

    # Domain OSINT
    "photon": PhotonTool,

    # Frameworks
    "spiderfoot": SpiderfootTool,
}

# Which tools to run for each input type
INPUT_TOOL_MAP = {
    "email": [
        "holehe", "xposedornot", "h8mail", "whatbreach",
        "leaksearch", "cr3dov3r", "comb2passlist",
        "theharvester", "ghunt", "emailrep",
        "breachdirectory", "hudsonrock", "leakcheck",
        "dehashed_free", "psbdmp", "intelx_phonebook",
        "socialscan",
    ],
    "username": [
        "sherlock", "maigret", "blackbird", "nexfil",
        "social_analyzer", "leaksearch", "comb2passlist",
        "socialscan", "hudsonrock", "psbdmp",
        "dehashed_free",
    ],
    "phone": [
        "phoneinfoga", "ignorant", "dehashed_free",
    ],
    "domain": [
        "theharvester", "spiderfoot", "photon",
        "intelx_phonebook", "psbdmp", "hudsonrock",
    ],
    "full_name": [
        # Name-based searches are done by extracting usernames first
    ],
}

# Priority ordering - lower = run first (fastest and most reliable)
TOOL_PRIORITY = {
    # Tier 1: Fast APIs, always work, no rate limits
    "xposedornot": 1,
    "holehe": 2,
    "emailrep": 3,
    "leakcheck": 4,
    "breachdirectory": 5,

    # Tier 2: Reliable tools
    "sherlock": 6,
    "hudsonrock": 7,
    "ignorant": 8,
    "socialscan": 9,
    "maigret": 10,

    # Tier 3: Core breach tools
    "phoneinfoga": 11,
    "h8mail": 12,
    "leaksearch": 13,
    "cr3dov3r": 14,
    "psbdmp": 15,
    "intelx_phonebook": 16,
    "dehashed_free": 17,

    # Tier 4: Slower / heavier tools
    "comb2passlist": 18,
    "whatbreach": 19,
    "blackbird": 20,
    "nexfil": 21,
    "social_analyzer": 22,
    "theharvester": 23,
    "photon": 24,
    "ghunt": 25,
    "spiderfoot": 26,
}


def get_tools_for_input(input_type):
    """Get ordered list of tool instances for a given input type."""
    tool_names = INPUT_TOOL_MAP.get(input_type, [])
    tools = []
    for name in sorted(tool_names, key=lambda x: TOOL_PRIORITY.get(x, 99)):
        cls = ALL_TOOLS.get(name)
        if cls:
            instance = cls()
            if instance.is_available():
                tools.append(instance)
    return tools


def get_all_tool_info():
    """Get info about all registered tools."""
    info = []
    for name, cls in ALL_TOOLS.items():
        instance = cls()
        tool_info = instance.get_info()
        tool_info["priority"] = TOOL_PRIORITY.get(name, 99)
        info.append(tool_info)
    return sorted(info, key=lambda x: x["priority"])
