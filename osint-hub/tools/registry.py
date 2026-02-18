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
from .osintgram_tool import OsintgramTool
from .x_osint_tool import XOsintTool
from .leaklooker_tool import LeakLookerTool
from .oblivion_tool import OblivionTool
from .findpeopleinfo_tool import FindPeopleInfoTool


ALL_TOOLS = {
    # Username search tools
    "sherlock": SherlockTool,
    "maigret": MaigretTool,
    "blackbird": BlackbirdTool,
    "nexfil": NexfilTool,
    "social_analyzer": SocialAnalyzerTool,

    # Email OSINT tools
    "holehe": HoleheTool,
    "theharvester": TheHarvesterTool,
    "ghunt": GHuntTool,

    # Phone OSINT
    "phoneinfoga": PhoneInfogaTool,

    # Social media specific
    "osintgram": OsintgramTool,
    "x_osint": XOsintTool,

    # Breach / leak tools
    "xposedornot": XposedOrNotTool,
    "h8mail": H8mailTool,
    "whatbreach": WhatBreachTool,
    "leaksearch": LeakSearchTool,
    "cr3dov3r": Cr3dOv3rTool,
    "comb2passlist": Comb2PasslistTool,
    "oblivion": OblivionTool,
    "leaklooker": LeakLookerTool,

    # People search
    "findpeopleinfo": FindPeopleInfoTool,

    # Frameworks
    "spiderfoot": SpiderfootTool,
}

# Which tools to run for each input type
INPUT_TOOL_MAP = {
    "email": [
        "holehe", "xposedornot", "h8mail", "whatbreach",
        "leaksearch", "cr3dov3r", "comb2passlist", "oblivion",
        "theharvester", "ghunt", "leaklooker", "findpeopleinfo",
    ],
    "username": [
        "sherlock", "maigret", "blackbird", "nexfil",
        "social_analyzer", "leaksearch", "comb2passlist",
        "osintgram", "x_osint",
    ],
    "phone": [
        "phoneinfoga", "findpeopleinfo",
    ],
    "domain": [
        "theharvester", "spiderfoot", "leaklooker",
    ],
    "full_name": [
        "findpeopleinfo",
    ],
}

# Priority ordering - run these first as they're fastest and most reliable
TOOL_PRIORITY = {
    "xposedornot": 1,    # Fast API, always works
    "holehe": 2,          # Fast, no API key
    "sherlock": 3,        # Well maintained
    "maigret": 4,         # Comprehensive but slower
    "phoneinfoga": 5,
    "h8mail": 6,
    "leaksearch": 7,
    "cr3dov3r": 8,
    "comb2passlist": 9,
    "oblivion": 10,
    "whatbreach": 11,
    "blackbird": 12,
    "nexfil": 13,
    "social_analyzer": 14,
    "osintgram": 15,
    "x_osint": 16,
    "theharvester": 17,
    "ghunt": 18,
    "leaklooker": 19,
    "findpeopleinfo": 20,
    "spiderfoot": 21,
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
