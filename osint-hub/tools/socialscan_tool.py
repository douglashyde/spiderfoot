"""Socialscan - check email/username availability across platforms."""
import re
from .base import ToolWrapper, Finding, FindingType

# Map platform names to profile URL templates ({} = username placeholder)
PLATFORM_URL_MAP = {
    "instagram": "https://instagram.com/{}",
    "twitter": "https://twitter.com/{}",
    "github": "https://github.com/{}",
    "tumblr": "https://{}.tumblr.com",
    "lastfm": "https://last.fm/user/{}",
    "spotify": "https://open.spotify.com/user/{}",
    "pinterest": "https://pinterest.com/{}",
    "snapchat": "https://snapchat.com/add/{}",
    "gitlab": "https://gitlab.com/{}",
    "reddit": "https://reddit.com/user/{}",
    "yahoo": "https://profile.yahoo.com/{}",
}


class SocialscanTool(ToolWrapper):
    name = "socialscan"
    description = "Check username/email availability across platforms"
    accepts_input = ["email", "username"]
    category = "social"

    def is_available(self):
        try:
            import importlib
            importlib.import_module("socialscan")
            return True
        except ImportError:
            return False

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "-m", "socialscan", input_value]
        raw = self._run_command(cmd, cwd="/tmp")
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Socialscan outputs: Platform: Taken/Available
            if "taken" in line.lower() or "claimed" in line.lower():
                parts = line.split(":", 1) if ":" in line else line.split(None, 1)
                platform = parts[0].strip().strip("[]").strip() if parts else line
                platform = re.sub(r"\x1b\[[0-9;]*m", "", platform)  # strip ANSI

                if platform and len(platform) > 1 and platform.lower() not in ("taken", "claimed"):
                    platform_lower = platform.lower().replace(" ", "")

                    # Build actual profile URL when possible
                    url_template = PLATFORM_URL_MAP.get(platform_lower)
                    if url_template and input_type == "username":
                        profile_url = url_template.format(input_value)
                    else:
                        profile_url = f"https://{platform.lower().replace(' ', '')}.com"

                    findings.append(Finding(
                        FindingType.REGISTERED_SITE,
                        profile_url,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "site": platform,
                            "input": input_value,
                            "input_type": input_type,
                            "status": "taken",
                        },
                    ))

        return findings
