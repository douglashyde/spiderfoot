"""Holehe - check which sites an email is registered on."""
import json
import re
from .base import ToolWrapper, Finding, FindingType

# Known site URL patterns for generating profile/login links
SITE_URL_MAP = {
    "twitter": "https://twitter.com",
    "instagram": "https://instagram.com",
    "facebook": "https://facebook.com",
    "github": "https://github.com",
    "linkedin": "https://linkedin.com",
    "pinterest": "https://pinterest.com",
    "spotify": "https://open.spotify.com",
    "tumblr": "https://tumblr.com",
    "wordpress": "https://wordpress.com",
    "adobe": "https://account.adobe.com",
    "amazon": "https://amazon.com",
    "apple": "https://appleid.apple.com",
    "discord": "https://discord.com",
    "dropbox": "https://dropbox.com",
    "ebay": "https://ebay.com",
    "flickr": "https://flickr.com",
    "google": "https://accounts.google.com",
    "imgur": "https://imgur.com",
    "lastfm": "https://last.fm",
    "myspace": "https://myspace.com",
    "netflix": "https://netflix.com",
    "patreon": "https://patreon.com",
    "quora": "https://quora.com",
    "reddit": "https://reddit.com",
    "snapchat": "https://snapchat.com",
    "steam": "https://store.steampowered.com",
    "strava": "https://strava.com",
    "telegram": "https://telegram.org",
    "tiktok": "https://tiktok.com",
    "twitch": "https://twitch.tv",
    "vimeo": "https://vimeo.com",
    "yahoo": "https://yahoo.com",
    "zoho": "https://zoho.com",
}


class HoleheTool(ToolWrapper):
    name = "holehe"
    description = "Check if email is registered on 120+ sites"
    accepts_input = ["email"]
    category = "email_osint"

    def is_available(self):
        try:
            import holehe
            return True
        except ImportError:
            return super().is_available()

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["holehe", input_value, "--no-color"]
        raw = self._run_command(cmd, cwd="/tmp")
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            # holehe output: [+] site.com: Exists
            if "[+]" in line:
                match = re.search(r"\[.\]\s*(\S+)", line)
                if match:
                    site = match.group(1).rstrip(":")
                    site_lower = site.lower().replace(".com", "").replace(".org", "").replace(".net", "")

                    # Get the website URL for this site
                    site_url = SITE_URL_MAP.get(site_lower, f"https://{site}")

                    findings.append(Finding(
                        FindingType.REGISTERED_SITE,
                        site_url,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "site": site,
                            "email": input_value,
                            "status": "registered",
                        },
                    ))

            # Check for rate-limiting info
            elif "[x]" in line or "rate" in line.lower():
                # Negative result or rate limit - skip
                continue

        return findings
