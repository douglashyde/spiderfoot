"""X-osint - Twitter/X OSINT tool."""
import re
import json
from .base import ToolWrapper, Finding, FindingType


class XOsintTool(ToolWrapper):
    name = "x_osint"
    description = "Twitter/X account OSINT and analysis"
    accepts_input = ["username"]
    category = "social"
    main_script = "x-osint.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "x-osint.py", "--username", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=120)
        tool_run.raw_output = raw

        # Try JSON output
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                if data.get("name"):
                    findings.append(Finding(
                        FindingType.FULL_NAME,
                        data["name"],
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={"twitter_user": input_value},
                    ))
                if data.get("location"):
                    findings.append(Finding(
                        FindingType.LOCATION,
                        data["location"],
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"twitter_user": input_value},
                    ))
                if data.get("description") or data.get("bio"):
                    bio = data.get("description", data.get("bio", ""))
                    findings.append(Finding(
                        FindingType.BIO,
                        bio,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={"twitter_user": input_value},
                    ))
                    # Extract URLs from bio
                    urls = re.findall(r"https?://\S+", bio)
                    for url in urls:
                        findings.append(Finding(
                            FindingType.RAW,
                            url,
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={"twitter_user": input_value, "type": "bio_link"},
                        ))
                if data.get("profile_image"):
                    findings.append(Finding(
                        FindingType.PHOTO_URL,
                        data["profile_image"],
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={"twitter_user": input_value},
                    ))
        except (json.JSONDecodeError, TypeError):
            # Parse text output
            for line in raw.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if not val:
                        continue
                    if "name" in key and "user" not in key:
                        findings.append(Finding(
                            FindingType.FULL_NAME, val,
                            source_tool=self.name, confidence=0.7,
                            metadata={"twitter_user": input_value},
                        ))
                    elif "location" in key:
                        findings.append(Finding(
                            FindingType.LOCATION, val,
                            source_tool=self.name, confidence=0.6,
                            metadata={"twitter_user": input_value},
                        ))

        # Always add the profile
        findings.append(Finding(
            FindingType.SOCIAL_PROFILE,
            f"https://x.com/{input_value}",
            source_tool=self.name,
            confidence=0.95,
            metadata={"platform": "twitter/x", "username": input_value},
        ))

        return findings
