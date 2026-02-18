"""Osintgram - Instagram OSINT tool."""
import re
from .base import ToolWrapper, Finding, FindingType


class OsintgramTool(ToolWrapper):
    name = "osintgram"
    description = "Instagram OSINT - photos, followers, contacts, locations"
    accepts_input = ["username"]
    category = "social"
    main_script = "main.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Osintgram uses an interactive prompt, so we pipe commands
        commands = ["info", "fwersemail", "fwingsemail", "fwersnumber", "fwingsnumber"]
        for osint_cmd in commands:
            cmd = ["python", "main.py", input_value, "--command", osint_cmd]
            raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)
            tool_run.raw_output += f"\n=== {osint_cmd} ===\n{raw}"

            # Extract emails
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw)
            for email in set(emails):
                findings.append(Finding(
                    FindingType.RELATED_EMAIL,
                    email.lower(),
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={"instagram_user": input_value, "from_cmd": osint_cmd},
                ))

            # Extract phone numbers
            phones = re.findall(r"\+?\d{10,15}", raw)
            for phone in set(phones):
                findings.append(Finding(
                    FindingType.RELATED_PHONE,
                    phone,
                    source_tool=self.name,
                    confidence=0.6,
                    metadata={"instagram_user": input_value, "from_cmd": osint_cmd},
                ))

            # Extract bio/info
            if osint_cmd == "info":
                for line in raw.split("\n"):
                    line = line.strip()
                    if ":" in line and line and not line.startswith(("[", "#")):
                        key, _, val = line.partition(":")
                        val = val.strip()
                        if val and key.strip().lower() in ("full name", "name", "biography", "bio"):
                            ftype = FindingType.FULL_NAME if "name" in key.lower() else FindingType.BIO
                            findings.append(Finding(
                                ftype, val,
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={"instagram_user": input_value},
                            ))

        # Always add the profile itself
        findings.append(Finding(
            FindingType.SOCIAL_PROFILE,
            f"https://instagram.com/{input_value}",
            source_tool=self.name,
            confidence=0.95,
            metadata={"platform": "instagram", "username": input_value},
        ))

        return findings
