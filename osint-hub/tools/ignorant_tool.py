"""Ignorant - check if phone numbers are used on social platforms."""
import re
import json
from .base import ToolWrapper, Finding, FindingType


class IgnorantTool(ToolWrapper):
    name = "ignorant"
    description = "Check phone number registration on social platforms"
    accepts_input = ["phone"]
    category = "phone_osint"

    def is_available(self):
        try:
            import importlib
            importlib.import_module("ignorant")
            return True
        except ImportError:
            return False

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        phone = input_value.strip()

        # Run ignorant as module
        cmd = ["python", "-m", "ignorant", phone]
        raw = self._run_command(cmd, cwd="/tmp")
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Ignorant outputs lines like: [+] platform: registered
            if "[+]" in line or "registered" in line.lower() or "exists" in line.lower():
                # Extract platform name
                platform = line.replace("[+]", "").strip()
                platform = re.sub(r"\s*(registered|exists|found).*", "", platform, flags=re.IGNORECASE).strip()
                platform = platform.rstrip(":").strip()

                if platform and len(platform) > 1:
                    findings.append(Finding(
                        FindingType.REGISTERED_SITE,
                        platform,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "phone": phone,
                            "platform": platform,
                            "registration": "confirmed",
                        },
                    ))

            # Look for any URLs in output
            urls = re.findall(r"https?://[^\s]+", line)
            for url in urls:
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    url,
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={"phone": phone},
                ))

        return findings
