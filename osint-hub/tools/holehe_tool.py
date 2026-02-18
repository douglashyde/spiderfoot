"""Holehe - check which sites an email is registered on."""
import json
import re
from .base import ToolWrapper, Finding, FindingType


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
                # Extract site name
                match = re.search(r"\[.\]\s*(\S+)", line)
                if match:
                    site = match.group(1).rstrip(":")
                    findings.append(Finding(
                        FindingType.REGISTERED_SITE,
                        site,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={"email": input_value, "status": "registered"},
                    ))

        return findings
