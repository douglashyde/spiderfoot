"""WhatBreach - find breached emails and databases."""
import re
from .base import ToolWrapper, Finding, FindingType


class WhatBreachTool(ToolWrapper):
    name = "whatbreach"
    description = "Find breached email databases"
    accepts_input = ["email"]
    category = "breach"

    def is_available(self):
        # WhatBreach requires interactive API token input - can't run headless
        return False

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "whatbreach.py", "-e", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if "breach" in line.lower() or "found" in line.lower() or "database" in line.lower():
                if line and not line.startswith("#"):
                    findings.append(Finding(
                        FindingType.BREACH,
                        line,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"email": input_value},
                    ))
            if "http" in line:
                url = re.search(r"https?://\S+", line)
                if url:
                    findings.append(Finding(
                        FindingType.RAW,
                        url.group(0),
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"email": input_value, "type": "database_link"},
                    ))

        return findings
