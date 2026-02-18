"""WhatBreach - find breached emails and databases."""
import re
from .base import ToolWrapper, Finding, FindingType


class WhatBreachTool(ToolWrapper):
    name = "whatbreach"
    description = "Find breached email databases"
    accepts_input = ["email"]
    category = "breach"

    def is_available(self):
        import os
        return os.path.isdir(self.tool_path)

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "whatbreach.py", "-e", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        current_breach = None
        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "breach" in line.lower() or "found" in line.lower() or "database" in line.lower():
                current_breach = line
                findings.append(Finding(
                    FindingType.BREACH,
                    line,
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={"email": input_value},
                ))

            # Extract download/paste links
            url_match = re.search(r"https?://\S+", line)
            if url_match:
                url = url_match.group(0)
                findings.append(Finding(
                    FindingType.RAW,
                    url,
                    source_tool=self.name,
                    confidence=0.6,
                    metadata={
                        "email": input_value,
                        "type": "database_link",
                        "breach": current_breach or "unknown",
                    },
                ))

            # Extract password/credential info if present
            if "password" in line.lower() and ":" in line:
                parts = line.split(":", 1)
                pwd = parts[1].strip() if len(parts) > 1 else ""
                if pwd and pwd.lower() not in ("none", "null", "n/a", "not found", "yes", "no"):
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        f"{input_value}:{pwd}",
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={
                            "email": input_value,
                            "password": pwd,
                            "breach": current_breach or "unknown",
                            "source": "whatbreach",
                            "type": "credential_pair",
                        },
                    ))

        return findings
