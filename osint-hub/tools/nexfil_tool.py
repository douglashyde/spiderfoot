"""NexFil - username OSINT across 350+ sites."""
import json
import os
from .base import ToolWrapper, Finding, FindingType


class NexfilTool(ToolWrapper):
    name = "nexfil"
    description = "OSINT tool for finding profiles by username across 350+ sites"
    accepts_input = ["username"]
    category = "username_search"
    main_script = "nexfil.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "nexfil.py", "-u", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if line.startswith("http") and " " not in line:
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    line,
                    source_tool=self.name,
                    confidence=0.75,
                    metadata={"username": input_value},
                ))
            elif "[+]" in line and "http" in line:
                idx = line.find("http")
                url = line[idx:].split()[0]
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    url,
                    source_tool=self.name,
                    confidence=0.75,
                    metadata={"username": input_value},
                ))

        return findings
