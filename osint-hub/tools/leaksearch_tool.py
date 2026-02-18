"""LeakSearch - search leaked credentials via ProxyNova COMB."""
import json
import re
from .base import ToolWrapper, Finding, FindingType


class LeakSearchTool(ToolWrapper):
    name = "leaksearch"
    description = "Search 3.2B leaked credentials (ProxyNova COMB)"
    accepts_input = ["email", "username"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "LeakSearch.py", "-k", input_value, "-l", "20"]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)
        tool_run.raw_output = raw

        # Parse results - LeakSearch shows credential pairs
        for line in raw.split("\n"):
            line = line.strip()
            if ":" in line and "@" in line:
                # This is a credential line (email:password)
                findings.append(Finding(
                    FindingType.RAW,
                    f"Credential found for {input_value}",
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={
                        "query": input_value,
                        "type": "leaked_credential",
                    },
                ))
            elif "result" in line.lower() or "found" in line.lower():
                findings.append(Finding(
                    FindingType.RAW,
                    line,
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={"query": input_value},
                ))

        return findings
