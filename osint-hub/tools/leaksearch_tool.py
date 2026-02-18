"""LeakSearch - search leaked credentials via ProxyNova COMB."""
import re
from .base import ToolWrapper, Finding, FindingType


class LeakSearchTool(ToolWrapper):
    name = "leaksearch"
    description = "Search 3.2B leaked credentials (ProxyNova COMB)"
    accepts_input = ["email", "username"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "LeakSearch.py", "-k", input_value, "-l", "50"]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)
        tool_run.raw_output = raw

        credential_count = 0
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            if ":" in line and not line.startswith(("[", "#", "---", "Leak", "Search", "Result", "Total")):
                parts = line.split(":", 1)
                identity = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""

                if password and len(identity) > 2 and not identity.startswith("http"):
                    credential_count += 1
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        line,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "query": input_value,
                            "identity": identity,
                            "password": password,
                            "source": "ProxyNova COMB",
                            "type": "credential_pair",
                        },
                    ))

                    if "@" in identity and identity.lower() != input_value.lower():
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            identity.lower(),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"found_with": input_value},
                        ))

            elif "result" in line.lower() or "found" in line.lower():
                findings.append(Finding(
                    FindingType.RAW,
                    line,
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={"query": input_value},
                ))

        if credential_count > 0:
            findings.append(Finding(
                FindingType.RAW,
                f"{credential_count} credential pairs found for {input_value}",
                source_tool=self.name,
                confidence=0.9,
                metadata={
                    "query": input_value,
                    "credential_count": credential_count,
                    "type": "credential_summary",
                },
            ))

        return findings
