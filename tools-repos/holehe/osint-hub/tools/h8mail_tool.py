"""h8mail - email breach hunting."""
import re
from .base import ToolWrapper, Finding, FindingType


class H8mailTool(ToolWrapper):
    name = "h8mail"
    description = "Email OSINT and breach hunting"
    accepts_input = ["email"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "-m", "h8mail", "-t", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        # Parse h8mail output for breach info
        for line in raw.split("\n"):
            line = line.strip()
            # h8mail outputs breach names and sometimes passwords
            if "breach" in line.lower() or "leak" in line.lower():
                findings.append(Finding(
                    FindingType.RAW,
                    line,
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={"email": input_value, "type": "breach_info"},
                ))
            # Look for related emails
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line)
            for email in emails:
                if email.lower() != input_value.lower():
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"found_with": input_value},
                    ))

        return findings
