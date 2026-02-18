"""h8mail - email breach hunting."""
import re
from .base import ToolWrapper, Finding, FindingType

# Strip ANSI escape codes from output
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


class H8mailTool(ToolWrapper):
    name = "h8mail"
    description = "Email OSINT and breach hunting"
    accepts_input = ["email"]
    category = "breach"
    pip_module = "h8mail"
    cli_command = "h8mail"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["h8mail", "-t", input_value]
        raw = self._run_command(cmd)
        # Strip ANSI escape codes before parsing
        raw = _ANSI_RE.sub('', raw)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            # h8mail outputs breach names and sometimes passwords
            if "breach" in line.lower() or "leak" in line.lower():
                findings.append(Finding(
                    FindingType.RAW,
                    line,
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={"email": input_value, "type": "breach_info"},
                ))
            # Look for related emails (but validate they're real)
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line)
            for email in emails:
                email = email.lower()
                # Skip the input email and obvious junk
                if email == input_value.lower():
                    continue
                # Validate it looks like a real email (no ANSI remnants)
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"found_with": input_value},
                    ))

        return findings
