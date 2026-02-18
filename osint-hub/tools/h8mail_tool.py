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

        current_breach = None
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "breach" in line.lower() or "leak" in line.lower() or "database" in line.lower():
                if not line.startswith("#"):
                    current_breach = line
                    findings.append(Finding(
                        FindingType.BREACH,
                        line,
                        source_tool=self.name,
                        confidence=0.75,
                        metadata={"email": input_value, "type": "breach_info"},
                    ))

            # Credential pairs (email:password)
            if ":" in line and "@" in line:
                parts = line.split(":", 1)
                email_part = parts[0].strip()
                password_part = parts[1].strip() if len(parts) > 1 else ""
                if re.match(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", email_part) and password_part:
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        line.strip(),
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "email": email_part,
                            "password": password_part,
                            "breach": current_breach or "unknown",
                            "source": "h8mail",
                            "type": "credential_pair",
                        },
                    ))

            # Password: value format
            password_match = re.search(r"[Pp]assword\s*[:=]\s*(.+)", line)
            if password_match:
                pwd = password_match.group(1).strip()
                if pwd and pwd.lower() not in ("none", "null", "n/a", "not found"):
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        f"{input_value}:{pwd}",
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "email": input_value,
                            "password": pwd,
                            "breach": current_breach or "unknown",
                            "source": "h8mail",
                            "type": "password_found",
                        },
                    ))

            # Hash values
            hash_match = re.search(r"[Hh]ash\s*[:=]\s*([a-fA-F0-9]{32,})", line)
            if hash_match:
                hash_val = hash_match.group(1).strip()
                findings.append(Finding(
                    FindingType.LEAKED_CREDENTIAL,
                    f"{input_value}:{hash_val}",
                    source_tool=self.name,
                    confidence=0.75,
                    metadata={
                        "email": input_value,
                        "password_hash": hash_val,
                        "breach": current_breach or "unknown",
                        "source": "h8mail",
                        "type": "password_hash",
                    },
                ))

            # Related emails
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
