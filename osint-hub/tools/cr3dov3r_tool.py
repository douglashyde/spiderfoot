"""Cr3dOv3r - credential leak checker."""
import re
from .base import ToolWrapper, Finding, FindingType


class Cr3dOv3rTool(ToolWrapper):
    name = "cr3dov3r"
    description = "Check if email credentials were leaked"
    accepts_input = ["email"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Run in quiet mode; no -p flag so passwords are extracted
        cmd = ["python", "Cr3d0v3r.py", input_value, "-q"]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "leak" in line.lower() or "breach" in line.lower() or "found" in line.lower():
                findings.append(Finding(
                    FindingType.BREACH,
                    line,
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={"email": input_value},
                ))

            # Extract passwords
            password_match = re.search(r"[Pp]assword\s*[:=]\s*(.+)", line)
            if password_match:
                pwd = password_match.group(1).strip()
                if pwd and pwd.lower() not in ("none", "null", "n/a", "not found"):
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        f"{input_value}:{pwd}",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "email": input_value,
                            "password": pwd,
                            "source": "cr3dov3r",
                            "type": "credential_pair",
                        },
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
                        confidence=0.85,
                        metadata={
                            "email": email_part,
                            "password": password_part,
                            "source": "cr3dov3r",
                            "type": "credential_pair",
                        },
                    ))

            # Hash detection
            hash_match = re.search(r"[Hh]ash\s*[:=]\s*([a-fA-F0-9]{32,})", line)
            if hash_match:
                hash_val = hash_match.group(1).strip()
                findings.append(Finding(
                    FindingType.LEAKED_CREDENTIAL,
                    f"{input_value}:{hash_val}",
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={
                        "email": input_value,
                        "password_hash": hash_val,
                        "source": "cr3dov3r",
                        "type": "password_hash",
                    },
                ))

        return findings
