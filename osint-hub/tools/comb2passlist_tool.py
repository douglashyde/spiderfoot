"""comb2passlist - generate password lists from leaked credentials."""
from .base import ToolWrapper, Finding, FindingType


class Comb2PasslistTool(ToolWrapper):
    name = "comb2passlist"
    description = "Generate password list from COMB leaked credentials"
    accepts_input = ["username", "email"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "comb2passlist.py", "-u", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)
        tool_run.raw_output = raw

        passwords = []
        for line in raw.split("\n"):
            line = line.strip()
            if line and not line.startswith(("[", "#", "usage", "error", "COMB", "---", "Found", "Search")):
                passwords.append(line)

        for password in passwords:
            if ":" in password:
                parts = password.split(":", 1)
                identity = parts[0].strip()
                pwd = parts[1].strip()
                findings.append(Finding(
                    FindingType.LEAKED_CREDENTIAL,
                    password,
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={
                        "query": input_value,
                        "identity": identity,
                        "password": pwd,
                        "source": "COMB",
                        "type": "credential_pair",
                    },
                ))
            else:
                findings.append(Finding(
                    FindingType.LEAKED_CREDENTIAL,
                    f"{input_value}:{password}",
                    source_tool=self.name,
                    confidence=0.85,
                    metadata={
                        "query": input_value,
                        "password": password,
                        "source": "COMB",
                        "type": "password_only",
                    },
                ))

        if passwords:
            findings.append(Finding(
                FindingType.RAW,
                f"{len(passwords)} leaked passwords found for {input_value}",
                source_tool=self.name,
                confidence=0.9,
                metadata={
                    "query": input_value,
                    "password_count": len(passwords),
                    "type": "password_list_summary",
                },
            ))

        return findings
