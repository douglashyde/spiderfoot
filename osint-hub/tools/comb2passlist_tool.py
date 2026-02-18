"""comb2passlist - generate password lists from leaked credentials."""
from .base import ToolWrapper, Finding, FindingType


class Comb2PasslistTool(ToolWrapper):
    name = "comb2passlist"
    description = "Generate password list from COMB leaked credentials"
    accepts_input = ["username", "email"]
    category = "breach"
    main_script = "comb2passlist.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "comb2passlist.py", "-u", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)
        tool_run.raw_output = raw

        password_count = 0
        for line in raw.split("\n"):
            line = line.strip()
            if line and not line.startswith(("[", "#", "usage", "error")):
                password_count += 1

        if password_count > 0:
            findings.append(Finding(
                FindingType.RAW,
                f"{password_count} leaked passwords found for {input_value}",
                source_tool=self.name,
                confidence=0.9,
                metadata={
                    "query": input_value,
                    "password_count": password_count,
                    "type": "password_list",
                },
            ))

        return findings
