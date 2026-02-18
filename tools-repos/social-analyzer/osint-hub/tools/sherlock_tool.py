"""Sherlock - username search across 400+ social networks."""
import json
import os
import tempfile
from .base import ToolWrapper, Finding, FindingType


class SherlockTool(ToolWrapper):
    name = "sherlock"
    description = "Hunt usernames across 400+ social networks"
    accepts_input = ["username"]
    category = "username_search"

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        output_dir = tempfile.mkdtemp()
        output_file = os.path.join(output_dir, f"{input_value}.json")

        cmd = [
            "python", "-m", "sherlock", input_value,
            "--json", output_file,
            "--timeout", "15",
            "--print-found",
        ]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        # Parse JSON results
        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    data = json.load(f)
                for site_name, info in data.items():
                    if info.get("status", "").lower() == "claimed":
                        url = info.get("url_user", "")
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            url,
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={"site": site_name, "username": input_value},
                        ))
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: parse stdout
        if not findings:
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        line,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"username": input_value},
                    ))

        return findings
