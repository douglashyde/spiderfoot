"""Sherlock - username search across 400+ social networks."""
import json
import os
import re
import tempfile
from .base import ToolWrapper, Finding, FindingType


class SherlockTool(ToolWrapper):
    name = "sherlock"
    description = "Hunt usernames across 400+ social networks"
    accepts_input = ["username"]
    category = "username_search"
    pip_module = "sherlock_project"
    cli_command = "sherlock"

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        output_dir = tempfile.mkdtemp()

        cmd = [
            "sherlock", input_value,
            "--folderoutput", output_dir,
            "--timeout", "10",
            "--print-found",
            "--no-color",
        ]
        raw = self._run_command(cmd, timeout=90)
        tool_run.raw_output = raw

        # Parse the txt output file sherlock creates
        txt_file = os.path.join(output_dir, f"{input_value}.txt")
        if os.path.exists(txt_file):
            try:
                with open(txt_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("http"):
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                line,
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={"username": input_value},
                            ))
            except Exception:
                pass

        # Fallback: parse stdout for URLs
        if not findings:
            for line in raw.split("\n"):
                line = line.strip()
                # Sherlock prints "[+] SiteName: URL"
                url_match = re.search(r'https?://\S+', line)
                if url_match and "[+]" in line:
                    url = url_match.group(0)
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        url,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={"username": input_value},
                    ))

        return findings
