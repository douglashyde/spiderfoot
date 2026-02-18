"""Blackbird - username search across platforms."""
import json
import os
from .base import ToolWrapper, Finding, FindingType


class BlackbirdTool(ToolWrapper):
    name = "blackbird"
    description = "Search usernames across online platforms"
    accepts_input = ["username"]
    category = "username_search"
    main_script = "blackbird.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "blackbird.py", "--username", input_value, "--json"]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        # Check for JSON output files
        results_dir = os.path.join(self.tool_path, "results")
        if os.path.isdir(results_dir):
            for fname in os.listdir(results_dir):
                if input_value in fname and fname.endswith(".json"):
                    try:
                        with open(os.path.join(results_dir, fname)) as f:
                            data = json.load(f)
                        for entry in data if isinstance(data, list) else [data]:
                            if isinstance(entry, dict):
                                for site in entry.get("sites", [entry]):
                                    if site.get("status", "").lower() in ("found", "claimed"):
                                        findings.append(Finding(
                                            FindingType.SOCIAL_PROFILE,
                                            site.get("url", ""),
                                            source_tool=self.name,
                                            confidence=0.8,
                                            metadata={"site": site.get("site", ""), "username": input_value},
                                        ))
                    except Exception:
                        pass

        # Fallback: parse stdout
        if not findings:
            for line in raw.split("\n"):
                if ("found" in line.lower() or "[+]" in line) and "http" in line:
                    idx = line.find("http")
                    url = line[idx:].split()[0] if idx >= 0 else ""
                    if url:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            url,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={"username": input_value},
                        ))

        return findings
