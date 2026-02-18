"""Social Analyzer - social media account detection."""
import json
import os
from .base import ToolWrapper, Finding, FindingType


class SocialAnalyzerTool(ToolWrapper):
    name = "social_analyzer"
    description = "Detect social media accounts by username"
    accepts_input = ["username"]
    category = "username_search"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = [
            "python", "-m", "social-analyzer",
            "--username", input_value,
            "--metadata",
            "--output", "json",
            "--trim",
        ]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=180)
        tool_run.raw_output = raw

        # Try to parse JSON from output
        try:
            # social-analyzer may output JSON directly
            data = json.loads(raw)
            if isinstance(data, dict):
                for site, info in data.items():
                    if isinstance(info, dict) and info.get("found"):
                        url = info.get("link", info.get("url", ""))
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            url or site,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={"site": site, "username": input_value},
                        ))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("found"):
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            item.get("link", item.get("url", "")),
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={"site": item.get("name", ""), "username": input_value},
                        ))
        except (json.JSONDecodeError, TypeError):
            # Parse text output
            for line in raw.split("\n"):
                if "found" in line.lower() and "http" in line:
                    url_start = line.find("http")
                    url = line[url_start:].split()[0] if url_start >= 0 else ""
                    if url:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            url,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"username": input_value},
                        ))

        return findings
