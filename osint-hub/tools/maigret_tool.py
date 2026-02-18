"""Maigret - username search across 2500+ sites with detailed profiles."""
import json
import os
import re
import tempfile
from .base import ToolWrapper, Finding, FindingType


class MaigretTool(ToolWrapper):
    name = "maigret"
    description = "Collect person info from usernames across 2500+ sites"
    accepts_input = ["username"]
    category = "username_search"
    pip_module = "maigret"
    cli_command = "maigret"

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        output_dir = tempfile.mkdtemp()

        cmd = [
            "maigret",
            input_value,
            "--top-sites", "100",
            "-J", "ndjson",
            "-fo", output_dir,
            "--timeout", "10",
            "--no-color",
            "--no-progressbar",
        ]
        raw = self._run_command(cmd, timeout=120)
        tool_run.raw_output = raw

        # Try parsing ndjson output
        try:
            for fname in os.listdir(output_dir):
                if fname.endswith(".json"):
                    try:
                        with open(os.path.join(output_dir, fname)) as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    if entry.get("status") and entry["status"].get("status") == "Claimed":
                                        url = entry.get("url_user", "")
                                        site = entry.get("site_name", entry.get("site", {}).get("name", ""))
                                        meta = {"site": site, "username": input_value}
                                        if entry.get("ids_usernames"):
                                            meta["linked_usernames"] = entry["ids_usernames"]
                                        if entry.get("ids_links"):
                                            meta["linked_urls"] = entry["ids_links"]
                                        findings.append(Finding(
                                            FindingType.SOCIAL_PROFILE,
                                            url,
                                            source_tool=self.name,
                                            confidence=0.9,
                                            metadata=meta,
                                        ))
                                        for linked_un in entry.get("ids_usernames", {}).values():
                                            if linked_un != input_value:
                                                findings.append(Finding(
                                                    FindingType.RELATED_USERNAME,
                                                    linked_un,
                                                    source_tool=self.name,
                                                    confidence=0.6,
                                                    metadata={"found_on": site},
                                                ))
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        pass
        except Exception:
            pass

        # Fallback: parse stdout for URLs
        if not findings:
            for line in raw.split("\n"):
                url_match = re.search(r'https?://\S+', line)
                if url_match and ("[+]" in line or "Claimed" in line):
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        url_match.group(0),
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"username": input_value},
                    ))

        return findings
