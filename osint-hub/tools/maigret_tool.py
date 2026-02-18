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

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        output_dir = tempfile.mkdtemp()

        cmd = [
            "python", "-m", "maigret",
            input_value,
            "--json", "ndjson",
            "-fo", output_dir,
            "--timeout", "15",
            "--no-color",
        ]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=360)
        tool_run.raw_output = raw

        # Try parsing ndjson output
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

                                    # Extract tags/categories for the site
                                    if entry.get("site", {}).get("tags"):
                                        meta["tags"] = entry["site"]["tags"]

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

                                    # Promote linked usernames to proper findings
                                    for linked_un in entry.get("ids_usernames", {}).values():
                                        if linked_un != input_value:
                                            findings.append(Finding(
                                                FindingType.RELATED_USERNAME,
                                                linked_un,
                                                source_tool=self.name,
                                                confidence=0.6,
                                                metadata={"found_on": site, "profile_url": url},
                                            ))

                                    # Promote linked URLs to separate profile findings
                                    for link_key, link_url in entry.get("ids_links", {}).items():
                                        if link_url and link_url != url and link_url.startswith("http"):
                                            findings.append(Finding(
                                                FindingType.SOCIAL_PROFILE,
                                                link_url,
                                                source_tool=self.name,
                                                confidence=0.7,
                                                metadata={
                                                    "site": site,
                                                    "username": input_value,
                                                    "link_type": link_key,
                                                    "discovered_from": url,
                                                },
                                            ))

                                    # Extract bio/about if available
                                    if entry.get("ids_id"):
                                        meta["user_id"] = entry["ids_id"]

                            except json.JSONDecodeError:
                                continue
                except Exception:
                    pass

        # Fallback: parse stdout for URLs
        if not findings:
            for line in raw.split("\n"):
                if "[+]" in line and "http" in line:
                    parts = line.split("http")
                    if len(parts) >= 2:
                        url = "http" + parts[-1].strip()
                        # Extract site name from the line
                        site_match = re.search(r"\[.\]\s*(\S+)", line)
                        site_name = site_match.group(1) if site_match else ""
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            url,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={"username": input_value, "site": site_name},
                        ))

        return findings
