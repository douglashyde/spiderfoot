"""PasteBin/Paste site search - search leaked data on paste sites."""
import re
import json
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class PasteDumpTool(ToolWrapper):
    name = "psbdmp"
    description = "Search paste sites for leaked data (emails, credentials, mentions)"
    accepts_input = ["email", "username", "domain"]
    category = "breach"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        }

        # Method 1: psbdmp.ws API (free, no auth)
        try:
            url = f"https://psbdmp.ws/api/v3/search/{input_value}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"PSBDMP: {resp.status_code} {resp.text[:2000]}\n"

            if resp.status_code == 200:
                data = resp.json()
                pastes = data if isinstance(data, list) else data.get("data", [])
                for paste in pastes:
                    if isinstance(paste, dict):
                        paste_id = paste.get("id", "")
                        paste_tags = paste.get("tags", "")
                        paste_time = paste.get("time", "")
                        paste_text = paste.get("text", "")

                        findings.append(Finding(
                            FindingType.PASTE,
                            f"https://pastebin.com/{paste_id}" if paste_id else str(paste),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "searched_for": input_value,
                                "paste_id": paste_id,
                                "tags": paste_tags,
                                "timestamp": paste_time,
                                "preview": paste_text[:200] if paste_text else "",
                            },
                        ))

                        # Extract emails from paste content
                        if paste_text:
                            emails = re.findall(
                                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                                paste_text,
                            )
                            for email in set(emails):
                                if email.lower() != input_value.lower():
                                    findings.append(Finding(
                                        FindingType.RELATED_EMAIL,
                                        email.lower(),
                                        source_tool=self.name,
                                        confidence=0.5,
                                        metadata={
                                            "found_in_paste": paste_id,
                                            "source": "psbdmp",
                                        },
                                    ))
        except Exception as e:
            tool_run.raw_output += f"PSBDMP error: {e}\n"

        # Method 2: Google Dorking via custom search (searches paste sites)
        try:
            paste_sites = [
                "site:pastebin.com", "site:ghostbin.co",
                "site:paste.ee", "site:dpaste.org",
            ]
            dork_query = f'"{input_value}" ({" OR ".join(paste_sites)})'
            tool_run.raw_output += f"Dork query: {dork_query}\n"
        except Exception as e:
            tool_run.raw_output += f"Dork error: {e}\n"

        # Method 3: Search IntelX pastes (free tier)
        try:
            url = "https://2.intelx.io/intelligent/search"
            payload = {
                "term": input_value,
                "buckets": ["pastes"],
                "maxresults": 20,
                "timeout": 10,
            }
            params = {"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571"}
            resp = requests.post(url, json=payload, params=params, headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
            }, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get("id")
                if search_id:
                    import time
                    time.sleep(2)
                    result_resp = requests.get(
                        f"https://2.intelx.io/intelligent/search/result",
                        params={"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571", "id": search_id},
                        timeout=15,
                    )
                    if result_resp.status_code == 200:
                        results = result_resp.json()
                        records = results.get("records", [])
                        tool_run.raw_output += f"IntelX pastes: {len(records)} results\n"
                        for record in records[:20]:
                            name = record.get("name", "")
                            media = record.get("mediah", "")
                            date = record.get("date", "")
                            findings.append(Finding(
                                FindingType.PASTE,
                                name or str(record.get("systemid", "")),
                                source_tool=self.name,
                                confidence=0.65,
                                metadata={
                                    "searched_for": input_value,
                                    "source": "intelx",
                                    "media_type": media,
                                    "date": date,
                                    "name": name,
                                },
                            ))
        except Exception as e:
            tool_run.raw_output += f"IntelX paste error: {e}\n"

        return findings
