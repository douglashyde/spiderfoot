"""IntelX Phonebook - free intelligence search via phonebook.cz (IntelX public)."""
import re
import json
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class IntelxPhonebookTool(ToolWrapper):
    name = "intelx_phonebook"
    description = "IntelX Phonebook - free email, domain, and URL intelligence search"
    accepts_input = ["email", "domain", "username"]
    category = "intelligence"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Phonebook.cz is IntelX's free public search
        # It searches emails, domains, and URLs across leaked/public data
        search_types = {
            "email": 0,     # email search
            "domain": 1,    # domain search
            "username": 0,  # try as email-like search
        }

        search_type = search_types.get(input_type, 0)

        # Step 1: Start search
        try:
            search_url = "https://2.intelx.io/phonebook/search"
            payload = {
                "term": input_value,
                "maxresults": 100,
                "media": 0,
                "target": search_type,
                "timeout": 20,
            }
            # IntelX free tier public key
            params = {"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571"}

            resp = requests.post(
                search_url, json=payload, params=params,
                headers=headers, timeout=20,
            )
            tool_run.raw_output += f"Search response: {resp.status_code}\n"

            if resp.status_code != 200:
                return findings

            data = resp.json()
            search_id = data.get("id")
            if not search_id:
                return findings

            # Step 2: Get results
            import time
            time.sleep(3)  # Wait for results

            result_url = f"https://2.intelx.io/phonebook/search/result"
            resp2 = requests.get(
                result_url,
                params={"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571", "id": search_id, "limit": 100},
                headers=headers,
                timeout=20,
            )
            tool_run.raw_output += f"Results: {resp2.text[:2000]}\n"

            if resp2.status_code != 200:
                return findings

            result_data = resp2.json()
            selectors = result_data.get("selectors", [])

            email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

            for selector in selectors:
                value = selector.get("selectorvalue", "")
                sel_type = selector.get("selectortype", 0)

                if not value:
                    continue

                # Type 0 = email, Type 1 = domain, Type 2 = URL
                if sel_type == 0 and email_pattern.match(value):
                    if value.lower() != input_value.lower():
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            value.lower(),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "searched_for": input_value,
                                "source": "intelx_phonebook",
                            },
                        ))
                elif sel_type == 1:
                    findings.append(Finding(
                        FindingType.RELATED_DOMAIN,
                        value.lower(),
                        source_tool=self.name,
                        confidence=0.65,
                        metadata={"searched_for": input_value},
                    ))
                elif sel_type == 2:
                    # URLs - check for social profiles
                    findings.append(Finding(
                        FindingType.RAW,
                        value,
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={
                            "searched_for": input_value,
                            "type": "url",
                        },
                    ))
                    # Check if it's a social profile
                    social_domains = [
                        "twitter.com", "x.com", "instagram.com", "facebook.com",
                        "linkedin.com", "github.com", "reddit.com", "tiktok.com",
                    ]
                    for sd in social_domains:
                        if sd in value.lower():
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                value,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={"searched_for": input_value},
                            ))
                            break

        except Exception as e:
            tool_run.raw_output += f"IntelX Phonebook error: {e}\n"

        return findings
