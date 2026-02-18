"""BreachDirectory - free breach search via RapidAPI free tier or direct scraping."""
import re
import json
import hashlib
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class BreachDirectoryTool(ToolWrapper):
    name = "breachdirectory"
    description = "Free breach directory lookup - SHA1 password hashes, breach sources"
    accepts_input = ["email", "username", "phone"]
    category = "breach"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # BreachDirectory has a free tier via RapidAPI that returns SHA-1 hashes
        # Also try their direct endpoint
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        # Method 1: Try BreachDirectory free API
        try:
            url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={input_value}"
            rapid_headers = {
                **headers,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            }
            resp = requests.get(url, headers=rapid_headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                tool_run.raw_output += f"BreachDirectory API: {json.dumps(data, indent=2)}\n"
                self._parse_breachdirectory_response(data, input_value, findings)
        except Exception as e:
            tool_run.raw_output += f"BreachDirectory API error: {e}\n"

        # Method 2: Try haveibeenpwned.com free check (no passwords, just breach names)
        try:
            url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{input_value}"
            resp = requests.get(url, headers={
                "User-Agent": "OSINT-Hub-Breach-Check",
                "Accept": "application/json",
            }, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                tool_run.raw_output += f"HIBP free: {json.dumps(data, indent=2)}\n"
                for breach in data:
                    name = breach.get("Name", "Unknown")
                    findings.append(Finding(
                        FindingType.BREACH,
                        name,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "email": input_value,
                            "breach_name": name,
                            "domain": breach.get("Domain", ""),
                            "breach_date": breach.get("BreachDate", ""),
                            "data_classes": breach.get("DataClasses", []),
                            "is_verified": breach.get("IsVerified", False),
                            "pwn_count": breach.get("PwnCount", 0),
                        },
                    ))
        except Exception as e:
            tool_run.raw_output += f"HIBP error: {e}\n"

        # Method 3: Generate SHA-1 hash for offline comparison
        if input_type == "email":
            sha1_hash = hashlib.sha1(input_value.encode()).hexdigest()
            findings.append(Finding(
                FindingType.RAW,
                f"SHA1({input_value})={sha1_hash}",
                source_tool=self.name,
                confidence=0.5,
                metadata={
                    "email": input_value,
                    "sha1": sha1_hash,
                    "type": "hash_for_lookup",
                },
            ))

        return findings

    def _parse_breachdirectory_response(self, data, input_value, findings):
        """Parse BreachDirectory API response."""
        if not isinstance(data, dict):
            return

        result = data.get("result", [])
        if isinstance(result, list):
            for entry in result:
                if isinstance(entry, dict):
                    sources = entry.get("sources", [])
                    password = entry.get("password", "")
                    sha1 = entry.get("sha1", "")
                    email = entry.get("email", input_value)

                    # Record breach sources
                    if isinstance(sources, list):
                        for source in sources:
                            findings.append(Finding(
                                FindingType.BREACH,
                                str(source),
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={
                                    "email": email,
                                    "source": "breachdirectory",
                                },
                            ))

                    # Record password hash (BD returns SHA-1 on free tier)
                    if sha1 and sha1.lower() not in ("", "none", "null"):
                        findings.append(Finding(
                            FindingType.PASSWORD_HASH,
                            sha1,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "email": email,
                                "hash_type": "sha1",
                                "source": "breachdirectory",
                            },
                        ))

                    # Record cleartext password if available
                    if password and password.lower() not in ("", "none", "null"):
                        findings.append(Finding(
                            FindingType.LEAKED_CREDENTIAL,
                            f"{email}:{password}",
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={
                                "email": email,
                                "password": password,
                                "source": "breachdirectory",
                            },
                        ))
