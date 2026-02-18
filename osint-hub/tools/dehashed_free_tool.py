"""Dehashed free search - scrapes what's available without API key."""
import re
import json
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class DehashedFreeTool(ToolWrapper):
    name = "dehashed_free"
    description = "Dehashed free search - breach records with partial credentials"
    accepts_input = ["email", "username", "phone", "domain"]
    category = "breach"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        # Try Dehashed search endpoint
        try:
            search_field = {
                "email": "email",
                "username": "username",
                "phone": "phone",
                "domain": "domain",
            }.get(input_type, "email")

            url = f"https://api.dehashed.com/search?query={search_field}:{input_value}"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"Dehashed: {resp.status_code}\n{resp.text[:3000]}\n"

            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entries", [])
                total = data.get("total", 0)

                if total > 0:
                    findings.append(Finding(
                        FindingType.BREACH,
                        f"{input_value}: {total} records in dehashed",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "target": input_value,
                            "total_records": total,
                            "source": "dehashed",
                        },
                    ))

                for entry in entries[:50]:
                    if not isinstance(entry, dict):
                        continue

                    email = entry.get("email", "")
                    username = entry.get("username", "")
                    password = entry.get("password", "")
                    hashed_password = entry.get("hashed_password", "")
                    name = entry.get("name", "")
                    phone = entry.get("phone", "")
                    ip_address = entry.get("ip_address", "")
                    database_name = entry.get("database_name", "")

                    # Record breach source
                    if database_name:
                        findings.append(Finding(
                            FindingType.BREACH,
                            database_name,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "target": input_value,
                                "source": "dehashed",
                            },
                        ))

                    # Leaked credentials
                    if password:
                        identity = email or username or input_value
                        findings.append(Finding(
                            FindingType.LEAKED_CREDENTIAL,
                            f"{identity}:{password}",
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={
                                "email": email,
                                "username": username,
                                "password": password,
                                "database": database_name,
                                "source": "dehashed",
                            },
                        ))

                    # Password hash
                    if hashed_password:
                        findings.append(Finding(
                            FindingType.PASSWORD_HASH,
                            hashed_password,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "email": email or input_value,
                                "database": database_name,
                                "source": "dehashed",
                            },
                        ))

                    # Related emails
                    if email and email.lower() != input_value.lower():
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            email.lower(),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"database": database_name},
                        ))

                    # Related usernames
                    if username and username.lower() != input_value.lower():
                        findings.append(Finding(
                            FindingType.RELATED_USERNAME,
                            username,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={"database": database_name},
                        ))

                    # Names
                    if name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            name,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "email": email,
                                "database": database_name,
                            },
                        ))

                    # Phone numbers
                    if phone and phone != input_value:
                        findings.append(Finding(
                            FindingType.RELATED_PHONE,
                            phone,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={"database": database_name},
                        ))

                    # IP addresses
                    if ip_address:
                        findings.append(Finding(
                            FindingType.IP_ADDRESS,
                            ip_address,
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "email": email,
                                "database": database_name,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Dehashed error: {e}\n"

        return findings
