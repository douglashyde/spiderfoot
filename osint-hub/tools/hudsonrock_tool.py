"""Hudson Rock Cavalier - free infostealer/botnet credential lookup."""
import json
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class HudsonRockTool(ToolWrapper):
    name = "hudsonrock"
    description = "Hudson Rock - free infostealer credential and botnet exposure check"
    accepts_input = ["email", "domain", "username"]
    category = "breach"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        # Hudson Rock Cavalier free API - checks if email/domain appeared in
        # infostealer logs (Raccoon, Redline, Vidar, etc.)
        endpoints = {
            "email": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={input_value}",
            "domain": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={input_value}",
            "username": f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={input_value}",
        }

        url = endpoints.get(input_type)
        if not url:
            return findings

        try:
            resp = requests.get(url, headers=headers, timeout=20)
            tool_run.raw_output = f"Status: {resp.status_code}\n{resp.text[:5000]}\n"

            if resp.status_code != 200:
                return findings

            data = resp.json()

            # Parse stealers data
            stealers = data.get("stealers", [])
            if not stealers and isinstance(data, list):
                stealers = data

            for stealer in stealers:
                if not isinstance(stealer, dict):
                    continue

                computer_name = stealer.get("computer_name", "")
                operating_system = stealer.get("operating_system", "")
                malware_path = stealer.get("malware_path", "")
                date_compromised = stealer.get("date_compromised", "")
                ip = stealer.get("ip", "")
                antiviruses = stealer.get("antiviruses", "")

                # Top-level finding: computer was compromised by infostealer
                findings.append(Finding(
                    FindingType.BREACH,
                    f"Infostealer infection: {computer_name or 'unknown machine'}",
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={
                        "target": input_value,
                        "computer_name": computer_name,
                        "operating_system": operating_system,
                        "malware_path": malware_path,
                        "date_compromised": date_compromised,
                        "ip": ip,
                        "antiviruses": antiviruses,
                        "type": "infostealer",
                        "source": "hudsonrock",
                    },
                ))

                # IP address
                if ip:
                    findings.append(Finding(
                        FindingType.IP_ADDRESS,
                        ip,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "target": input_value,
                            "computer_name": computer_name,
                            "context": "compromised_machine_ip",
                        },
                    ))

                # Credentials from the stealer log
                top_logins = stealer.get("top_logins", [])
                for login in top_logins:
                    if isinstance(login, dict):
                        login_url = login.get("url", "")
                        login_user = login.get("username", "")
                        login_pass = login.get("password", "")

                        if login_user or login_pass:
                            cred_value = f"{login_user}:{login_pass}" if login_pass else login_user
                            findings.append(Finding(
                                FindingType.LEAKED_CREDENTIAL,
                                cred_value,
                                source_tool=self.name,
                                confidence=0.9,
                                metadata={
                                    "url": login_url,
                                    "username": login_user,
                                    "password": login_pass,
                                    "date_compromised": date_compromised,
                                    "source": "infostealer_log",
                                    "computer_name": computer_name,
                                },
                            ))

                        # Extract related domain from login URL
                        if login_url:
                            import re
                            domain_match = re.search(r"https?://([^/]+)", login_url)
                            if domain_match:
                                findings.append(Finding(
                                    FindingType.REGISTERED_SITE,
                                    domain_match.group(1),
                                    source_tool=self.name,
                                    confidence=0.85,
                                    metadata={
                                        "login_url": login_url,
                                        "context": "saved_credential_site",
                                    },
                                ))

                # Top passwords (if available)
                top_passwords = stealer.get("top_passwords", [])
                for pwd_entry in top_passwords:
                    if isinstance(pwd_entry, dict):
                        pwd = pwd_entry.get("password", "")
                        if pwd:
                            findings.append(Finding(
                                FindingType.LEAKED_CREDENTIAL,
                                f"{input_value}:{pwd}",
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={
                                    "password": pwd,
                                    "source": "infostealer_top_passwords",
                                    "target": input_value,
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"HudsonRock error: {e}\n"

        return findings
