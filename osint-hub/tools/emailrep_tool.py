"""EmailRep.io - free email reputation and intelligence."""
import json
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class EmailRepTool(ToolWrapper):
    name = "emailrep"
    description = "Email reputation check - breach history, social profiles, domain age"
    accepts_input = ["email"]
    category = "email_osint"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        try:
            url = f"https://emailrep.io/{input_value}"
            headers = {
                "User-Agent": "OSINT-Hub",
                "Accept": "application/json",
            }
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output = f"Status: {resp.status_code}\n{resp.text[:3000]}\n"

            if resp.status_code != 200:
                return findings

            data = resp.json()

            # Reputation info
            reputation = data.get("reputation", "none")
            suspicious = data.get("suspicious", False)
            references = data.get("references", 0)
            details = data.get("details", {})

            # Breach info
            credentials_leaked = details.get("credentials_leaked", False)
            credentials_leaked_recent = details.get("credentials_leaked_recent", False)
            data_breach = details.get("data_breach", False)

            if data_breach or credentials_leaked:
                findings.append(Finding(
                    FindingType.BREACH,
                    f"{input_value} found in data breaches",
                    source_tool=self.name,
                    confidence=0.85,
                    metadata={
                        "email": input_value,
                        "credentials_leaked": credentials_leaked,
                        "credentials_leaked_recent": credentials_leaked_recent,
                        "data_breach": data_breach,
                        "reputation": reputation,
                        "references": references,
                    },
                ))

            # Social/profile info
            profiles = details.get("profiles", [])
            for profile in profiles:
                findings.append(Finding(
                    FindingType.REGISTERED_SITE,
                    str(profile),
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={
                        "email": input_value,
                        "source": "emailrep",
                    },
                ))

            # Domain info
            domain_exists = details.get("domain_exists", False)
            domain_reputation = details.get("domain_reputation", "")
            free_provider = details.get("free_provider", False)
            deliverable = details.get("deliverable", False)
            accept_all = details.get("accept_all", False)
            spf_strict = details.get("spf_strict", False)
            dmarc_enforced = details.get("dmarc_enforced", False)

            # Extract domain
            if "@" in input_value:
                domain = input_value.split("@")[1]
                findings.append(Finding(
                    FindingType.RAW,
                    f"Domain analysis: {domain}",
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={
                        "domain": domain,
                        "exists": domain_exists,
                        "reputation": domain_reputation,
                        "free_provider": free_provider,
                        "deliverable": deliverable,
                        "accept_all": accept_all,
                        "spf_strict": spf_strict,
                        "dmarc_enforced": dmarc_enforced,
                        "suspicious": suspicious,
                        "overall_reputation": reputation,
                    },
                ))

            # Last seen / activity
            last_seen = details.get("last_seen", "")
            first_seen = details.get("first_seen", "")
            if last_seen or first_seen:
                findings.append(Finding(
                    FindingType.RAW,
                    f"Activity: first={first_seen}, last={last_seen}",
                    source_tool=self.name,
                    confidence=0.6,
                    metadata={
                        "email": input_value,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    },
                ))

        except Exception as e:
            tool_run.raw_output += f"EmailRep error: {e}\n"

        return findings
