"""XposedOrNot - free breach notification API (no API key)."""
import json
import urllib.request
import urllib.error
from .base import ToolWrapper, Finding, FindingType


class XposedOrNotTool(ToolWrapper):
    name = "xposedornot"
    description = "Check email breaches via free XposedOrNot API"
    accepts_input = ["email"]
    category = "breach"

    def is_available(self):
        return True  # API-based, always available

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Check breaches
        try:
            url = f"https://api.xposedornot.com/v1/check-email/{input_value}"
            req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Hub/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                tool_run.raw_output = json.dumps(data, indent=2)

                if data.get("breaches"):
                    breach_list = data["breaches"]
                    if isinstance(breach_list, list) and breach_list:
                        # Can be nested: [["Breach1", "Breach2"]]
                        breaches = breach_list[0] if isinstance(breach_list[0], list) else breach_list
                        for breach_name in breaches:
                            findings.append(Finding(
                                FindingType.BREACH,
                                breach_name,
                                source_tool=self.name,
                                confidence=0.95,
                                metadata={"email": input_value},
                            ))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                tool_run.raw_output = "No breaches found"
            else:
                tool_run.raw_output = f"HTTP Error {e.code}"
        except Exception as e:
            tool_run.raw_output = str(e)

        # Check password exposure (hash-based, privacy-preserving)
        try:
            url2 = f"https://passwords.xposedornot.com/v1/pass/anon/{input_value}"
            req2 = urllib.request.Request(url2, headers={"User-Agent": "OSINT-Hub/1.0"})
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                pwd_data = json.loads(resp2.read().decode())
                if pwd_data.get("SearchPassAnon", {}).get("anon"):
                    count = pwd_data["SearchPassAnon"]["anon"]
                    findings.append(Finding(
                        FindingType.RAW,
                        f"Password associated with {input_value} found in {count} breaches",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={"email": input_value, "password_exposure_count": count},
                    ))
        except Exception:
            pass

        return findings
