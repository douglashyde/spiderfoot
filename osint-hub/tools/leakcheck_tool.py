"""LeakCheck - free breach lookup with public endpoint."""
import json
import re
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class LeakCheckTool(ToolWrapper):
    name = "leakcheck"
    description = "LeakCheck free breach lookup - breach sources and partial data"
    accepts_input = ["email", "username", "phone"]
    category = "breach"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
        }

        # LeakCheck public lookup endpoint
        try:
            url = f"https://leakcheck.io/api/public?check={input_value}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"LeakCheck: {resp.status_code} {resp.text[:3000]}\n"

            if resp.status_code == 200:
                data = resp.json()

                if data.get("success") and data.get("found", 0) > 0:
                    found_count = data.get("found", 0)

                    findings.append(Finding(
                        FindingType.BREACH,
                        f"{input_value}: {found_count} breach entries found",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "target": input_value,
                            "found_count": found_count,
                            "source": "leakcheck",
                        },
                    ))

                    # Parse individual results
                    results = data.get("result", [])
                    for entry in results:
                        if isinstance(entry, dict):
                            source_name = entry.get("source", {})
                            if isinstance(source_name, dict):
                                source_name = source_name.get("name", "unknown")

                            findings.append(Finding(
                                FindingType.BREACH,
                                str(source_name),
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "target": input_value,
                                    "breach_source": str(source_name),
                                    "source": "leakcheck",
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"LeakCheck error: {e}\n"

        # Also try XposedOrNot API (free, no key)
        try:
            url = f"https://api.xposedornot.com/v1/check-email/{input_value}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"XposedOrNot: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get("breaches", [])
                if isinstance(breaches, list):
                    for breach in breaches:
                        if isinstance(breach, str):
                            findings.append(Finding(
                                FindingType.BREACH,
                                breach,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "email": input_value,
                                    "source": "xposedornot",
                                },
                            ))
                        elif isinstance(breach, dict):
                            name = breach.get("breach", breach.get("name", str(breach)))
                            findings.append(Finding(
                                FindingType.BREACH,
                                str(name),
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "email": input_value,
                                    "details": breach,
                                    "source": "xposedornot",
                                },
                            ))
        except Exception as e:
            tool_run.raw_output += f"XposedOrNot API error: {e}\n"

        return findings
