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

        # Get detailed breach analytics
        try:
            url_analytics = f"https://api.xposedornot.com/v1/breach-analytics?email={input_value}"
            req_analytics = urllib.request.Request(url_analytics, headers={"User-Agent": "OSINT-Hub/1.0"})
            with urllib.request.urlopen(req_analytics, timeout=30) as resp_analytics:
                analytics_data = json.loads(resp_analytics.read().decode())
                if tool_run.raw_output:
                    tool_run.raw_output += "\n\n" + json.dumps(analytics_data, indent=2)
                else:
                    tool_run.raw_output = json.dumps(analytics_data, indent=2)

                exposed_breaches = analytics_data.get("ExposedBreaches", {}).get("breaches_details", [])
                if isinstance(exposed_breaches, list):
                    for breach_detail in exposed_breaches:
                        if isinstance(breach_detail, dict):
                            breach_name = breach_detail.get("breach", breach_detail.get("name", ""))
                            data_types = breach_detail.get("xposed_data", breach_detail.get("data_types", ""))
                            domain = breach_detail.get("domain", "")
                            date = breach_detail.get("xposed_date", breach_detail.get("date", ""))
                            records = breach_detail.get("xposed_records", breach_detail.get("records", 0))

                            if breach_name:
                                meta = {"email": input_value, "breach_name": breach_name}
                                if data_types:
                                    meta["data_types_exposed"] = data_types
                                if domain:
                                    meta["breach_domain"] = domain
                                if date:
                                    meta["breach_date"] = date
                                if records:
                                    meta["records_exposed"] = records

                                data_types_str = str(data_types).lower()
                                if any(kw in data_types_str for kw in ["password", "credential", "hash"]):
                                    meta["password_exposed"] = True

                                findings.append(Finding(
                                    FindingType.BREACH,
                                    f"{breach_name} ({data_types})" if data_types else breach_name,
                                    source_tool=self.name,
                                    confidence=0.95,
                                    metadata=meta,
                                ))

                metrics = analytics_data.get("BreachMetrics", {})
                if isinstance(metrics, dict) and metrics.get("passwords_strength"):
                    findings.append(Finding(
                        FindingType.RAW,
                        f"Password strength analysis available for {input_value}",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "email": input_value,
                            "password_metrics": metrics["passwords_strength"],
                            "type": "password_analysis",
                        },
                    ))
        except Exception:
            pass

        # Check password exposure (hash-based, privacy-preserving)
        try:
            url2 = f"https://passwords.xposedornot.com/v1/pass/anon/{input_value}"
            req2 = urllib.request.Request(url2, headers={"User-Agent": "OSINT-Hub/1.0"})
            with urllib.request.urlopen(req2, timeout=30) as resp2:
                pwd_data = json.loads(resp2.read().decode())
                if pwd_data.get("SearchPassAnon", {}).get("anon"):
                    count = pwd_data["SearchPassAnon"]["anon"]
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        f"Password for {input_value} exposed in {count} breaches",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "email": input_value,
                            "password_exposure_count": count,
                            "source": "xposedornot",
                            "type": "password_exposure",
                        },
                    ))
        except Exception:
            pass

        return findings
