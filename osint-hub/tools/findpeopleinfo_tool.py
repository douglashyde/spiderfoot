"""findpeopleinfo - people search tool."""
import re
import json
from .base import ToolWrapper, Finding, FindingType


class FindPeopleInfoTool(ToolWrapper):
    name = "findpeopleinfo"
    description = "Search for people by name, email, or phone"
    accepts_input = ["full_name", "email", "phone"]
    category = "social"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        if input_type == "full_name":
            cmd = ["python", "findpeopleinfo.py", "--name", input_value]
        elif input_type == "email":
            cmd = ["python", "findpeopleinfo.py", "--email", input_value]
        elif input_type == "phone":
            cmd = ["python", "findpeopleinfo.py", "--phone", input_value]
        else:
            cmd = ["python", "findpeopleinfo.py", "--query", input_value]

        raw = self._run_command(cmd, cwd=self.tool_path, timeout=120)
        tool_run.raw_output = raw

        # Try JSON
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for person in data:
                    if isinstance(person, dict):
                        if person.get("name"):
                            findings.append(Finding(
                                FindingType.FULL_NAME,
                                person["name"],
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={"query": input_value},
                            ))
                        if person.get("email"):
                            findings.append(Finding(
                                FindingType.RELATED_EMAIL,
                                person["email"],
                                source_tool=self.name,
                                confidence=0.6,
                                metadata={"query": input_value},
                            ))
                        if person.get("phone"):
                            findings.append(Finding(
                                FindingType.RELATED_PHONE,
                                person["phone"],
                                source_tool=self.name,
                                confidence=0.6,
                                metadata={"query": input_value},
                            ))
                        if person.get("location") or person.get("address"):
                            findings.append(Finding(
                                FindingType.LOCATION,
                                person.get("location", person.get("address", "")),
                                source_tool=self.name,
                                confidence=0.5,
                                metadata={"query": input_value},
                            ))
        except (json.JSONDecodeError, TypeError):
            # Parse text output
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw)
            for email in set(emails):
                findings.append(Finding(
                    FindingType.RELATED_EMAIL,
                    email.lower(),
                    source_tool=self.name,
                    confidence=0.5,
                    metadata={"query": input_value},
                ))

            phones = re.findall(r"\+?\d[\d\-\(\) ]{8,}\d", raw)
            for phone in set(phones):
                clean = re.sub(r"[^\d+]", "", phone)
                if len(clean) >= 10:
                    findings.append(Finding(
                        FindingType.RELATED_PHONE,
                        clean,
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={"query": input_value},
                    ))

            # Look for URLs (social profiles, public records)
            urls = re.findall(r"https?://\S+", raw)
            for url in set(urls):
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    url,
                    source_tool=self.name,
                    confidence=0.5,
                    metadata={"query": input_value},
                ))

        return findings
