"""PhoneInfoga - phone number OSINT."""
import json
from .base import ToolWrapper, Finding, FindingType


class PhoneInfogaTool(ToolWrapper):
    name = "phoneinfoga"
    description = "Advanced phone number OSINT framework"
    accepts_input = ["phone"]
    category = "phone_osint"
    cli_command = "phoneinfoga"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["phoneinfoga", "scan", "-n", input_value]
        raw = self._run_command(cmd)

        if "[ERROR]" in raw or "not found" in raw.lower():
            cmd = ["python", "phoneinfoga.py", "scan", "-n", input_value]
            raw = self._run_command(cmd)

        tool_run.raw_output = raw

        # Parse output for phone metadata
        info = {}
        for line in raw.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if value and value != "null":
                    info[key] = value

        if info:
            findings.append(Finding(
                FindingType.RAW,
                json.dumps(info),
                source_tool=self.name,
                confidence=0.9,
                metadata={"phone": input_value, "type": "phone_info", **info},
            ))

            # Extract specific details
            for key in ("carrier", "country", "location", "region"):
                if key in info:
                    findings.append(Finding(
                        FindingType.LOCATION,
                        info[key],
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"phone": input_value, "detail": key},
                    ))

        return findings
