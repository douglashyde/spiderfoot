"""LeakLooker - find exposed databases and servers."""
import json
import re
from .base import ToolWrapper, Finding, FindingType


class LeakLookerTool(ToolWrapper):
    name = "leaklooker"
    description = "Search for exposed databases, servers, and leaked data"
    accepts_input = ["domain", "email"]
    category = "breach"
    main_script = "leaklooker.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Extract domain from email if needed
        if input_type == "email" and "@" in input_value:
            query = input_value.split("@")[1]
        else:
            query = input_value

        cmd = ["python", "leaklooker.py", "--query", query]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=120)
        tool_run.raw_output = raw

        # Try JSON
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        ip = entry.get("ip", entry.get("host", ""))
                        db_type = entry.get("type", entry.get("service", ""))
                        if ip:
                            findings.append(Finding(
                                FindingType.IP_ADDRESS,
                                ip,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={"domain": query, "service": db_type},
                            ))
                        findings.append(Finding(
                            FindingType.RAW,
                            json.dumps(entry),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"domain": query, "type": "exposed_service"},
                        ))
        except (json.JSONDecodeError, TypeError):
            # Parse text output
            for line in raw.split("\n"):
                line = line.strip()
                if not line or line.startswith(("#", "[*]")):
                    continue
                # Look for IPs
                ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                for ip in ips:
                    findings.append(Finding(
                        FindingType.IP_ADDRESS,
                        ip,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"domain": query},
                    ))
                if "exposed" in line.lower() or "open" in line.lower() or "database" in line.lower():
                    findings.append(Finding(
                        FindingType.RAW,
                        line,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"domain": query, "type": "exposed_service"},
                    ))

        return findings
