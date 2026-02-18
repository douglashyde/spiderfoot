"""Oblivion - data leak checker via Scylla.so."""
import json
import re
from .base import ToolWrapper, Finding, FindingType


class OblivionTool(ToolWrapper):
    name = "oblivion"
    description = "Check leaked credentials via Scylla.so database"
    accepts_input = ["email", "username"]
    category = "breach"
    main_script = "Linux/OblivionServer.py"

    def is_available(self):
        # Has API fallback to Scylla.so, so always available
        return True

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Oblivion has a server mode with API - try direct script
        cmd = ["python", "Linux/OblivionServer.py", "--search", input_value]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=60)

        # If that doesn't work, try querying Scylla.so directly
        if "error" in raw.lower() or not raw.strip():
            import urllib.request
            try:
                url = f"https://scylla.so/search?q=email:{input_value}&size=20"
                req = urllib.request.Request(url, headers={
                    "User-Agent": "OSINT-Hub/1.0",
                    "Accept": "application/json",
                })
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode()
            except Exception as e:
                raw = f"Scylla.so query failed: {e}"

        tool_run.raw_output = raw

        # Try JSON parsing
        try:
            data = json.loads(raw)
            hits = data if isinstance(data, list) else data.get("hits", {}).get("hits", [])
            for hit in hits:
                source = hit.get("_source", hit) if isinstance(hit, dict) else {}
                if source.get("email"):
                    findings.append(Finding(
                        FindingType.BREACH,
                        f"Leaked credential found for {source['email']}",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "email": source.get("email", ""),
                            "source_db": source.get("source", "scylla"),
                        },
                    ))
                if source.get("username") and source["username"] != input_value:
                    findings.append(Finding(
                        FindingType.RELATED_USERNAME,
                        source["username"],
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"found_with": input_value},
                    ))
        except (json.JSONDecodeError, TypeError, KeyError):
            # Parse text
            for line in raw.split("\n"):
                if "found" in line.lower() or "leak" in line.lower():
                    findings.append(Finding(
                        FindingType.RAW,
                        line.strip(),
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"query": input_value},
                    ))

        return findings
