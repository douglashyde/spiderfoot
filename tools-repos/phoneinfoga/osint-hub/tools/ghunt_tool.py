"""GHunt - Google account OSINT."""
import json
from .base import ToolWrapper, Finding, FindingType


class GHuntTool(ToolWrapper):
    name = "ghunt"
    description = "Investigate Google accounts"
    accepts_input = ["email"]
    category = "social"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        cmd = ["python", "-m", "ghunt", "email", input_value, "--json"]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        # Try JSON parsing
        try:
            data = json.loads(raw)
            if data.get("name"):
                findings.append(Finding(
                    FindingType.FULL_NAME,
                    data["name"],
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={"email": input_value},
                ))
            if data.get("profile_photo"):
                findings.append(Finding(
                    FindingType.PHOTO_URL,
                    data["profile_photo"],
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={"email": input_value},
                ))
            if data.get("last_edit"):
                findings.append(Finding(
                    FindingType.RAW,
                    f"Google profile last edited: {data['last_edit']}",
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={"email": input_value},
                ))
        except (json.JSONDecodeError, TypeError):
            # Parse text output
            for line in raw.split("\n"):
                if "name" in line.lower() and ":" in line:
                    name = line.split(":", 1)[1].strip()
                    if name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            name,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"email": input_value},
                        ))

        return findings
