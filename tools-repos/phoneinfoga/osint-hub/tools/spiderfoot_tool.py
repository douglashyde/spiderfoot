"""SpiderFoot - automated OSINT framework."""
from .base import ToolWrapper, Finding, FindingType


class SpiderfootTool(ToolWrapper):
    name = "spiderfoot"
    description = "Automated OSINT collection framework"
    accepts_input = ["email", "username", "domain", "phone"]
    category = "framework"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # SpiderFoot CLI scan
        cmd = [
            "python", "sf.py",
            "-s", input_value,
            "-q",
            "-m", "sfp_accounts,sfp_emailformat,sfp_socialprofiles",
            "-F", "SOCIAL_MEDIA,EMAILADDR,PHONE_NUMBER,HUMAN_NAME",
        ]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=300)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith(("#", "---", "SpiderFoot")):
                continue
            if "SOCIAL_MEDIA" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        parts[2].strip(),
                        source_tool=self.name,
                        confidence=0.8,
                    ))
            elif "EMAILADDR" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        parts[2].strip(),
                        source_tool=self.name,
                        confidence=0.7,
                    ))
            elif "HUMAN_NAME" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    findings.append(Finding(
                        FindingType.FULL_NAME,
                        parts[2].strip(),
                        source_tool=self.name,
                        confidence=0.7,
                    ))

        return findings
