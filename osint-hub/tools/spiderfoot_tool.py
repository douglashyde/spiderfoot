"""SpiderFoot - automated OSINT collection framework."""
import re
from .base import ToolWrapper, Finding, FindingType


class SpiderfootTool(ToolWrapper):
    name = "spiderfoot"
    description = "Automated OSINT collection framework"
    accepts_input = ["email", "username", "domain", "phone"]
    category = "framework"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # SpiderFoot CLI scan with expanded modules
        cmd = [
            "python", "sf.py",
            "-s", input_value,
            "-q",
            "-m", "sfp_accounts,sfp_emailformat,sfp_socialprofiles,sfp_haveibeenpwned,sfp_leakix,sfp_psbdmp",
            "-F", "SOCIAL_MEDIA,EMAILADDR,PHONE_NUMBER,HUMAN_NAME,ACCOUNT_EXTERNAL_OWNED,LEAKED_CREDENTIAL",
        ]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=300)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith(("#", "---", "SpiderFoot")):
                continue

            if "SOCIAL_MEDIA" in line or "ACCOUNT_EXTERNAL" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    url_or_profile = parts[2].strip()
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        url_or_profile,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"input": input_value},
                    ))
            elif "EMAILADDR" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    email = parts[2].strip()
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"input": input_value},
                    ))
            elif "HUMAN_NAME" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    findings.append(Finding(
                        FindingType.FULL_NAME,
                        parts[2].strip(),
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"input": input_value},
                    ))
            elif "PHONE_NUMBER" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    findings.append(Finding(
                        FindingType.RELATED_PHONE,
                        parts[2].strip(),
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"input": input_value},
                    ))
            elif "LEAKED_CREDENTIAL" in line:
                parts = line.split(",", 2)
                if len(parts) >= 3:
                    cred = parts[2].strip()
                    cred_parts = cred.split(":", 1) if ":" in cred else [cred, ""]
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        cred,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "identity": cred_parts[0],
                            "password": cred_parts[1] if len(cred_parts) > 1 else "",
                            "source": "spiderfoot",
                            "type": "credential_pair",
                        },
                    ))

        return findings
