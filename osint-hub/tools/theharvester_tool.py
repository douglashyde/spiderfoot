"""theHarvester - email, subdomain, IP OSINT."""
import json
import os
import tempfile
from .base import ToolWrapper, Finding, FindingType


class TheHarvesterTool(ToolWrapper):
    name = "theharvester"
    description = "Gather emails, subdomains, IPs from public sources"
    accepts_input = ["domain", "email"]
    category = "email_osint"
    cli_command = "theHarvester"
    main_script = "theHarvester/__main__.py"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # For email input, extract domain
        if input_type == "email" and "@" in input_value:
            domain = input_value.split("@")[1]
        else:
            domain = input_value

        output_file = os.path.join(tempfile.mkdtemp(), "results.json")

        cmd = [
            "python", "-m", "theHarvester",
            "-d", domain,
            "-b", "all",
            "-l", "200",
            "-f", output_file,
        ]
        raw = self._run_command(cmd, cwd=self.tool_path, timeout=300)
        tool_run.raw_output = raw

        # Parse JSON output
        json_file = output_file
        if not os.path.exists(json_file):
            json_file = output_file + ".json"

        if os.path.exists(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)

                for email in data.get("emails", []):
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"domain": domain},
                    ))

                for ip in data.get("ips", []):
                    findings.append(Finding(
                        FindingType.IP_ADDRESS,
                        ip,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"domain": domain},
                    ))

                for host in data.get("hosts", []):
                    findings.append(Finding(
                        FindingType.DOMAIN,
                        host,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"parent_domain": domain},
                    ))
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: parse text output
        if not findings:
            for line in raw.split("\n"):
                line = line.strip()
                if "@" in line and "." in line and " " not in line:
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        line,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"domain": domain},
                    ))

        return findings
