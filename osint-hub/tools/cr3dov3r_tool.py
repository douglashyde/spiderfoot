"""Cr3dOv3r - credential leak checker."""
import re
from .base import ToolWrapper, Finding, FindingType


class Cr3dOv3rTool(ToolWrapper):
    name = "cr3dov3r"
    description = "Check if email credentials were leaked"
    accepts_input = ["email"]
    category = "breach"

    def _execute(self, input_type, input_value, tool_run):
        findings = []

        # Run in quiet mode, skip active credential testing (-p flag)
        cmd = ["python", "Cr3d0v3r.py", input_value, "-q", "-p"]
        raw = self._run_command(cmd, cwd=self.tool_path)
        tool_run.raw_output = raw

        for line in raw.split("\n"):
            line = line.strip()
            if "leak" in line.lower() or "breach" in line.lower() or "found" in line.lower():
                findings.append(Finding(
                    FindingType.BREACH,
                    line,
                    source_tool=self.name,
                    confidence=0.8,
                    metadata={"email": input_value},
                ))
            elif "password" in line.lower() and "not" not in line.lower():
                findings.append(Finding(
                    FindingType.RAW,
                    f"Password exposure detected for {input_value}",
                    source_tool=self.name,
                    confidence=0.85,
                    metadata={"email": input_value, "type": "password_leak"},
                ))

        return findings
