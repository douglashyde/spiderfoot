"""Base class for all tool wrappers."""
import subprocess
import os
import json
import tempfile
from engine.models import Finding, FindingType, ToolRun, ToolStatus
from config import TOOL_PATHS, SCAN_TIMEOUT


class ToolWrapper:
    """Base class that all tool wrappers inherit from."""

    name = "base"
    description = "Base tool"
    accepts_input = []  # e.g., ["email", "username", "phone", "domain"]
    category = "general"  # username_search, email_osint, phone_osint, breach, social, framework

    def __init__(self):
        self.tool_path = TOOL_PATHS.get(self.name, "")

    def is_available(self):
        """Check if the tool is installed and accessible."""
        return os.path.isdir(self.tool_path)

    def run(self, input_type, input_value, tool_run=None):
        """Execute the tool and return findings."""
        if tool_run is None:
            tool_run = ToolRun(self.name, input_type, input_value)
        tool_run.start()

        try:
            findings = self._execute(input_type, input_value, tool_run)
            tool_run.complete(findings)
        except Exception as e:
            tool_run.fail(str(e))
            findings = []

        return tool_run

    def _execute(self, input_type, input_value, tool_run):
        """Override this in subclasses. Must return list of Finding objects."""
        raise NotImplementedError

    def _run_command(self, cmd, cwd=None, timeout=None, env=None):
        """Run a shell command and return stdout."""
        timeout = timeout or SCAN_TIMEOUT
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or self.tool_path,
                env=run_env,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Tool {self.name} timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    def get_info(self):
        return {
            "name": self.name,
            "description": self.description,
            "accepts_input": self.accepts_input,
            "category": self.category,
            "available": self.is_available(),
        }
