"""Base class for all tool wrappers."""
import subprocess
import shutil
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
    # Set to a pip module name to auto-detect pip-installed tools
    pip_module = None
    # Set to a CLI command name to auto-detect CLI-available tools
    cli_command = None

    def __init__(self):
        self.tool_path = TOOL_PATHS.get(self.name, "")

    def is_available(self):
        """Check if the tool is installed and accessible."""
        # Check if directory exists (git-cloned tool)
        if os.path.isdir(self.tool_path):
            return True
        # Check if pip module is importable
        if self.pip_module:
            try:
                __import__(self.pip_module)
                return True
            except ImportError:
                pass
        # Check if CLI command is on PATH
        if self.cli_command:
            if shutil.which(self.cli_command):
                return True
        return False

    def _get_cwd(self):
        """Get a valid working directory for subprocess calls."""
        if os.path.isdir(self.tool_path):
            return self.tool_path
        return tempfile.gettempdir()

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
        work_dir = cwd or self._get_cwd()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=work_dir,
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
