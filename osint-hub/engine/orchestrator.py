"""
Orchestrator - runs tools intelligently, chains results, and builds the profile.
This is the brain of the OSINT Hub.
"""
import sys
import os
import threading
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.models import TargetProfile, Finding, FindingType, ToolRun, ToolStatus
from engine.correlator import Correlator
from tools.registry import get_tools_for_input, get_all_tool_info, ALL_TOOLS, TOOL_PRIORITY
from config import MAX_CHAIN_DEPTH, DATA_DIR


class ScanStatus:
    """Tracks the overall scan progress."""

    def __init__(self):
        self.phase = "idle"  # idle, scanning, correlating, chaining, complete
        self.current_tool = None
        self.progress = 0  # 0-100
        self.total_tools = 0
        self.completed_tools = 0
        self.log = []
        self.started_at = None
        self.finished_at = None
        self.chain_depth = 0

    def log_event(self, message):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "message": message}
        self.log.append(entry)

    def to_dict(self):
        return {
            "phase": self.phase,
            "current_tool": self.current_tool,
            "progress": self.progress,
            "total_tools": self.total_tools,
            "completed_tools": self.completed_tools,
            "log": self.log[-50:],  # Last 50 entries
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "chain_depth": self.chain_depth,
        }


class Orchestrator:
    """Manages the entire scan lifecycle."""

    def __init__(self):
        self.profile = None
        self.status = ScanStatus()
        self.correlator = None
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def start_scan(self, seeds):
        """Start a new scan with the given seeds.

        seeds = {
            "email": "user@example.com",
            "username": "johndoe",
            "phone": "+1234567890",
            "full_name": "John Doe",
            "domain": "example.com",
        }
        """
        if self._running:
            return {"error": "Scan already in progress"}

        self.profile = TargetProfile()
        self.profile.add_seeds(seeds)
        self.correlator = Correlator(self.profile)
        self.status = ScanStatus()
        self.status.started_at = datetime.now().isoformat()
        self.status.phase = "scanning"

        self._running = True
        self._thread = threading.Thread(target=self._run_scan, args=(seeds,), daemon=True)
        self._thread.start()

        return {"status": "started", "profile_id": self.profile.id}

    def _run_scan(self, seeds):
        """Main scan loop."""
        try:
            # Phase 1: Run tools on all seed inputs
            self.status.log_event("=== Phase 1: Initial seed scanning ===")
            self._scan_seeds(seeds)

            # Phase 2: Correlate findings
            self.status.phase = "correlating"
            self.status.log_event("=== Phase 2: Cross-referencing findings ===")
            self.correlator.correlate()

            # Phase 3: Chase new leads (up to MAX_CHAIN_DEPTH)
            for depth in range(MAX_CHAIN_DEPTH):
                new_leads = self.profile.get_new_leads()
                if not new_leads:
                    self.status.log_event(f"No new leads at depth {depth + 1}")
                    break

                self.status.phase = "chaining"
                self.status.chain_depth = depth + 1
                self.status.log_event(
                    f"=== Phase 3.{depth + 1}: Chasing {len(new_leads)} new leads (depth {depth + 1}) ==="
                )

                for lead_type, lead_value in new_leads:
                    self.status.log_event(f"New lead: {lead_type} = {lead_value}")
                    tools = get_tools_for_input(lead_type)
                    # Only run fast/reliable tools on chained leads
                    priority_tools = [t for t in tools if TOOL_PRIORITY.get(t.name, 99) <= 8]
                    for tool in priority_tools:
                        run_key = f"{tool.name}:{lead_value}"
                        already_run = any(
                            f"{tr.tool_name}:{tr.input_value}" == run_key
                            for tr in self.profile.tool_runs
                        )
                        if not already_run:
                            self._run_tool(tool, lead_type, lead_value)

                # Re-correlate after chaining
                self.correlator.correlate()

            # Phase 4: Final summary
            self.status.phase = "complete"
            self.status.progress = 100
            self.status.finished_at = datetime.now().isoformat()

            total_findings = len(self.profile.findings)
            total_runs = len(self.profile.tool_runs)
            successful = sum(1 for tr in self.profile.tool_runs if tr.status == ToolStatus.COMPLETED)
            self.status.log_event(
                f"=== Scan complete: {total_findings} findings from {successful}/{total_runs} tool runs ==="
            )

            # Save results
            report_path = os.path.join(DATA_DIR, f"scan_{self.profile.id}.json")
            self.profile.save(report_path)
            self.status.log_event(f"Report saved to {report_path}")

        except Exception as e:
            self.status.phase = "complete"
            self.status.log_event(f"ERROR: {str(e)}")
        finally:
            self._running = False

    def _scan_seeds(self, seeds):
        """Run appropriate tools on each seed input."""
        all_runs = []

        for input_type, value in seeds.items():
            if not value:
                continue

            values = [v.strip() for v in value.split(",")] if isinstance(value, str) else [value]
            for val in values:
                if not val:
                    continue

                # Add as a finding
                type_map = {
                    "email": FindingType.EMAIL,
                    "username": FindingType.USERNAME,
                    "phone": FindingType.PHONE,
                    "full_name": FindingType.FULL_NAME,
                    "domain": FindingType.DOMAIN,
                }
                if input_type in type_map:
                    self.profile.add_finding(Finding(
                        type_map[input_type], val,
                        source_tool="user_input",
                        confidence=1.0,
                    ))

                tools = get_tools_for_input(input_type)
                for tool in tools:
                    all_runs.append((tool, input_type, val))

        self.status.total_tools = len(all_runs)
        self.status.log_event(f"Queued {len(all_runs)} tool runs across {len(seeds)} seed types")

        for tool, input_type, val in all_runs:
            if not self._running:
                break
            self._run_tool(tool, input_type, val)

    def _run_tool(self, tool, input_type, input_value):
        """Execute a single tool and process results."""
        self.status.current_tool = tool.name
        self.status.log_event(f"Running {tool.name} on {input_type}={input_value}")

        tool_run = ToolRun(tool.name, input_type, input_value)
        self.profile.add_tool_run(tool_run)

        try:
            tool.run(input_type, input_value, tool_run)

            if tool_run.status == ToolStatus.COMPLETED:
                for finding in tool_run.findings:
                    self.profile.add_finding(finding)
                self.status.log_event(
                    f"  {tool.name}: {len(tool_run.findings)} findings"
                )
            else:
                self.status.log_event(
                    f"  {tool.name}: FAILED - {tool_run.error}"
                )
        except Exception as e:
            tool_run.fail(str(e))
            self.status.log_event(f"  {tool.name}: ERROR - {str(e)}")

        self.status.completed_tools += 1
        if self.status.total_tools > 0:
            self.status.progress = int(
                (self.status.completed_tools / self.status.total_tools) * 90
            )

    def get_status(self):
        return self.status.to_dict()

    def get_results(self):
        if self.profile:
            return self.profile.to_dict()
        return {}

    def get_recommendations(self):
        if self.correlator:
            return self.correlator.get_tool_recommendations()
        return []

    def is_running(self):
        return self._running

    def stop_scan(self):
        self._running = False
        self.status.log_event("Scan stopped by user")
