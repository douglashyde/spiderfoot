"""Data models for the OSINT Hub."""
import json
import time
import uuid
from datetime import datetime
from enum import Enum


class FindingType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    FULL_NAME = "full_name"
    SOCIAL_PROFILE = "social_profile"
    BREACH = "breach"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    PHOTO_URL = "photo_url"
    LOCATION = "location"
    BIO = "bio"
    ORGANIZATION = "organization"
    REGISTERED_SITE = "registered_site"
    RELATED_EMAIL = "related_email"
    RELATED_USERNAME = "related_username"
    RELATED_PHONE = "related_phone"
    RAW = "raw"


class ToolStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Finding:
    """A single piece of discovered information."""

    def __init__(self, finding_type, value, source_tool, confidence=1.0, metadata=None):
        self.id = str(uuid.uuid4())[:8]
        self.type = finding_type
        self.value = value
        self.source_tool = source_tool
        self.confidence = confidence
        self.metadata = metadata or {}
        self.timestamp = datetime.now().isoformat()
        self.linked_to = []  # IDs of related findings

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "source_tool": self.source_tool,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "linked_to": self.linked_to,
        }


class ToolRun:
    """Tracks the execution of a single tool."""

    def __init__(self, tool_name, input_type, input_value):
        self.id = str(uuid.uuid4())[:8]
        self.tool_name = tool_name
        self.input_type = input_type
        self.input_value = input_value
        self.status = ToolStatus.PENDING
        self.started_at = None
        self.finished_at = None
        self.findings = []
        self.error = None
        self.raw_output = ""

    def start(self):
        self.status = ToolStatus.RUNNING
        self.started_at = datetime.now().isoformat()

    def complete(self, findings):
        self.status = ToolStatus.COMPLETED
        self.finished_at = datetime.now().isoformat()
        self.findings = findings

    def fail(self, error):
        self.status = ToolStatus.FAILED
        self.finished_at = datetime.now().isoformat()
        self.error = str(error)

    def to_dict(self):
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "input_type": self.input_type,
            "input_value": self.input_value,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


class TargetProfile:
    """The unified profile of the investigation target."""

    def __init__(self):
        self.id = str(uuid.uuid4())[:8]
        self.created_at = datetime.now().isoformat()
        self.seeds = {}  # initial user-provided data
        self.findings = []  # all Finding objects
        self.tool_runs = []  # all ToolRun objects
        self.discovery_queue = []  # new leads to investigate
        self.investigated = set()  # (type, value) pairs already checked
        self.chain_depth = 0

    def add_seeds(self, seeds_dict):
        """Add user-provided seed data."""
        self.seeds = seeds_dict
        for seed_type, values in seeds_dict.items():
            if not values:
                continue
            if isinstance(values, str):
                values = [v.strip() for v in values.split(",") if v.strip()]
            for val in values:
                self.investigated.add((seed_type, val))

    def add_finding(self, finding):
        """Add a finding and check if it's a new lead."""
        # Deduplicate
        for existing in self.findings:
            if existing.type == finding.type and existing.value == finding.value:
                if finding.confidence > existing.confidence:
                    existing.confidence = finding.confidence
                    existing.metadata.update(finding.metadata)
                return existing
        self.findings.append(finding)

        # Check if this finding reveals new leads to investigate
        discoverable_types = {
            FindingType.RELATED_EMAIL: "email",
            FindingType.RELATED_USERNAME: "username",
            FindingType.RELATED_PHONE: "phone",
            FindingType.USERNAME: "username",
        }
        if finding.type in discoverable_types:
            seed_type = discoverable_types[finding.type]
            key = (seed_type, finding.value)
            if key not in self.investigated:
                self.discovery_queue.append(key)
        return finding

    def add_tool_run(self, tool_run):
        self.tool_runs.append(tool_run)

    def get_new_leads(self):
        """Get uninvestigated leads from the discovery queue."""
        leads = []
        for lead in self.discovery_queue:
            if lead not in self.investigated:
                leads.append(lead)
                self.investigated.add(lead)
        self.discovery_queue.clear()
        return leads

    def get_findings_by_type(self, finding_type):
        return [f for f in self.findings if f.type == finding_type]

    def get_summary(self):
        """Generate a summary of all findings."""
        summary = {
            "id": self.id,
            "created_at": self.created_at,
            "seeds": self.seeds,
            "total_findings": len(self.findings),
            "total_tool_runs": len(self.tool_runs),
            "findings_by_type": {},
            "tool_runs": [tr.to_dict() for tr in self.tool_runs],
        }
        for f in self.findings:
            ft = f.type
            if ft not in summary["findings_by_type"]:
                summary["findings_by_type"][ft] = []
            summary["findings_by_type"][ft].append(f.to_dict())
        return summary

    def to_dict(self):
        return self.get_summary()

    def save(self, filepath):
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
