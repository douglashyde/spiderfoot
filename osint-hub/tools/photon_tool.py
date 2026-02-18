"""Photon - fast web crawler that extracts URLs, emails, social accounts, files."""
import os
import re
import json
import tempfile
from .base import ToolWrapper, Finding, FindingType


class PhotonTool(ToolWrapper):
    name = "photon"
    description = "Web crawler - extract emails, social profiles, files from domains"
    accepts_input = ["domain"]
    category = "domain_osint"

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        domain = input_value.strip()

        if not domain.startswith("http"):
            url = f"https://{domain}"
        else:
            url = domain

        out_dir = tempfile.mkdtemp(prefix="photon_")

        cmd = [
            "python", os.path.join(self.tool_path, "photon.py"),
            "-u", url,
            "-l", "2",       # depth 2
            "-t", "10",      # 10 threads
            "-o", out_dir,
            "--dns",
            "--keys",
        ]
        raw = self._run_command(cmd, timeout=120)
        tool_run.raw_output = raw

        # Parse Photon output files
        for fname in ("intel.txt", "external.txt", "fuzzable.txt",
                       "scripts.txt", "files.txt", "robots.txt"):
            fpath = os.path.join(out_dir, domain, fname)
            if not os.path.exists(fpath):
                fpath = os.path.join(out_dir, fname)
            if not os.path.exists(fpath):
                continue

            try:
                with open(fpath) as f:
                    content = f.read()
            except Exception:
                continue

            # Extract emails
            emails = re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                content,
            )
            for email in set(emails):
                findings.append(Finding(
                    FindingType.RELATED_EMAIL,
                    email.lower(),
                    source_tool=self.name,
                    confidence=0.75,
                    metadata={"domain": domain, "source_file": fname},
                ))

            # Extract social media URLs
            social_patterns = [
                r"https?://(?:www\.)?(?:twitter|x)\.com/[^\s\"'<>]+",
                r"https?://(?:www\.)?instagram\.com/[^\s\"'<>]+",
                r"https?://(?:www\.)?facebook\.com/[^\s\"'<>]+",
                r"https?://(?:www\.)?linkedin\.com/(?:in|company)/[^\s\"'<>]+",
                r"https?://(?:www\.)?github\.com/[^\s\"'<>]+",
                r"https?://(?:www\.)?youtube\.com/[^\s\"'<>]+",
                r"https?://(?:www\.)?tiktok\.com/@[^\s\"'<>]+",
                r"https?://(?:www\.)?reddit\.com/u(?:ser)?/[^\s\"'<>]+",
                r"https?://(?:www\.)?t\.me/[^\s\"'<>]+",
            ]
            for pattern in social_patterns:
                urls = re.findall(pattern, content, re.IGNORECASE)
                for url_found in set(urls):
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        url_found.rstrip("/"),
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"domain": domain},
                    ))

            # Extract subdomains
            subdomain_pattern = re.compile(
                r"(?:[a-zA-Z0-9-]+\.)+" + re.escape(domain)
            )
            subdomains = subdomain_pattern.findall(content)
            for sub in set(subdomains):
                if sub != domain:
                    findings.append(Finding(
                        FindingType.SUBDOMAIN,
                        sub,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"parent_domain": domain},
                    ))

            # Extract document/file URLs
            doc_patterns = re.findall(
                r"https?://[^\s\"'<>]+\.(?:pdf|doc|docx|xls|xlsx|csv|txt|conf|bak|sql|xml|json)",
                content,
                re.IGNORECASE,
            )
            for doc_url in set(doc_patterns):
                findings.append(Finding(
                    FindingType.DOCUMENT_URL,
                    doc_url,
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={"domain": domain, "type": "document"},
                ))

            # Extract IP addresses
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
            for ip in set(ips):
                if not ip.startswith("0.") and not ip.startswith("255."):
                    findings.append(Finding(
                        FindingType.IP_ADDRESS,
                        ip,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"domain": domain},
                    ))

            # Extract phone numbers
            phones = re.findall(r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}", content)
            for phone in set(phones):
                cleaned = re.sub(r"[\s\-\.\(\)]", "", phone)
                if 10 <= len(cleaned) <= 15:
                    findings.append(Finding(
                        FindingType.RELATED_PHONE,
                        cleaned,
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={"domain": domain},
                    ))

        # Parse raw stdout too for any missed intel
        emails_raw = re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", raw
        )
        existing_emails = {f.value for f in findings if f.type == FindingType.RELATED_EMAIL}
        for email in set(emails_raw):
            if email.lower() not in existing_emails:
                findings.append(Finding(
                    FindingType.RELATED_EMAIL,
                    email.lower(),
                    source_tool=self.name,
                    confidence=0.65,
                    metadata={"domain": domain, "source": "stdout"},
                ))

        return findings
