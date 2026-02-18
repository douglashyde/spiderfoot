"""Wayback Machine - historical web snapshot search and analysis."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


# Social media profile URL patterns for constructing archive lookups
PROFILE_URL_TEMPLATES = {
    "twitter": "https://twitter.com/{u}",
    "x": "https://x.com/{u}",
    "instagram": "https://instagram.com/{u}",
    "facebook": "https://facebook.com/{u}",
    "github": "https://github.com/{u}",
    "linkedin": "https://linkedin.com/in/{u}",
    "reddit": "https://reddit.com/user/{u}",
    "tiktok": "https://tiktok.com/@{u}",
    "medium": "https://medium.com/@{u}",
    "tumblr": "https://{u}.tumblr.com",
    "pinterest": "https://pinterest.com/{u}",
    "keybase": "https://keybase.io/{u}",
    "aboutme": "https://about.me/{u}",
    "devto": "https://dev.to/{u}",
    "hackerone": "https://hackerone.com/{u}",
}


class WaybackTool(ToolWrapper):
    name = "wayback"
    description = "Wayback Machine - find archived/deleted pages, historical profiles, and old web content"
    accepts_input = ["username", "email", "domain", "full_name"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        if input_type == "username":
            # Search archived social profiles
            self._search_archived_profiles(input_value, headers, findings, tool_run)

        if input_type == "domain":
            # Search archived pages for the domain
            self._search_domain_archives(input_value, headers, findings, tool_run)

        if input_type == "email":
            # Search web archive for email mentions
            local_part = input_value.split("@")[0] if "@" in input_value else input_value
            self._search_archived_profiles(local_part, headers, findings, tool_run)

        # Use Wayback Machine CDX API for all types
        self._search_cdx_api(input_value, input_type, headers, findings, tool_run)

        # Use web.archive.org full-text search
        self._search_archive_fulltext(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_archived_profiles(self, username, headers, findings, tool_run):
        """Search Wayback Machine for archived social media profiles."""
        for platform, url_template in PROFILE_URL_TEMPLATES.items():
            try:
                profile_url = url_template.format(u=username)
                # Use Wayback Availability API
                api_url = f"https://archive.org/wayback/available?url={urllib.parse.quote(profile_url)}"
                resp = requests.get(api_url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    closest = data.get("archived_snapshots", {}).get("closest", {})
                    if closest and closest.get("available"):
                        archive_url = closest.get("url", "")
                        timestamp = closest.get("timestamp", "")
                        status = closest.get("status", "")

                        if status == "200":
                            findings.append(Finding(
                                FindingType.ARCHIVED_PAGE,
                                archive_url,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "original_url": profile_url,
                                    "platform": platform,
                                    "username": username,
                                    "timestamp": timestamp,
                                    "status": status,
                                },
                            ))

                            # Also add as social profile (the original URL was live at some point)
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                profile_url,
                                source_tool=self.name,
                                confidence=0.6,
                                metadata={
                                    "found_via": "wayback_machine",
                                    "archived_url": archive_url,
                                    "timestamp": timestamp,
                                    "may_be_deleted": True,
                                },
                            ))

                time.sleep(0.3)  # Rate limit

            except Exception as e:
                tool_run.raw_output += f"Wayback {platform} error: {e}\n"

    def _search_domain_archives(self, domain, headers, findings, tool_run):
        """Search CDX API for all archived URLs under a domain."""
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=timestamp,original,statuscode,mimetype&limit=100&collapse=urlkey"
            resp = requests.get(url, headers=headers, timeout=30)
            tool_run.raw_output += f"Wayback CDX domain: {resp.status_code}\n"

            if resp.status_code == 200:
                try:
                    rows = resp.json()
                    if rows and len(rows) > 1:
                        header = rows[0]
                        for row in rows[1:50]:  # Cap at 50
                            data_dict = dict(zip(header, row))
                            timestamp = data_dict.get("timestamp", "")
                            original = data_dict.get("original", "")
                            status = data_dict.get("statuscode", "")
                            mime = data_dict.get("mimetype", "")

                            archive_url = f"https://web.archive.org/web/{timestamp}/{original}"

                            findings.append(Finding(
                                FindingType.ARCHIVED_PAGE,
                                archive_url,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "original_url": original,
                                    "timestamp": timestamp,
                                    "status_code": status,
                                    "mime_type": mime,
                                    "domain": domain,
                                },
                            ))

                            # Extract subdomains
                            if original:
                                domain_match = re.search(r"https?://([^/]+)", original)
                                if domain_match:
                                    full_domain = domain_match.group(1).lower()
                                    if full_domain != domain and domain in full_domain:
                                        findings.append(Finding(
                                            FindingType.SUBDOMAIN,
                                            full_domain,
                                            source_tool=self.name,
                                            confidence=0.75,
                                            metadata={
                                                "found_via": "wayback_cdx",
                                                "parent_domain": domain,
                                            },
                                        ))

                except json.JSONDecodeError:
                    tool_run.raw_output += "CDX response not JSON\n"

        except Exception as e:
            tool_run.raw_output += f"Wayback CDX domain error: {e}\n"

    def _search_cdx_api(self, query, input_type, headers, findings, tool_run):
        """Use CDX API to find archived pages mentioning the target."""
        try:
            # For emails/usernames, search for pages that might contain them
            if input_type in ("email", "username"):
                url = f"https://web.archive.org/cdx/search/cdx?url=*{urllib.parse.quote(query)}*&output=json&fl=timestamp,original,statuscode&limit=30&collapse=urlkey"
            elif input_type == "domain":
                url = f"https://web.archive.org/cdx/search/cdx?url={query}/*&output=json&fl=timestamp,original,statuscode&limit=50&collapse=urlkey"
            else:
                return

            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                try:
                    rows = resp.json()
                    if rows and len(rows) > 1:
                        header = rows[0]
                        tool_run.raw_output += f"CDX wildcard: {len(rows)-1} results\n"
                        for row in rows[1:30]:
                            data_dict = dict(zip(header, row))
                            original = data_dict.get("original", "")
                            timestamp = data_dict.get("timestamp", "")
                            archive_url = f"https://web.archive.org/web/{timestamp}/{original}"

                            findings.append(Finding(
                                FindingType.ARCHIVED_PAGE,
                                archive_url,
                                source_tool=self.name,
                                confidence=0.65,
                                metadata={
                                    "original_url": original,
                                    "timestamp": timestamp,
                                    "target": query,
                                },
                            ))
                except json.JSONDecodeError:
                    pass

        except Exception as e:
            tool_run.raw_output += f"CDX wildcard error: {e}\n"

    def _search_archive_fulltext(self, query, headers, findings, tool_run):
        """Search archive.org full-text search."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://archive.org/advancedsearch.php?q={encoded}&fl[]=identifier,title,description,date&rows=20&output=json"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                tool_run.raw_output += f"Archive.org full-text: {len(docs)} results\n"

                for doc in docs[:15]:
                    identifier = doc.get("identifier", "")
                    title = doc.get("title", "")
                    description = doc.get("description", "")
                    date = doc.get("date", "")

                    archive_url = f"https://archive.org/details/{identifier}" if identifier else ""
                    if archive_url:
                        findings.append(Finding(
                            FindingType.ARCHIVED_PAGE,
                            archive_url,
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "title": title[:200] if isinstance(title, str) else str(title)[:200],
                                "description": str(description)[:500],
                                "date": date,
                                "target": query,
                                "source": "archive.org_search",
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Archive.org search error: {e}\n"
