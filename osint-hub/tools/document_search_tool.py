"""Document Search - find exposed documents, files, and data dumps."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class DocumentSearchTool(ToolWrapper):
    name = "document_search"
    description = "Find exposed documents (PDFs, spreadsheets, presentations, databases) and sensitive files across the web"
    accepts_input = ["email", "username", "domain", "full_name"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # File type dorks
        file_types = ["pdf", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx", "txt", "rtf"]

        # Sensitive file types (for domain searches)
        sensitive_types = ["sql", "bak", "log", "env", "cfg", "conf", "xml", "json", "yml", "yaml"]

        if input_type == "domain":
            # Domain-specific document search
            self._search_domain_documents(input_value, file_types, headers, findings, tool_run)
            self._search_domain_sensitive(input_value, sensitive_types, headers, findings, tool_run)
            self._search_domain_directory_listings(input_value, headers, findings, tool_run)
        else:
            # General document search for person/email
            self._search_person_documents(input_value, file_types, headers, findings, tool_run)

        # Search Scribd
        self._search_scribd(input_value, headers, findings, tool_run)

        # Search SlideShare
        self._search_slideshare(input_value, headers, findings, tool_run)

        # Search archive.org for documents
        self._search_archive_documents(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_domain_documents(self, domain, file_types, headers, findings, tool_run):
        """Search for exposed documents on a domain."""
        for ftype in file_types:
            try:
                encoded = urllib.parse.quote_plus(f"site:{domain} filetype:{ftype}")
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    links = self._extract_ddg_links(resp.text)
                    for link in links[:10]:
                        findings.append(Finding(
                            FindingType.DOCUMENT_URL,
                            link,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={
                                "file_type": ftype,
                                "domain": domain,
                                "source": "domain_file_dork",
                            },
                        ))

                time.sleep(1)

            except Exception as e:
                tool_run.raw_output += f"Doc dork {ftype} error: {e}\n"

    def _search_domain_sensitive(self, domain, sensitive_types, headers, findings, tool_run):
        """Search for sensitive files on a domain."""
        for ftype in sensitive_types:
            try:
                encoded = urllib.parse.quote_plus(f"site:{domain} filetype:{ftype}")
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    links = self._extract_ddg_links(resp.text)
                    for link in links[:5]:
                        findings.append(Finding(
                            FindingType.DOCUMENT_URL,
                            link,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "file_type": ftype,
                                "domain": domain,
                                "sensitive": True,
                                "source": "sensitive_file_dork",
                            },
                        ))

                time.sleep(1)

            except Exception as e:
                tool_run.raw_output += f"Sensitive dork {ftype} error: {e}\n"

    def _search_domain_directory_listings(self, domain, headers, findings, tool_run):
        """Search for open directory listings on a domain."""
        dorks = [
            f'site:{domain} intitle:"index of" OR intitle:"directory listing"',
            f'site:{domain} intitle:"index of" "parent directory"',
            f'site:{domain} inurl:"/uploads/" OR inurl:"/files/" OR inurl:"/documents/"',
        ]

        for dork in dorks:
            try:
                encoded = urllib.parse.quote_plus(dork)
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    links = self._extract_ddg_links(resp.text)
                    for link in links[:5]:
                        findings.append(Finding(
                            FindingType.DOCUMENT_URL,
                            link,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "type": "directory_listing",
                                "domain": domain,
                                "dork": dork,
                            },
                        ))

                time.sleep(1)

            except Exception as e:
                tool_run.raw_output += f"Dir listing dork error: {e}\n"

    def _search_person_documents(self, query, file_types, headers, findings, tool_run):
        """Search for documents mentioning a person/email."""
        # Search common doc types in batches
        type_groups = [
            "filetype:pdf OR filetype:doc OR filetype:docx",
            "filetype:xls OR filetype:xlsx OR filetype:csv",
            "filetype:ppt OR filetype:pptx OR filetype:txt",
        ]

        for type_group in type_groups:
            try:
                encoded = urllib.parse.quote_plus(f'"{query}" {type_group}')
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    links = self._extract_ddg_links(resp.text)
                    for link in links[:10]:
                        # Determine file type from URL
                        ftype = "unknown"
                        for ft in file_types:
                            if f".{ft}" in link.lower():
                                ftype = ft
                                break

                        findings.append(Finding(
                            FindingType.DOCUMENT_URL,
                            link,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "file_type": ftype,
                                "target": query,
                                "source": "person_doc_search",
                            },
                        ))

                time.sleep(1.5)

            except Exception as e:
                tool_run.raw_output += f"Person doc search error: {e}\n"

    def _search_scribd(self, query, headers, findings, tool_run):
        """Search Scribd for documents."""
        try:
            encoded = urllib.parse.quote_plus(f'site:scribd.com "{query}"')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                scribd_links = [l for l in links if "scribd.com" in l.lower()]
                for link in scribd_links[:10]:
                    findings.append(Finding(
                        FindingType.DOCUMENT_URL,
                        link,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "source": "scribd",
                            "target": query,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"Scribd error: {e}\n"

    def _search_slideshare(self, query, headers, findings, tool_run):
        """Search SlideShare for presentations."""
        try:
            encoded = urllib.parse.quote_plus(f'site:slideshare.net "{query}"')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                ss_links = [l for l in links if "slideshare.net" in l.lower()]
                for link in ss_links[:10]:
                    findings.append(Finding(
                        FindingType.DOCUMENT_URL,
                        link,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "source": "slideshare",
                            "target": query,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"SlideShare error: {e}\n"

    def _search_archive_documents(self, query, headers, findings, tool_run):
        """Search archive.org for documents."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://archive.org/advancedsearch.php?q={encoded}+mediatype:texts&fl[]=identifier,title,format,date&rows=15&output=json"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                for doc in docs[:10]:
                    identifier = doc.get("identifier", "")
                    title = doc.get("title", "")
                    date = doc.get("date", "")

                    if identifier:
                        findings.append(Finding(
                            FindingType.DOCUMENT_URL,
                            f"https://archive.org/details/{identifier}",
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "title": str(title)[:200],
                                "date": date,
                                "source": "archive.org",
                                "target": query,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Archive.org doc error: {e}\n"

    def _extract_ddg_links(self, html):
        """Extract actual URLs from DuckDuckGo HTML results."""
        links = []
        for match in re.finditer(r'uddg=([^&"]+)', html):
            url = urllib.parse.unquote(match.group(1))
            if url.startswith("http") and "duckduckgo.com" not in url:
                links.append(url)
        return links
