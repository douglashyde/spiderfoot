"""Dark Web Search - search .onion indexes via clearnet gateways."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class DarkWebSearchTool(ToolWrapper):
    name = "darkweb_search"
    description = "Search dark web via Ahmia.fi, IntelX darknet bucket, and onion search indexes"
    accepts_input = ["email", "username", "domain", "phone", "full_name"]
    category = "dark_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
        }

        # Method 1: Ahmia.fi - Legal clearnet search engine for .onion sites
        self._search_ahmia(input_value, headers, findings, tool_run)

        # Method 2: IntelX darknet bucket
        self._search_intelx_darknet(input_value, headers, findings, tool_run)

        # Method 3: Tor66 search (clearnet mirror)
        self._search_tor66(input_value, headers, findings, tool_run)

        # Method 4: Onion search via DarkSearch.io
        self._search_darksearch(input_value, headers, findings, tool_run)

        # Method 5: Hunchly Dark Web report (public data)
        self._search_hunchly(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_ahmia(self, query, headers, findings, tool_run):
        """Search Ahmia.fi - the most reliable legal dark web search engine."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://ahmia.fi/search/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=20)
            tool_run.raw_output += f"Ahmia: {resp.status_code}\n"

            if resp.status_code == 200:
                # Parse search results from HTML
                # Ahmia returns .onion links with descriptions
                result_pattern = re.compile(
                    r'<li class="result">\s*<h4>\s*<a href="(/search/redirect\?[^"]*)"[^>]*>(.*?)</a>\s*</h4>\s*'
                    r'(?:<p class="[^"]*">(.*?)</p>)?',
                    re.DOTALL,
                )
                results = result_pattern.findall(resp.text)

                # Fallback: simpler pattern
                if not results:
                    # Try extracting onion links directly
                    onion_pattern = re.compile(
                        r'href="[^"]*"[^>]*>.*?(https?://[a-z2-7]{16,56}\.onion[^<]*)<',
                        re.DOTALL | re.IGNORECASE,
                    )
                    onion_results = onion_pattern.findall(resp.text)

                    # Also try redirect URLs
                    redirect_pattern = re.compile(
                        r'<a href="(/search/redirect\?search_term=[^"]+redirect_url=([^"&]+))"[^>]*>(.*?)</a>',
                        re.DOTALL,
                    )
                    redirect_results = redirect_pattern.findall(resp.text)

                    for _, onion_url, title in redirect_results[:20]:
                        onion_url = urllib.parse.unquote(onion_url)
                        title = re.sub(r"<[^>]+>", "", title).strip()
                        findings.append(Finding(
                            FindingType.DARK_WEB_MENTION,
                            onion_url,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "title": title[:200],
                                "source": "ahmia.fi",
                                "target": query,
                            },
                        ))

                    for onion_url in onion_results[:10]:
                        findings.append(Finding(
                            FindingType.DARK_WEB_MENTION,
                            onion_url.strip(),
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "source": "ahmia.fi",
                                "target": query,
                            },
                        ))
                else:
                    for redirect_url, title, description in results[:20]:
                        title = re.sub(r"<[^>]+>", "", title).strip()
                        description = re.sub(r"<[^>]+>", "", description).strip() if description else ""

                        # Extract actual onion URL from redirect
                        onion_match = re.search(r"redirect_url=([^&]+)", redirect_url)
                        onion_url = urllib.parse.unquote(onion_match.group(1)) if onion_match else redirect_url

                        findings.append(Finding(
                            FindingType.DARK_WEB_MENTION,
                            onion_url,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "title": title[:200],
                                "description": description[:500],
                                "source": "ahmia.fi",
                                "target": query,
                            },
                        ))

                tool_run.raw_output += f"Ahmia results: {len(findings)} dark web mentions\n"

        except Exception as e:
            tool_run.raw_output += f"Ahmia error: {e}\n"

    def _search_intelx_darknet(self, query, headers, findings, tool_run):
        """Search IntelligenceX darknet bucket."""
        try:
            url = "https://2.intelx.io/intelligent/search"
            payload = {
                "term": query,
                "buckets": ["darknet"],
                "maxresults": 25,
                "timeout": 10,
            }
            params = {"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571"}
            resp = requests.post(url, json=payload, params=params, headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
            }, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get("id")
                if search_id:
                    time.sleep(3)
                    result_resp = requests.get(
                        "https://2.intelx.io/intelligent/search/result",
                        params={"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571", "id": search_id},
                        timeout=15,
                    )
                    if result_resp.status_code == 200:
                        results = result_resp.json()
                        records = results.get("records", [])
                        tool_run.raw_output += f"IntelX darknet: {len(records)} results\n"

                        for record in records[:25]:
                            name = record.get("name", "")
                            media = record.get("mediah", "")
                            date = record.get("date", "")

                            findings.append(Finding(
                                FindingType.DARK_WEB_MENTION,
                                name or str(record.get("systemid", "")),
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "searched_for": query,
                                    "source": "intelx_darknet",
                                    "media_type": media,
                                    "date": date,
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"IntelX darknet error: {e}\n"

    def _search_tor66(self, query, headers, findings, tool_run):
        """Search Tor66 onion search engine (clearnet mirror)."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://tor66.me/search?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"Tor66: {resp.status_code}\n"

            if resp.status_code == 200:
                onion_links = re.findall(r"(https?://[a-z2-7]{16,56}\.onion[^\s\"<]*)", resp.text, re.IGNORECASE)
                for link in set(onion_links[:15]):
                    findings.append(Finding(
                        FindingType.DARK_WEB_MENTION,
                        link,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "source": "tor66",
                            "target": query,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"Tor66 error: {e}\n"

    def _search_darksearch(self, query, headers, findings, tool_run):
        """Search DarkSearch.io API."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://darksearch.io/api/search?query={encoded}&page=1"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"DarkSearch: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", [])
                for result in results[:15]:
                    title = result.get("title", "")
                    link = result.get("link", "")
                    description = result.get("description", "")

                    if link:
                        findings.append(Finding(
                            FindingType.DARK_WEB_MENTION,
                            link,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "title": title[:200],
                                "description": description[:500],
                                "source": "darksearch.io",
                                "target": query,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"DarkSearch error: {e}\n"

    def _search_hunchly(self, query, headers, findings, tool_run):
        """Search Hunchly Dark Web report (public dataset)."""
        try:
            # Hunchly publishes daily dark web reports
            url = f"https://api.hunch.ly/darkweb-osint/search?q={urllib.parse.quote(query)}"
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("results", [])[:10]:
                    findings.append(Finding(
                        FindingType.DARK_WEB_MENTION,
                        item.get("url", str(item)),
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "source": "hunchly",
                            "target": query,
                            "title": item.get("title", ""),
                        },
                    ))
        except Exception as e:
            tool_run.raw_output += f"Hunchly error: {e}\n"
