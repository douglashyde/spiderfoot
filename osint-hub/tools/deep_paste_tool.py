"""Deep Paste Search - comprehensive paste site and code snippet search."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class DeepPasteTool(ToolWrapper):
    name = "deep_paste"
    description = "Deep search across paste sites, GitHub Gists, code snippets, and data dumps for leaked data"
    accepts_input = ["email", "username", "domain", "phone"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # Method 1: GitHub Gist search (free, no auth for search)
        self._search_github_gists(input_value, headers, findings, tool_run)

        # Method 2: grep.app (searches all of GitHub)
        self._search_grep_app(input_value, headers, findings, tool_run)

        # Method 3: SearchCode.com (searches code snippets)
        self._search_searchcode(input_value, headers, findings, tool_run)

        # Method 4: IntelX paste search (free tier)
        self._search_intelx_pastes(input_value, headers, findings, tool_run)

        # Method 5: Paste search via web search
        self._search_pastes_via_web(input_value, input_type, headers, findings, tool_run)

        # Method 6: Redhunt Labs (Open Threat Intelligence)
        self._search_redhuntlabs(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_github_gists(self, query, headers, findings, tool_run):
        """Search GitHub Gists for mentions."""
        try:
            url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}+in:file&per_page=30"
            gh_headers = {
                **headers,
                "Accept": "application/vnd.github.v3.text-match+json",
            }
            resp = requests.get(url, headers=gh_headers, timeout=15)
            tool_run.raw_output += f"GitHub Gist Search: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for item in items[:20]:
                    repo_name = item.get("repository", {}).get("full_name", "")
                    file_name = item.get("name", "")
                    html_url = item.get("html_url", "")
                    text_matches = item.get("text_matches", [])

                    snippet = ""
                    for tm in text_matches:
                        snippet += tm.get("fragment", "") + "\n"

                    findings.append(Finding(
                        FindingType.CODE_REPOSITORY,
                        html_url,
                        source_tool=self.name,
                        confidence=0.75,
                        metadata={
                            "repo": repo_name,
                            "file": file_name,
                            "snippet": snippet[:500],
                            "target": query,
                            "source": "github_code_search",
                        },
                    ))

                    # Extract emails from snippets
                    for email in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", snippet):
                        if email.lower() != query.lower():
                            findings.append(Finding(
                                FindingType.RELATED_EMAIL,
                                email.lower(),
                                source_tool=self.name,
                                confidence=0.5,
                                metadata={"found_in": html_url},
                            ))

        except Exception as e:
            tool_run.raw_output += f"GitHub Gist error: {e}\n"

    def _search_grep_app(self, query, headers, findings, tool_run):
        """Search grep.app (GitHub code search engine)."""
        try:
            url = f"https://grep.app/api/search?q={urllib.parse.quote(query)}&page=1"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"grep.app: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", {}).get("hits", [])
                for hit in hits[:15]:
                    repo = hit.get("repo", {}).get("raw", "")
                    path = hit.get("path", {}).get("raw", "")
                    snippet_lines = hit.get("content", {}).get("snippet", {}).get("highlights", [])
                    snippet = "\n".join(snippet_lines) if snippet_lines else ""

                    gh_url = f"https://github.com/{repo}/blob/master/{path}" if repo else ""

                    findings.append(Finding(
                        FindingType.CODE_REPOSITORY,
                        gh_url,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={
                            "repo": repo,
                            "file_path": path,
                            "snippet": snippet[:500],
                            "target": query,
                            "source": "grep.app",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"grep.app error: {e}\n"

    def _search_searchcode(self, query, headers, findings, tool_run):
        """Search searchcode.com for code snippets."""
        try:
            url = f"https://searchcode.com/api/codesearch_I/?q={urllib.parse.quote(query)}&per_page=20"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"SearchCode: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                for result in results[:15]:
                    repo = result.get("repo", "")
                    filename = result.get("filename", "")
                    url_link = result.get("url", "")
                    lines = result.get("lines", {})
                    snippet = "\n".join(str(v) for v in list(lines.values())[:5])

                    findings.append(Finding(
                        FindingType.CODE_REPOSITORY,
                        url_link,
                        source_tool=self.name,
                        confidence=0.65,
                        metadata={
                            "repo": repo,
                            "file": filename,
                            "snippet": snippet[:500],
                            "target": query,
                            "source": "searchcode",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"SearchCode error: {e}\n"

    def _search_intelx_pastes(self, query, headers, findings, tool_run):
        """Search IntelligenceX for pastes and leaks."""
        try:
            url = "https://2.intelx.io/intelligent/search"
            payload = {
                "term": query,
                "buckets": ["pastes", "leaks", "darknet"],
                "maxresults": 30,
                "timeout": 10,
            }
            params = {"k": "9df61df0-84f7-4dc7-b34c-8ccfb8646571"}  # free API key
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
                        tool_run.raw_output += f"IntelX deep: {len(records)} results\n"

                        for record in records[:30]:
                            name = record.get("name", "")
                            media = record.get("mediah", "")
                            date = record.get("date", "")
                            bucket = record.get("bucket", "")
                            system_id = record.get("systemid", "")
                            storage_id = record.get("storageid", "")

                            finding_type = FindingType.PASTE
                            if bucket == "darknet":
                                finding_type = FindingType.DARK_WEB_MENTION
                            elif bucket == "leaks":
                                finding_type = FindingType.LEAKED_CREDENTIAL

                            findings.append(Finding(
                                finding_type,
                                name or str(system_id),
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "searched_for": query,
                                    "source": "intelx",
                                    "bucket": bucket,
                                    "media_type": media,
                                    "date": date,
                                    "storage_id": storage_id,
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"IntelX deep paste error: {e}\n"

    def _search_pastes_via_web(self, query, input_type, headers, findings, tool_run):
        """Search paste sites via DuckDuckGo."""
        try:
            paste_sites = "site:pastebin.com OR site:paste.ee OR site:dpaste.org OR site:ideone.com OR site:rentry.co OR site:hastebin.com OR site:gist.github.com"
            encoded = urllib.parse.quote_plus(f'"{query}" ({paste_sites})')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = re.findall(r'href="(https?://[^"]+)"', resp.text)
                paste_urls = set()
                for link in links:
                    if "uddg=" in link:
                        actual = re.search(r"uddg=([^&]+)", link)
                        if actual:
                            link = urllib.parse.unquote(actual.group(1))
                    paste_domains = ["pastebin.com", "paste.ee", "dpaste.org", "ideone.com",
                                     "rentry.co", "hastebin.com", "gist.github.com"]
                    if any(d in link.lower() for d in paste_domains):
                        paste_urls.add(link)

                tool_run.raw_output += f"Paste web search: {len(paste_urls)} paste links found\n"
                for paste_url in list(paste_urls)[:15]:
                    findings.append(Finding(
                        FindingType.PASTE,
                        paste_url,
                        source_tool=self.name,
                        confidence=0.65,
                        metadata={
                            "target": query,
                            "source": "web_search",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"Paste web search error: {e}\n"

    def _search_redhuntlabs(self, query, headers, findings, tool_run):
        """Search Redhunt Labs Open Threat Intelligence."""
        try:
            url = f"https://reconapi.redhuntlabs.com/community/v1/search?query={urllib.parse.quote(query)}"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"RedhuntLabs: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", data.get("data", []))
                if isinstance(results, list):
                    for item in results[:10]:
                        findings.append(Finding(
                            FindingType.WEB_MENTION,
                            str(item.get("url", item.get("value", str(item)))),
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "target": query,
                                "source": "redhuntlabs",
                                "raw": str(item)[:500],
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"RedhuntLabs error: {e}\n"
