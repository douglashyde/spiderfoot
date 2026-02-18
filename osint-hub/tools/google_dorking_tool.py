"""Google Dorking Engine - automated search dorks for deep OSINT."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


# Dork templates per input type
EMAIL_DORKS = [
    '"{email}"',
    '"{email}" password OR passwd OR credentials',
    '"{email}" site:pastebin.com OR site:ghostbin.co OR site:paste.ee',
    '"{email}" filetype:sql OR filetype:csv OR filetype:log',
    '"{email}" site:github.com OR site:gitlab.com',
    '"{email}" site:scribd.com OR site:slideshare.net',
    '"{email}" site:trello.com OR site:notion.so',
    '"{email}" "leak" OR "dump" OR "breach" OR "database"',
    '"{email}" site:reddit.com OR site:stackoverflow.com',
    '"{email}" site:t.me OR site:telegram.me',
]

USERNAME_DORKS = [
    '"{username}"',
    '"{username}" site:pastebin.com OR site:paste.ee',
    '"{username}" site:github.com OR site:gitlab.com',
    '"{username}" site:reddit.com',
    '"{username}" site:medium.com OR site:dev.to',
    '"{username}" site:keybase.io OR site:pgp.mit.edu',
    '"{username}" "password" OR "credentials" OR "leak"',
    '"{username}" site:t.me OR site:discord.gg',
    '"{username}" site:flickr.com OR site:behance.net OR site:dribbble.com',
    '"{username}" site:youtube.com OR site:twitch.tv',
]

DOMAIN_DORKS = [
    'site:{domain}',
    'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls',
    'site:{domain} filetype:sql OR filetype:bak OR filetype:log',
    'site:{domain} filetype:env OR filetype:cfg OR filetype:conf',
    'site:{domain} inurl:admin OR inurl:login OR inurl:panel',
    'site:{domain} intitle:"index of" OR intitle:"directory listing"',
    'site:{domain} "password" OR "secret" OR "api_key" OR "token"',
    '"{domain}" site:pastebin.com OR site:paste.ee',
    '"{domain}" site:github.com "password" OR "secret" OR "key"',
    '"{domain}" "leak" OR "breach" OR "dump" OR "database"',
]

FULLNAME_DORKS = [
    '"{full_name}"',
    '"{full_name}" site:linkedin.com',
    '"{full_name}" site:facebook.com',
    '"{full_name}" site:twitter.com OR site:x.com',
    '"{full_name}" resume OR cv filetype:pdf',
    '"{full_name}" site:whitepages.com OR site:spokeo.com OR site:pipl.com',
    '"{full_name}" email OR contact OR phone',
    '"{full_name}" site:reddit.com OR site:medium.com',
]

PHONE_DORKS = [
    '"{phone}"',
    '"{phone}" site:truecaller.com OR site:whoscall.com',
    '"{phone}" site:facebook.com OR site:linkedin.com',
    '"{phone}" "leak" OR "dump" OR "database"',
    '"{phone}" site:pastebin.com',
]


class GoogleDorkingTool(ToolWrapper):
    name = "google_dorking"
    description = "Automated Google/DuckDuckGo dorking engine - finds exposed data, documents, credentials, and mentions across the web"
    accepts_input = ["email", "username", "domain", "full_name", "phone"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        dork_map = {
            "email": EMAIL_DORKS,
            "username": USERNAME_DORKS,
            "domain": DOMAIN_DORKS,
            "full_name": FULLNAME_DORKS,
            "phone": PHONE_DORKS,
        }

        dorks = dork_map.get(input_type, [])
        all_urls_found = set()

        for dork_template in dorks:
            dork = dork_template.format(
                email=input_value,
                username=input_value,
                domain=input_value,
                full_name=input_value,
                phone=input_value,
            )
            tool_run.raw_output += f"Dork: {dork}\n"

            try:
                # Use DuckDuckGo HTML search (no API key required)
                encoded = urllib.parse.quote_plus(dork)
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    # Parse results from DuckDuckGo HTML
                    results = self._parse_ddg_html(resp.text)
                    tool_run.raw_output += f"  Results: {len(results)}\n"

                    for result in results:
                        result_url = result.get("url", "")
                        title = result.get("title", "")
                        snippet = result.get("snippet", "")

                        if not result_url or result_url in all_urls_found:
                            continue
                        all_urls_found.add(result_url)

                        # Classify the result
                        self._classify_result(
                            result_url, title, snippet, dork,
                            input_value, input_type, findings
                        )

                # Rate limit to avoid blocks
                time.sleep(1.5)

            except Exception as e:
                tool_run.raw_output += f"  Error: {e}\n"

        # Deduplicate findings by value
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        tool_run.raw_output += f"\nTotal unique findings: {len(unique)}\n"
        return unique

    def _parse_ddg_html(self, html):
        """Parse DuckDuckGo HTML results page."""
        results = []
        # Extract result blocks
        result_pattern = re.compile(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?'
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            re.DOTALL,
        )
        for match in result_pattern.finditer(html):
            url = match.group(1)
            title = re.sub(r"<[^>]+>", "", match.group(2)).strip()
            snippet = re.sub(r"<[^>]+>", "", match.group(3)).strip()

            # DDG wraps URLs - extract actual URL
            if "uddg=" in url:
                actual = re.search(r"uddg=([^&]+)", url)
                if actual:
                    url = urllib.parse.unquote(actual.group(1))

            if url.startswith("http"):
                results.append({"url": url, "title": title, "snippet": snippet})

        # Fallback: simpler pattern
        if not results:
            link_pattern = re.compile(r'href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
            for match in link_pattern.finditer(html):
                url = match.group(1)
                title = re.sub(r"<[^>]+>", "", match.group(2)).strip()
                if "duckduckgo.com" not in url and url.startswith("http"):
                    results.append({"url": url, "title": title, "snippet": ""})

        return results[:20]  # cap at 20 per dork

    def _classify_result(self, url, title, snippet, dork, input_value, input_type, findings):
        """Classify a search result into the appropriate finding type."""
        url_lower = url.lower()
        combined = f"{title} {snippet}".lower()

        # Paste sites
        paste_domains = [
            "pastebin.com", "paste.ee", "ghostbin.co", "dpaste.org",
            "ideone.com", "rentry.co", "hastebin.com",
        ]
        if any(d in url_lower for d in paste_domains):
            findings.append(Finding(
                FindingType.PASTE,
                url,
                source_tool=self.name,
                confidence=0.7,
                metadata={
                    "title": title,
                    "snippet": snippet[:300],
                    "dork": dork,
                    "target": input_value,
                },
            ))
            return

        # Social profiles
        social_domains = [
            "twitter.com", "x.com", "instagram.com", "facebook.com",
            "linkedin.com", "github.com", "gitlab.com", "reddit.com",
            "medium.com", "dev.to", "keybase.io", "twitch.tv",
            "youtube.com", "tiktok.com", "pinterest.com", "tumblr.com",
            "behance.net", "dribbble.com", "flickr.com", "soundcloud.com",
            "mastodon.social", "hackerone.com", "bugcrowd.com",
        ]
        if any(d in url_lower for d in social_domains):
            findings.append(Finding(
                FindingType.SOCIAL_PROFILE,
                url,
                source_tool=self.name,
                confidence=0.65,
                metadata={
                    "title": title,
                    "snippet": snippet[:300],
                    "dork": dork,
                },
            ))
            return

        # Messaging platforms
        msg_domains = ["t.me", "telegram.me", "discord.gg", "discord.com"]
        if any(d in url_lower for d in msg_domains):
            findings.append(Finding(
                FindingType.MESSAGING_PROFILE,
                url,
                source_tool=self.name,
                confidence=0.6,
                metadata={
                    "title": title,
                    "snippet": snippet[:300],
                    "dork": dork,
                },
            ))
            return

        # Documents / files
        doc_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx"]
        if any(url_lower.endswith(ext) for ext in doc_extensions):
            findings.append(Finding(
                FindingType.DOCUMENT_URL,
                url,
                source_tool=self.name,
                confidence=0.7,
                metadata={
                    "title": title,
                    "snippet": snippet[:300],
                    "dork": dork,
                    "target": input_value,
                },
            ))
            return

        # Credential / leak / database mentions
        leak_words = ["password", "credential", "leak", "dump", "breach", "database", "sql"]
        if any(w in combined for w in leak_words):
            findings.append(Finding(
                FindingType.WEB_MENTION,
                url,
                source_tool=self.name,
                confidence=0.6,
                metadata={
                    "title": title,
                    "snippet": snippet[:300],
                    "dork": dork,
                    "context": "potential_leak_mention",
                    "target": input_value,
                },
            ))
            # Extract emails from snippet
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", snippet)
            for email in set(emails):
                if email.lower() != input_value.lower():
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=self.name,
                        confidence=0.45,
                        metadata={"found_in_dork_result": url},
                    ))
            return

        # Generic web mention
        findings.append(Finding(
            FindingType.WEB_MENTION,
            url,
            source_tool=self.name,
            confidence=0.5,
            metadata={
                "title": title,
                "snippet": snippet[:300],
                "dork": dork,
                "target": input_value,
            },
        ))
