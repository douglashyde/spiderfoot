"""Messaging Platform Search - search Telegram, Discord, Matrix, and other platforms."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class MessagingSearchTool(ToolWrapper):
    name = "messaging_search"
    description = "Search Telegram channels/groups, Discord servers, Matrix rooms, and messaging platforms for mentions"
    accepts_input = ["email", "username", "domain", "phone", "full_name"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        if input_type == "username":
            # Direct profile checks
            self._check_telegram_profile(input_value, headers, findings, tool_run)
            self._check_matrix_user(input_value, headers, findings, tool_run)
            self._check_signal_username(input_value, headers, findings, tool_run)

        # Telegram channel/group search
        self._search_telegram_channels(input_value, headers, findings, tool_run)

        # Discord search
        self._search_discord_public(input_value, headers, findings, tool_run)

        # Web search for messaging mentions
        self._search_messaging_web(input_value, input_type, headers, findings, tool_run)

        # Search Telegram content aggregators
        self._search_telegram_aggregators(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _check_telegram_profile(self, username, headers, findings, tool_run):
        """Check if a Telegram username exists by checking t.me."""
        try:
            url = f"https://t.me/{username}"
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            tool_run.raw_output += f"Telegram t.me: {resp.status_code}\n"

            if resp.status_code == 200:
                # Check if it's a real profile vs 404 page
                if "tgme_page_title" in resp.text or "tgme_channel_info" in resp.text:
                    # Extract profile info
                    title_match = re.search(r'class="tgme_page_title[^"]*"[^>]*><span[^>]*>(.*?)</span>', resp.text, re.DOTALL)
                    desc_match = re.search(r'class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', resp.text, re.DOTALL)
                    photo_match = re.search(r'class="tgme_page_photo[^"]*"[^>]*>.*?<img[^>]*src="([^"]+)"', resp.text, re.DOTALL)
                    members_match = re.search(r'class="tgme_page_extra"[^>]*>(.*?)</div>', resp.text, re.DOTALL)

                    title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else ""
                    description = re.sub(r"<[^>]+>", "", desc_match.group(1)).strip() if desc_match else ""
                    photo = photo_match.group(1) if photo_match else ""
                    extra = re.sub(r"<[^>]+>", "", members_match.group(1)).strip() if members_match else ""

                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        f"https://t.me/{username}",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "platform": "telegram",
                            "title": title,
                            "description": description[:300],
                            "extra": extra,
                            "username": username,
                        },
                    ))

                    if photo:
                        findings.append(Finding(
                            FindingType.PHOTO_URL,
                            photo,
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={"source": "telegram", "username": username},
                        ))

                    if title and " " in title:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            title,
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={"source": "telegram_profile", "username": username},
                        ))

        except Exception as e:
            tool_run.raw_output += f"Telegram check error: {e}\n"

    def _check_matrix_user(self, username, headers, findings, tool_run):
        """Check Matrix/Element user directory."""
        try:
            # Search public Matrix directory
            url = "https://matrix-client.matrix.org/_matrix/client/r0/user_directory/search"
            resp = requests.post(url, json={
                "search_term": username,
                "limit": 10,
            }, headers={
                **headers,
                "Content-Type": "application/json",
            }, timeout=10)
            tool_run.raw_output += f"Matrix: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                for user in results[:5]:
                    user_id = user.get("user_id", "")
                    display_name = user.get("display_name", "")
                    avatar_url = user.get("avatar_url", "")

                    if user_id and username.lower() in user_id.lower():
                        findings.append(Finding(
                            FindingType.MESSAGING_PROFILE,
                            f"https://matrix.to/#/{user_id}",
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "platform": "matrix",
                                "user_id": user_id,
                                "display_name": display_name,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Matrix error: {e}\n"

    def _check_signal_username(self, username, headers, findings, tool_run):
        """Check Signal username (limited - just web search)."""
        try:
            encoded = urllib.parse.quote_plus(f'"{username}" site:signal.me OR site:signal.org')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                signal_links = [l for l in links if "signal.me" in l or "signal.org" in l]
                for link in signal_links[:3]:
                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        link,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"platform": "signal", "username": username},
                    ))

        except Exception as e:
            tool_run.raw_output += f"Signal check error: {e}\n"

    def _search_telegram_channels(self, query, headers, findings, tool_run):
        """Search for Telegram channels/groups mentioning the target."""
        try:
            # tgstat.com channel search
            encoded = urllib.parse.quote_plus(query)
            url = f"https://tgstat.com/search?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"TGStat: {resp.status_code}\n"

            if resp.status_code == 200:
                # Extract channel links
                channel_pattern = re.compile(r'href="(https?://t\.me/[a-zA-Z0-9_]+)"', re.IGNORECASE)
                channels = set(channel_pattern.findall(resp.text))
                for channel in list(channels)[:10]:
                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        channel,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "platform": "telegram",
                            "type": "channel_mention",
                            "target": query,
                            "source": "tgstat",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"TGStat error: {e}\n"

    def _search_telegram_aggregators(self, query, headers, findings, tool_run):
        """Search Telegram content aggregators."""
        aggregator_urls = [
            f"https://lyzem.com/search?q={urllib.parse.quote_plus(query)}",
            f"https://tg-me.com/search?q={urllib.parse.quote_plus(query)}",
        ]

        for agg_url in aggregator_urls:
            try:
                resp = requests.get(agg_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    # Extract t.me links
                    tg_links = re.findall(r'(https?://t\.me/[a-zA-Z0-9_/]+)', resp.text)
                    for link in set(tg_links[:10]):
                        findings.append(Finding(
                            FindingType.MESSAGING_PROFILE,
                            link,
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "platform": "telegram",
                                "target": query,
                                "source": "telegram_aggregator",
                            },
                        ))

            except Exception as e:
                tool_run.raw_output += f"TG aggregator error: {e}\n"

    def _search_discord_public(self, query, headers, findings, tool_run):
        """Search for Discord server invites and mentions."""
        try:
            # Search for Discord invite links and public servers
            encoded = urllib.parse.quote_plus(f'"{query}" site:discord.gg OR site:discord.com/invite OR site:discordapp.com')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                discord_links = [l for l in links if "discord" in l.lower()]
                for link in discord_links[:10]:
                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        link,
                        source_tool=self.name,
                        confidence=0.55,
                        metadata={
                            "platform": "discord",
                            "target": query,
                        },
                    ))

            # Discordbotlist / top.gg search
            time.sleep(1)
            encoded = urllib.parse.quote_plus(f'"{query}" site:top.gg OR site:discord.me OR site:disboard.org')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                for link in links[:5]:
                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        link,
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={
                            "platform": "discord",
                            "target": query,
                            "source": "discord_directory",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"Discord search error: {e}\n"

    def _search_messaging_web(self, query, input_type, headers, findings, tool_run):
        """Search for messaging platform mentions via web."""
        try:
            platforms = "site:t.me OR site:discord.gg OR site:matrix.to OR site:signal.me OR site:wire.com OR site:keybase.io"
            encoded = urllib.parse.quote_plus(f'"{query}" ({platforms})')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                platform_map = {
                    "t.me": "telegram",
                    "telegram.me": "telegram",
                    "discord.gg": "discord",
                    "discord.com": "discord",
                    "matrix.to": "matrix",
                    "signal.me": "signal",
                    "wire.com": "wire",
                    "keybase.io": "keybase",
                }

                for link in links[:15]:
                    platform = "unknown"
                    for domain, pname in platform_map.items():
                        if domain in link.lower():
                            platform = pname
                            break

                    findings.append(Finding(
                        FindingType.MESSAGING_PROFILE,
                        link,
                        source_tool=self.name,
                        confidence=0.55,
                        metadata={
                            "platform": platform,
                            "target": query,
                            "source": "web_search",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"Messaging web search error: {e}\n"

    def _extract_ddg_links(self, html):
        """Extract actual URLs from DuckDuckGo HTML."""
        links = []
        for match in re.finditer(r'uddg=([^&"]+)', html):
            url = urllib.parse.unquote(match.group(1))
            if url.startswith("http") and "duckduckgo.com" not in url:
                links.append(url)
        return links
