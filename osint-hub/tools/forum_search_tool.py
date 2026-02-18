"""Forum Search - search Reddit, StackOverflow, HackerNews, and other public forums."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class ForumSearchTool(ToolWrapper):
    name = "forum_search"
    description = "Search Reddit, StackOverflow, HackerNews, and public forums for mentions, posts, and profiles"
    accepts_input = ["email", "username", "domain", "full_name"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        if input_type == "username":
            # Direct profile lookups
            self._search_reddit_user(input_value, headers, findings, tool_run)
            self._search_hackernews_user(input_value, headers, findings, tool_run)
            self._search_stackoverflow_user(input_value, headers, findings, tool_run)
            self._search_keybase_user(input_value, headers, findings, tool_run)

        # Search across forums for mentions
        self._search_reddit_posts(input_value, headers, findings, tool_run)
        self._search_stackoverflow_search(input_value, headers, findings, tool_run)
        self._search_hackernews_search(input_value, headers, findings, tool_run)

        # Web search for forum mentions
        self._search_forums_via_web(input_value, input_type, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_reddit_user(self, username, headers, findings, tool_run):
        """Check Reddit user profile."""
        try:
            url = f"https://www.reddit.com/user/{urllib.parse.quote(username)}/about.json"
            resp = requests.get(url, headers={
                **headers,
                "User-Agent": "OSINT-Hub/1.0",
            }, timeout=10)
            tool_run.raw_output += f"Reddit user: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                name = data.get("subreddit", {}).get("title", "")
                description = data.get("subreddit", {}).get("public_description", "")
                icon = data.get("icon_img", "") or data.get("snoovatar_img", "")
                created = data.get("created_utc", "")
                karma = data.get("total_karma", 0)
                link_karma = data.get("link_karma", 0)
                comment_karma = data.get("comment_karma", 0)

                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    f"https://reddit.com/user/{username}",
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={
                        "platform": "reddit",
                        "display_name": name,
                        "description": description[:300],
                        "total_karma": karma,
                        "link_karma": link_karma,
                        "comment_karma": comment_karma,
                        "created_utc": created,
                    },
                ))

                if icon and icon.startswith("http"):
                    findings.append(Finding(
                        FindingType.PHOTO_URL,
                        icon,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"source": "reddit_avatar", "username": username},
                    ))

        except Exception as e:
            tool_run.raw_output += f"Reddit user error: {e}\n"

    def _search_reddit_posts(self, query, headers, findings, tool_run):
        """Search Reddit for mentions."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://www.reddit.com/search.json?q={encoded}&limit=25&sort=relevance"
            resp = requests.get(url, headers={
                **headers,
                "User-Agent": "OSINT-Hub/1.0",
            }, timeout=15)
            tool_run.raw_output += f"Reddit search: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                posts = data.get("data", {}).get("children", [])
                for post in posts[:20]:
                    pdata = post.get("data", {})
                    title = pdata.get("title", "")
                    permalink = pdata.get("permalink", "")
                    subreddit = pdata.get("subreddit", "")
                    author = pdata.get("author", "")
                    selftext = pdata.get("selftext", "")
                    score = pdata.get("score", 0)
                    created = pdata.get("created_utc", "")

                    if permalink:
                        findings.append(Finding(
                            FindingType.FORUM_POST,
                            f"https://reddit.com{permalink}",
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "title": title[:200],
                                "subreddit": subreddit,
                                "author": author,
                                "score": score,
                                "preview": selftext[:300],
                                "target": query,
                                "platform": "reddit",
                                "created_utc": created,
                            },
                        ))

                        # Extract emails from post text
                        if selftext:
                            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", selftext)
                            for email in set(emails):
                                findings.append(Finding(
                                    FindingType.RELATED_EMAIL,
                                    email.lower(),
                                    source_tool=self.name,
                                    confidence=0.45,
                                    metadata={"found_in_reddit_post": permalink},
                                ))

            time.sleep(1)

        except Exception as e:
            tool_run.raw_output += f"Reddit search error: {e}\n"

    def _search_hackernews_user(self, username, headers, findings, tool_run):
        """Check HackerNews user profile."""
        try:
            url = f"https://hacker-news.firebaseio.com/v0/user/{urllib.parse.quote(username)}.json"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"HN user: {resp.status_code}\n"

            if resp.status_code == 200 and resp.text != "null":
                data = resp.json()
                if data:
                    about = data.get("about", "")
                    karma = data.get("karma", 0)
                    created = data.get("created", "")

                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        f"https://news.ycombinator.com/user?id={username}",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "platform": "hackernews",
                            "about": re.sub(r"<[^>]+>", "", about)[:300],
                            "karma": karma,
                            "created": created,
                        },
                    ))

                    # Extract URLs from about section
                    if about:
                        urls = re.findall(r'href="([^"]+)"', about)
                        for url_found in urls:
                            if url_found.startswith("http"):
                                findings.append(Finding(
                                    FindingType.WEB_MENTION,
                                    url_found,
                                    source_tool=self.name,
                                    confidence=0.6,
                                    metadata={"source": "hackernews_about", "username": username},
                                ))

                        # Extract emails
                        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", about)
                        for email in set(emails):
                            findings.append(Finding(
                                FindingType.RELATED_EMAIL,
                                email.lower(),
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={"source": "hackernews_about"},
                            ))

        except Exception as e:
            tool_run.raw_output += f"HN user error: {e}\n"

    def _search_hackernews_search(self, query, headers, findings, tool_run):
        """Search HackerNews via Algolia API."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://hn.algolia.com/api/v1/search?query={encoded}&tags=story&hitsPerPage=15"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"HN search: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                hits = data.get("hits", [])
                for hit in hits[:15]:
                    title = hit.get("title", "")
                    hn_url = hit.get("url", "")
                    story_url = f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"
                    author = hit.get("author", "")
                    points = hit.get("points", 0)

                    findings.append(Finding(
                        FindingType.FORUM_POST,
                        story_url,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={
                            "title": title[:200],
                            "external_url": hn_url,
                            "author": author,
                            "points": points,
                            "target": query,
                            "platform": "hackernews",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"HN search error: {e}\n"

    def _search_stackoverflow_user(self, username, headers, findings, tool_run):
        """Search StackOverflow for user profile."""
        try:
            encoded = urllib.parse.quote_plus(username)
            url = f"https://api.stackexchange.com/2.3/users?inname={encoded}&site=stackoverflow&pagesize=5"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"SO user: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for user in items[:3]:
                    display_name = user.get("display_name", "")
                    link = user.get("link", "")
                    reputation = user.get("reputation", 0)
                    location = user.get("location", "")
                    website = user.get("website_url", "")
                    profile_image = user.get("profile_image", "")

                    if link:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            link,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "platform": "stackoverflow",
                                "display_name": display_name,
                                "reputation": reputation,
                                "location": location,
                                "website": website,
                            },
                        ))

                    if location:
                        findings.append(Finding(
                            FindingType.LOCATION,
                            location,
                            source_tool=self.name,
                            confidence=0.5,
                            metadata={"source": "stackoverflow_profile"},
                        ))

                    if website and website.startswith("http"):
                        findings.append(Finding(
                            FindingType.WEB_MENTION,
                            website,
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={"source": "stackoverflow_website"},
                        ))

        except Exception as e:
            tool_run.raw_output += f"SO user error: {e}\n"

    def _search_stackoverflow_search(self, query, headers, findings, tool_run):
        """Search StackOverflow questions/answers."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://api.stackexchange.com/2.3/search/excerpts?q={encoded}&site=stackoverflow&pagesize=10"
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for item in items[:10]:
                    title = item.get("title", "")
                    question_id = item.get("question_id", "")
                    excerpt = item.get("excerpt", "")

                    if question_id:
                        findings.append(Finding(
                            FindingType.FORUM_POST,
                            f"https://stackoverflow.com/questions/{question_id}",
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "title": re.sub(r"<[^>]+>", "", title)[:200],
                                "excerpt": re.sub(r"<[^>]+>", "", excerpt)[:300],
                                "target": query,
                                "platform": "stackoverflow",
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"SO search error: {e}\n"

    def _search_keybase_user(self, username, headers, findings, tool_run):
        """Search Keybase for user profile and linked accounts."""
        try:
            url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={urllib.parse.quote(username)}"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"Keybase: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                users = data.get("them", [])
                for user in users:
                    if not user:
                        continue

                    kb_username = user.get("basics", {}).get("username", "")
                    profile = user.get("profile", {})
                    full_name = profile.get("full_name", "")
                    bio = profile.get("bio", "")
                    location = profile.get("location", "")

                    if kb_username:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            f"https://keybase.io/{kb_username}",
                            source_tool=self.name,
                            confidence=0.9,
                            metadata={
                                "platform": "keybase",
                                "full_name": full_name,
                                "bio": bio,
                                "location": location,
                            },
                        ))

                    if full_name and " " in full_name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            full_name,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={"source": "keybase_profile"},
                        ))

                    # Extract linked proofs (GitHub, Twitter, Reddit, etc.)
                    proofs = user.get("proofs_summary", {}).get("all", [])
                    for proof in proofs:
                        proof_type = proof.get("proof_type", "")
                        nametag = proof.get("nametag", "")
                        service_url = proof.get("service_url", "")

                        if service_url:
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                service_url,
                                source_tool=self.name,
                                confidence=0.9,
                                metadata={
                                    "platform": proof_type,
                                    "username": nametag,
                                    "verified_via": "keybase_proof",
                                },
                            ))

                        if nametag and proof_type != "keybase":
                            findings.append(Finding(
                                FindingType.RELATED_USERNAME,
                                nametag,
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={
                                    "platform": proof_type,
                                    "verified_via": "keybase_proof",
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"Keybase error: {e}\n"

    def _search_forums_via_web(self, query, input_type, headers, findings, tool_run):
        """Search forums via DuckDuckGo."""
        try:
            forum_sites = "site:reddit.com OR site:quora.com OR site:stackoverflow.com OR site:news.ycombinator.com OR site:medium.com OR site:dev.to"
            encoded = urllib.parse.quote_plus(f'"{query}" ({forum_sites})')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = re.findall(r'uddg=([^&"]+)', resp.text)
                forum_domains = ["reddit.com", "quora.com", "stackoverflow.com",
                                 "news.ycombinator.com", "medium.com", "dev.to"]
                for link in links[:15]:
                    decoded = urllib.parse.unquote(link)
                    if any(d in decoded.lower() for d in forum_domains):
                        findings.append(Finding(
                            FindingType.FORUM_POST,
                            decoded,
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "target": query,
                                "source": "web_search",
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Forum web search error: {e}\n"
