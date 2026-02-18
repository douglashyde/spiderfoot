"""Code Search - search GitHub, GitLab, and code repositories for target mentions."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class CodeSearchTool(ToolWrapper):
    name = "code_search"
    description = "Search GitHub repos, commits, users, and code for emails, usernames, secrets, and mentions"
    accepts_input = ["email", "username", "domain"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/vnd.github.v3+json",
        }

        # GitHub API searches (unauthenticated: 10 requests/min)
        if input_type == "email":
            self._search_github_commits_by_email(input_value, headers, findings, tool_run)
            self._search_github_code(input_value, headers, findings, tool_run)

        if input_type == "username":
            self._search_github_user(input_value, headers, findings, tool_run)
            self._search_github_code(input_value, headers, findings, tool_run)
            self._search_gitlab_user(input_value, headers, findings, tool_run)

        if input_type == "domain":
            self._search_github_code(input_value, headers, findings, tool_run)

        # SourceGraph search (public, no auth needed)
        self._search_sourcegraph(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_github_user(self, username, headers, findings, tool_run):
        """Search GitHub for user profile and repos."""
        try:
            # User profile
            url = f"https://api.github.com/users/{urllib.parse.quote(username)}"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"GitHub user: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                profile_url = data.get("html_url", "")
                name = data.get("name", "")
                email = data.get("email", "")
                bio = data.get("bio", "")
                company = data.get("company", "")
                location = data.get("location", "")
                blog = data.get("blog", "")
                twitter = data.get("twitter_username", "")
                avatar = data.get("avatar_url", "")
                public_repos = data.get("public_repos", 0)
                followers = data.get("followers", 0)
                created = data.get("created_at", "")

                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    profile_url,
                    source_tool=self.name,
                    confidence=0.9,
                    metadata={
                        "platform": "github",
                        "name": name,
                        "bio": bio,
                        "company": company,
                        "location": location,
                        "blog": blog,
                        "twitter": twitter,
                        "public_repos": public_repos,
                        "followers": followers,
                        "created_at": created,
                    },
                ))

                if name:
                    findings.append(Finding(
                        FindingType.FULL_NAME,
                        name,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"source": "github_profile", "username": username},
                    ))

                if email:
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={"source": "github_profile", "username": username},
                    ))

                if company:
                    findings.append(Finding(
                        FindingType.EMPLOYER,
                        company,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"source": "github_profile"},
                    ))

                if location:
                    findings.append(Finding(
                        FindingType.LOCATION,
                        location,
                        source_tool=self.name,
                        confidence=0.65,
                        metadata={"source": "github_profile"},
                    ))

                if blog and blog.startswith("http"):
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        blog,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"source": "github_blog", "platform": "personal_blog"},
                    ))

                if twitter:
                    findings.append(Finding(
                        FindingType.SOCIAL_PROFILE,
                        f"https://twitter.com/{twitter}",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={"platform": "twitter", "username": twitter},
                    ))

                if avatar:
                    findings.append(Finding(
                        FindingType.PHOTO_URL,
                        avatar,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={"source": "github_avatar"},
                    ))

            time.sleep(1)

            # User's repos (check for interesting files)
            url = f"https://api.github.com/users/{urllib.parse.quote(username)}/repos?per_page=30&sort=updated"
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                repos = resp.json()
                for repo in repos[:20]:
                    repo_name = repo.get("full_name", "")
                    repo_url = repo.get("html_url", "")
                    desc = repo.get("description", "")
                    language = repo.get("language", "")
                    stars = repo.get("stargazers_count", 0)

                    findings.append(Finding(
                        FindingType.CODE_REPOSITORY,
                        repo_url,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "repo_name": repo_name,
                            "description": desc,
                            "language": language,
                            "stars": stars,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"GitHub user error: {e}\n"

    def _search_github_commits_by_email(self, email, headers, findings, tool_run):
        """Search GitHub commits by author email - finds associated accounts."""
        try:
            url = f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}&per_page=20"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/vnd.github.cloak-preview+json",
            }, timeout=15)
            tool_run.raw_output += f"GitHub commits by email: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                seen_authors = set()

                for item in items[:20]:
                    author = item.get("author", {})
                    committer = item.get("committer", {})
                    commit = item.get("commit", {})
                    repo = item.get("repository", {})

                    # Extract GitHub username from commit author
                    if author and isinstance(author, dict):
                        login = author.get("login", "")
                        if login and login not in seen_authors:
                            seen_authors.add(login)
                            findings.append(Finding(
                                FindingType.RELATED_USERNAME,
                                login,
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={
                                    "source": "github_commit",
                                    "email": email,
                                    "platform": "github",
                                },
                            ))
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                f"https://github.com/{login}",
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={"platform": "github", "found_via": "commit_email"},
                            ))

                    # Extract name from commit data
                    commit_author = commit.get("author", {})
                    name = commit_author.get("name", "")
                    if name and " " in name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            name,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={"source": "git_commit", "email": email},
                        ))

                    # Track repos
                    if repo:
                        repo_url = repo.get("html_url", "")
                        if repo_url:
                            findings.append(Finding(
                                FindingType.CODE_REPOSITORY,
                                repo_url,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "contributor_email": email,
                                    "repo_name": repo.get("full_name", ""),
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"GitHub commit search error: {e}\n"

    def _search_github_code(self, query, headers, findings, tool_run):
        """Search GitHub code for mentions of the target."""
        try:
            time.sleep(2)  # Rate limit
            encoded = urllib.parse.quote(f'"{query}"')
            url = f"https://api.github.com/search/code?q={encoded}&per_page=20"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/vnd.github.v3.text-match+json",
            }, timeout=15)
            tool_run.raw_output += f"GitHub code search: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for item in items[:15]:
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
                        confidence=0.7,
                        metadata={
                            "repo": repo_name,
                            "file": file_name,
                            "snippet": snippet[:500],
                            "target": query,
                        },
                    ))

                    # Check for potential secrets/credentials in matches
                    if snippet:
                        self._extract_secrets(snippet, html_url, findings)

        except Exception as e:
            tool_run.raw_output += f"GitHub code search error: {e}\n"

    def _search_gitlab_user(self, username, headers, findings, tool_run):
        """Search GitLab for user profile."""
        try:
            url = f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(username)}"
            resp = requests.get(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            }, timeout=10)
            tool_run.raw_output += f"GitLab user: {resp.status_code}\n"

            if resp.status_code == 200:
                users = resp.json()
                for user in users[:3]:
                    name = user.get("name", "")
                    web_url = user.get("web_url", "")
                    avatar = user.get("avatar_url", "")
                    bio = user.get("bio", "")
                    location = user.get("location", "")

                    if web_url:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            web_url,
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={
                                "platform": "gitlab",
                                "name": name,
                                "bio": bio,
                                "location": location,
                            },
                        ))

                    if name and " " in name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            name,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={"source": "gitlab_profile"},
                        ))

        except Exception as e:
            tool_run.raw_output += f"GitLab error: {e}\n"

    def _search_sourcegraph(self, query, headers, findings, tool_run):
        """Search Sourcegraph for code mentions."""
        try:
            url = "https://sourcegraph.com/.api/search/stream"
            params = {
                "q": f'"{query}" count:20',
                "v": "V3",
                "t": "literal",
                "display": "20",
            }
            resp = requests.get(url, params=params, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/event-stream",
            }, timeout=15, stream=True)
            tool_run.raw_output += f"Sourcegraph: {resp.status_code}\n"

            if resp.status_code == 200:
                content = resp.text[:10000]
                # Parse SSE events for matches
                repo_pattern = re.compile(r'"repository":"([^"]+)"')
                file_pattern = re.compile(r'"path":"([^"]+)"')
                repos_found = set()
                for repo_match in repo_pattern.finditer(content):
                    repo = repo_match.group(1)
                    if repo not in repos_found:
                        repos_found.add(repo)
                        findings.append(Finding(
                            FindingType.CODE_REPOSITORY,
                            f"https://sourcegraph.com/{repo}",
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "repo": repo,
                                "target": query,
                                "source": "sourcegraph",
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Sourcegraph error: {e}\n"

    def _extract_secrets(self, text, source_url, findings):
        """Extract potential secrets/credentials from code snippets."""
        # Look for common secret patterns
        patterns = {
            "api_key": r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
            "password": r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]+)['\"]",
            "token": r"(?:token|access_token|auth_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?",
            "secret": r"(?:secret|secret_key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
        }

        for secret_type, pattern in patterns.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                secret_value = match.group(1)
                if len(secret_value) > 8:  # Filter out very short matches
                    findings.append(Finding(
                        FindingType.LEAKED_CREDENTIAL,
                        f"{secret_type}: {secret_value[:50]}...",
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={
                            "type": secret_type,
                            "found_in": source_url,
                            "context": "code_search",
                        },
                    ))
