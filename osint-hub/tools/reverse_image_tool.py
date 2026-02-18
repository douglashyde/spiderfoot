"""Reverse Image Search - use found photos to discover more accounts and identities."""
import re
import json
import time
import hashlib
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class ReverseImageTool(ToolWrapper):
    name = "reverse_image"
    description = "Reverse image search - find where profile photos appear across the web (TinEye, Yandex, Google)"
    accepts_input = ["username", "email"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # This tool works differently - it looks at EXISTING findings for photo URLs
        # and then reverse-searches them. It also checks common avatar URLs.
        photo_urls = self._gather_photo_urls(input_value, input_type, tool_run)

        for photo_url in photo_urls[:5]:  # Limit to 5 photos
            tool_run.raw_output += f"\nReverse searching: {photo_url}\n"

            # TinEye API (free for limited searches)
            self._search_tineye(photo_url, headers, findings, tool_run)

            # Yandex Images (most powerful for faces)
            self._search_yandex(photo_url, headers, findings, tool_run)

            # Google Lens via web search
            self._search_google_lens(photo_url, headers, findings, tool_run)

            # PimEyes alternative search
            self._search_facecheck(photo_url, headers, findings, tool_run)

            time.sleep(1)

        # Also generate direct avatar URLs for common platforms and check them
        if input_type == "username":
            self._check_platform_avatars(input_value, headers, findings, tool_run)
        elif input_type == "email":
            self._check_gravatar_avatar(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _gather_photo_urls(self, input_value, input_type, tool_run):
        """Gather photo URLs from the current investigation profile.
        Since we can't access the profile directly from the tool,
        we construct common avatar URLs."""
        photo_urls = []

        if input_type == "email":
            # Gravatar
            email_hash = hashlib.md5(input_value.lower().strip().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=400&d=404"
            try:
                resp = requests.head(gravatar_url, timeout=5)
                if resp.status_code == 200:
                    photo_urls.append(gravatar_url)
                    tool_run.raw_output += f"Found Gravatar: {gravatar_url}\n"
            except Exception:
                pass

        if input_type == "username":
            # GitHub avatar
            try:
                resp = requests.get(
                    f"https://api.github.com/users/{input_value}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    avatar = resp.json().get("avatar_url", "")
                    if avatar:
                        photo_urls.append(avatar)
                        tool_run.raw_output += f"Found GitHub avatar: {avatar}\n"
            except Exception:
                pass

            # Twitter/X avatar (via unavatar.io - free avatar proxy)
            try:
                unavatar_url = f"https://unavatar.io/{input_value}?fallback=false"
                resp = requests.head(unavatar_url, timeout=5, allow_redirects=True)
                if resp.status_code == 200:
                    photo_urls.append(unavatar_url)
                    tool_run.raw_output += f"Found unavatar: {unavatar_url}\n"
            except Exception:
                pass

        return photo_urls

    def _search_tineye(self, image_url, headers, findings, tool_run):
        """Search TinEye for reverse image matches."""
        try:
            url = f"https://tineye.com/search?url={urllib.parse.quote(image_url)}"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "text/html",
            }, timeout=15)
            tool_run.raw_output += f"TinEye: {resp.status_code}\n"

            if resp.status_code == 200:
                # Extract match count
                match_count = re.search(r'(\d+)\s+results?', resp.text)
                if match_count and int(match_count.group(1)) > 0:
                    count = int(match_count.group(1))
                    findings.append(Finding(
                        FindingType.WEB_MENTION,
                        f"TinEye: {count} reverse image matches",
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "image_url": image_url,
                            "match_count": count,
                            "search_url": url,
                            "source": "tineye",
                        },
                    ))

                # Extract matched domains
                domains = re.findall(r'class="match[^"]*"[^>]*>.*?<a[^>]*href="(https?://[^"]+)"', resp.text, re.DOTALL)
                for match_url in domains[:10]:
                    self._classify_image_match(match_url, image_url, findings)

        except Exception as e:
            tool_run.raw_output += f"TinEye error: {e}\n"

    def _search_yandex(self, image_url, headers, findings, tool_run):
        """Search Yandex Images (best for facial recognition)."""
        try:
            url = f"https://yandex.com/images/search?rpt=imageview&url={urllib.parse.quote(image_url)}"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "text/html",
            }, timeout=15, allow_redirects=True)
            tool_run.raw_output += f"Yandex: {resp.status_code}\n"

            if resp.status_code == 200:
                # Extract similar image URLs and sites
                site_matches = re.findall(r'"url":"(https?://[^"]+)"', resp.text)
                for match_url in set(site_matches[:15]):
                    if "yandex" not in match_url.lower():
                        self._classify_image_match(match_url, image_url, findings)

                # Extract "other sizes" and "similar images" links
                similar = re.findall(r'href="(https?://[^"]+)"[^>]*class="[^"]*similar', resp.text)
                for sim_url in set(similar[:10]):
                    self._classify_image_match(sim_url, image_url, findings)

                # Note the search URL for manual investigation
                findings.append(Finding(
                    FindingType.WEB_MENTION,
                    url,
                    source_tool=self.name,
                    confidence=0.5,
                    metadata={
                        "type": "reverse_image_search_url",
                        "image_url": image_url,
                        "source": "yandex",
                        "note": "Open this URL to see Yandex reverse image results",
                    },
                ))

        except Exception as e:
            tool_run.raw_output += f"Yandex error: {e}\n"

    def _search_google_lens(self, image_url, headers, findings, tool_run):
        """Generate Google Lens reverse image search URL."""
        try:
            lens_url = f"https://lens.google.com/uploadbyurl?url={urllib.parse.quote(image_url)}"
            findings.append(Finding(
                FindingType.WEB_MENTION,
                lens_url,
                source_tool=self.name,
                confidence=0.5,
                metadata={
                    "type": "reverse_image_search_url",
                    "image_url": image_url,
                    "source": "google_lens",
                    "note": "Open this URL to see Google Lens results",
                },
            ))

            # Also try Google's image search
            google_url = f"https://www.google.com/searchbyimage?image_url={urllib.parse.quote(image_url)}"
            findings.append(Finding(
                FindingType.WEB_MENTION,
                google_url,
                source_tool=self.name,
                confidence=0.5,
                metadata={
                    "type": "reverse_image_search_url",
                    "image_url": image_url,
                    "source": "google_images",
                },
            ))

        except Exception as e:
            tool_run.raw_output += f"Google Lens error: {e}\n"

    def _search_facecheck(self, image_url, headers, findings, tool_run):
        """Check FaceCheck.ID (face-matching search engine)."""
        try:
            # FaceCheck.ID doesn't have a free API, but we can note the URL
            facecheck_url = f"https://facecheck.id/search?url={urllib.parse.quote(image_url)}"
            findings.append(Finding(
                FindingType.WEB_MENTION,
                facecheck_url,
                source_tool=self.name,
                confidence=0.4,
                metadata={
                    "type": "face_search_url",
                    "image_url": image_url,
                    "source": "facecheck",
                    "note": "Face recognition search - open to find matching faces",
                },
            ))

        except Exception as e:
            tool_run.raw_output += f"FaceCheck error: {e}\n"

    def _check_platform_avatars(self, username, headers, findings, tool_run):
        """Check and collect avatars from major platforms."""
        avatar_endpoints = {
            "github": f"https://github.com/{username}.png",
            "twitter": f"https://unavatar.io/twitter/{username}",
            "instagram": f"https://unavatar.io/instagram/{username}",
            "youtube": f"https://unavatar.io/youtube/{username}",
            "reddit": f"https://unavatar.io/reddit/{username}",
            "telegram": f"https://unavatar.io/telegram/{username}",
        }

        for platform, url in avatar_endpoints.items():
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "image" in content_type:
                        findings.append(Finding(
                            FindingType.PHOTO_URL,
                            url,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={
                                "platform": platform,
                                "username": username,
                                "type": "avatar",
                            },
                        ))
                        tool_run.raw_output += f"Found {platform} avatar\n"

            except Exception:
                pass

    def _check_gravatar_avatar(self, email, headers, findings, tool_run):
        """Check Gravatar for email avatar."""
        try:
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            url = f"https://www.gravatar.com/avatar/{email_hash}?s=400&d=404"
            resp = requests.head(url, timeout=5)
            if resp.status_code == 200:
                findings.append(Finding(
                    FindingType.PHOTO_URL,
                    url,
                    source_tool=self.name,
                    confidence=0.85,
                    metadata={
                        "platform": "gravatar",
                        "email": email,
                        "hash": email_hash,
                    },
                ))
        except Exception:
            pass

    def _classify_image_match(self, match_url, original_image_url, findings):
        """Classify where a reverse image match was found."""
        url_lower = match_url.lower()

        social_domains = {
            "twitter.com": "twitter", "x.com": "twitter",
            "instagram.com": "instagram", "facebook.com": "facebook",
            "linkedin.com": "linkedin", "github.com": "github",
            "reddit.com": "reddit", "tiktok.com": "tiktok",
            "vk.com": "vk", "ok.ru": "odnoklassniki",
            "pinterest.com": "pinterest", "flickr.com": "flickr",
        }

        for domain, platform in social_domains.items():
            if domain in url_lower:
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    match_url,
                    source_tool=self.name,
                    confidence=0.7,
                    metadata={
                        "platform": platform,
                        "found_via": "reverse_image_search",
                        "original_image": original_image_url,
                    },
                ))
                return

        # Generic web mention
        findings.append(Finding(
            FindingType.WEB_MENTION,
            match_url,
            source_tool=self.name,
            confidence=0.55,
            metadata={
                "found_via": "reverse_image_search",
                "original_image": original_image_url,
            },
        ))
