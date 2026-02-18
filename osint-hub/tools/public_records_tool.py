"""Public Records - search people search engines, public databases, and data aggregators."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class PublicRecordsTool(ToolWrapper):
    name = "public_records"
    description = "Search people search engines, public records, voter rolls, court records, and data aggregators"
    accepts_input = ["email", "username", "full_name", "phone", "domain"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # Web search across people search engines
        self._search_people_engines(input_value, input_type, headers, findings, tool_run)

        # Gravatar (works for emails)
        if input_type == "email":
            self._search_gravatar(input_value, headers, findings, tool_run)

        # About.me
        if input_type == "username":
            self._search_aboutme(input_value, headers, findings, tool_run)

        # OpenCorporates (for names and domains)
        if input_type in ("full_name", "domain"):
            self._search_opencorporates(input_value, input_type, headers, findings, tool_run)

        # Skymem (email search engine)
        if input_type in ("email", "domain"):
            self._search_skymem(input_value, headers, findings, tool_run)

        # That's Them (public records)
        self._search_thatsthem(input_value, input_type, headers, findings, tool_run)

        # Web archive people search
        self._search_people_web(input_value, input_type, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_people_engines(self, query, input_type, headers, findings, tool_run):
        """Search across multiple people search engines via DuckDuckGo."""
        people_sites = [
            "site:spokeo.com",
            "site:whitepages.com",
            "site:pipl.com",
            "site:beenverified.com",
            "site:truepeoplesearch.com",
            "site:fastpeoplesearch.com",
            "site:thatsThem.com",
            "site:webmii.com",
            "site:peekyou.com",
            "site:radaris.com",
            "site:zabasearch.com",
            "site:intelius.com",
        ]

        # Batch search in groups
        site_groups = [
            " OR ".join(people_sites[:4]),
            " OR ".join(people_sites[4:8]),
            " OR ".join(people_sites[8:]),
        ]

        for site_group in site_groups:
            try:
                encoded = urllib.parse.quote_plus(f'"{query}" ({site_group})')
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    links = self._extract_ddg_links(resp.text)
                    titles = self._extract_ddg_titles(resp.text)

                    for i, link in enumerate(links[:10]):
                        title = titles[i] if i < len(titles) else ""
                        findings.append(Finding(
                            FindingType.PUBLIC_RECORD,
                            link,
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "title": title[:200],
                                "target": query,
                                "source": "people_search_engine",
                            },
                        ))

                time.sleep(1.5)

            except Exception as e:
                tool_run.raw_output += f"People search error: {e}\n"

    def _search_gravatar(self, email, headers, findings, tool_run):
        """Search Gravatar for profile info."""
        try:
            import hashlib
            email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
            url = f"https://www.gravatar.com/{email_hash}.json"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"Gravatar: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entry", [])
                for entry in entries:
                    display_name = entry.get("displayName", "")
                    name_obj = entry.get("name", {})
                    full_name = f"{name_obj.get('givenName', '')} {name_obj.get('familyName', '')}".strip()
                    about = entry.get("aboutMe", "")
                    location = entry.get("currentLocation", "")
                    thumbnail = entry.get("thumbnailUrl", "")
                    profile_url = entry.get("profileUrl", "")

                    if profile_url:
                        findings.append(Finding(
                            FindingType.SOCIAL_PROFILE,
                            profile_url,
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={
                                "platform": "gravatar",
                                "display_name": display_name,
                                "about": about[:300],
                                "location": location,
                                "email": email,
                            },
                        ))

                    if full_name and " " in full_name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            full_name,
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={"source": "gravatar", "email": email},
                        ))

                    if location:
                        findings.append(Finding(
                            FindingType.LOCATION,
                            location,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"source": "gravatar"},
                        ))

                    if thumbnail:
                        findings.append(Finding(
                            FindingType.PHOTO_URL,
                            thumbnail,
                            source_tool=self.name,
                            confidence=0.9,
                            metadata={"source": "gravatar", "email": email},
                        ))

                    # Linked accounts
                    accounts = entry.get("accounts", [])
                    for account in accounts:
                        acc_url = account.get("url", "")
                        acc_name = account.get("shortname", "")
                        acc_username = account.get("username", "")

                        if acc_url:
                            findings.append(Finding(
                                FindingType.SOCIAL_PROFILE,
                                acc_url,
                                source_tool=self.name,
                                confidence=0.85,
                                metadata={
                                    "platform": acc_name,
                                    "username": acc_username,
                                    "linked_via": "gravatar",
                                },
                            ))

                        if acc_username:
                            findings.append(Finding(
                                FindingType.RELATED_USERNAME,
                                acc_username,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={"platform": acc_name, "linked_via": "gravatar"},
                            ))

        except Exception as e:
            tool_run.raw_output += f"Gravatar error: {e}\n"

    def _search_aboutme(self, username, headers, findings, tool_run):
        """Check about.me profile."""
        try:
            url = f"https://about.me/{username}"
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            tool_run.raw_output += f"About.me: {resp.status_code}\n"

            if resp.status_code == 200 and "about.me" in resp.url:
                findings.append(Finding(
                    FindingType.SOCIAL_PROFILE,
                    url,
                    source_tool=self.name,
                    confidence=0.75,
                    metadata={"platform": "about.me", "username": username},
                ))

                # Extract bio/info from HTML
                name_match = re.search(r'<h1[^>]*class="[^"]*name[^"]*"[^>]*>(.*?)</h1>', resp.text, re.DOTALL)
                if name_match:
                    name = re.sub(r"<[^>]+>", "", name_match.group(1)).strip()
                    if name and " " in name:
                        findings.append(Finding(
                            FindingType.FULL_NAME,
                            name,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"source": "about.me"},
                        ))

        except Exception as e:
            tool_run.raw_output += f"About.me error: {e}\n"

    def _search_opencorporates(self, query, input_type, headers, findings, tool_run):
        """Search OpenCorporates for company connections."""
        try:
            if input_type == "full_name":
                url = f"https://api.opencorporates.com/v0.4/officers/search?q={urllib.parse.quote(query)}&per_page=10"
            else:
                url = f"https://api.opencorporates.com/v0.4/companies/search?q={urllib.parse.quote(query)}&per_page=10"

            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"OpenCorporates: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", {})

                if input_type == "full_name":
                    officers = results.get("officers", [])
                    for officer_data in officers[:10]:
                        officer = officer_data.get("officer", {})
                        name = officer.get("name", "")
                        position = officer.get("position", "")
                        company = officer.get("company", {})
                        company_name = company.get("name", "")
                        company_number = company.get("company_number", "")
                        jurisdiction = company.get("jurisdiction_code", "")

                        if company_name:
                            findings.append(Finding(
                                FindingType.EMPLOYER,
                                company_name,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "position": position,
                                    "company_number": company_number,
                                    "jurisdiction": jurisdiction,
                                    "officer_name": name,
                                    "source": "opencorporates",
                                },
                            ))
                else:
                    companies = results.get("companies", [])
                    for company_data in companies[:10]:
                        company = company_data.get("company", {})
                        name = company.get("name", "")
                        company_number = company.get("company_number", "")
                        jurisdiction = company.get("jurisdiction_code", "")
                        opencorporates_url = company.get("opencorporates_url", "")

                        if name:
                            findings.append(Finding(
                                FindingType.ORGANIZATION,
                                name,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "company_number": company_number,
                                    "jurisdiction": jurisdiction,
                                    "url": opencorporates_url,
                                    "source": "opencorporates",
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"OpenCorporates error: {e}\n"

    def _search_skymem(self, query, headers, findings, tool_run):
        """Search Skymem email search engine."""
        try:
            encoded = urllib.parse.quote_plus(query)
            url = f"https://www.skymem.info/srch?q={encoded}&ss=home"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"Skymem: {resp.status_code}\n"

            if resp.status_code == 200:
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", resp.text)
                for email in set(emails[:20]):
                    if email.lower() != query.lower():
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            email.lower(),
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "source": "skymem",
                                "searched_for": query,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"Skymem error: {e}\n"

    def _search_thatsthem(self, query, input_type, headers, findings, tool_run):
        """Search That's Them people search."""
        try:
            if input_type == "email":
                url = f"https://thatsthem.com/email/{urllib.parse.quote(query)}"
            elif input_type == "phone":
                url = f"https://thatsthem.com/phone/{urllib.parse.quote(query)}"
            elif input_type == "full_name":
                parts = query.split()
                if len(parts) >= 2:
                    url = f"https://thatsthem.com/name/{urllib.parse.quote(parts[0])}-{urllib.parse.quote(parts[-1])}"
                else:
                    return
            else:
                return

            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"ThatsThem: {resp.status_code}\n"

            if resp.status_code == 200:
                # Extract structured data from HTML
                name_matches = re.findall(r'<h2[^>]*class="[^"]*name[^"]*"[^>]*>(.*?)</h2>', resp.text, re.DOTALL)
                for name_html in name_matches[:5]:
                    name = re.sub(r"<[^>]+>", "", name_html).strip()
                    if name and len(name) > 3:
                        findings.append(Finding(
                            FindingType.PUBLIC_RECORD,
                            f"ThatsThem: {name}",
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "name": name,
                                "source": "thatsthem",
                                "target": query,
                                "url": url,
                            },
                        ))

                # Extract addresses
                addr_matches = re.findall(r'<span[^>]*class="[^"]*address[^"]*"[^>]*>(.*?)</span>', resp.text, re.DOTALL)
                for addr_html in addr_matches[:5]:
                    addr = re.sub(r"<[^>]+>", "", addr_html).strip()
                    if addr and len(addr) > 5:
                        findings.append(Finding(
                            FindingType.ADDRESS,
                            addr,
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={
                                "source": "thatsthem",
                                "target": query,
                            },
                        ))

                # Extract phone numbers
                phones = re.findall(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", resp.text)
                for phone in set(phones[:5]):
                    findings.append(Finding(
                        FindingType.RELATED_PHONE,
                        re.sub(r"[\s\-\.\(\)]", "", phone),
                        source_tool=self.name,
                        confidence=0.55,
                        metadata={"source": "thatsthem", "target": query},
                    ))

                # Extract emails
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", resp.text)
                for email in set(emails[:10]):
                    if email.lower() != query.lower():
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            email.lower(),
                            source_tool=self.name,
                            confidence=0.55,
                            metadata={"source": "thatsthem"},
                        ))

        except Exception as e:
            tool_run.raw_output += f"ThatsThem error: {e}\n"

    def _search_people_web(self, query, input_type, headers, findings, tool_run):
        """General people search via web."""
        try:
            if input_type == "full_name":
                dork = f'"{query}" resume OR cv OR linkedin OR profile'
            elif input_type == "email":
                dork = f'"{query}" profile OR about OR contact'
            elif input_type == "phone":
                dork = f'"{query}" name OR address OR owner'
            else:
                return

            encoded = urllib.parse.quote_plus(dork)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                links = self._extract_ddg_links(resp.text)
                for link in links[:10]:
                    findings.append(Finding(
                        FindingType.WEB_MENTION,
                        link,
                        source_tool=self.name,
                        confidence=0.5,
                        metadata={
                            "target": query,
                            "dork": dork,
                            "source": "web_people_search",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"People web search error: {e}\n"

    def _extract_ddg_links(self, html):
        """Extract actual URLs from DuckDuckGo HTML."""
        links = []
        for match in re.finditer(r'uddg=([^&"]+)', html):
            url = urllib.parse.unquote(match.group(1))
            if url.startswith("http") and "duckduckgo.com" not in url:
                links.append(url)
        return links

    def _extract_ddg_titles(self, html):
        """Extract titles from DuckDuckGo results."""
        titles = []
        for match in re.finditer(r'class="result__a"[^>]*>(.*?)</a>', html, re.DOTALL):
            title = re.sub(r"<[^>]+>", "", match.group(1)).strip()
            titles.append(title)
        return titles
