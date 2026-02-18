"""
Correlation engine V2 - massively upgraded intelligence graph builder.

Cross-references findings from all tools, generates derivative leads,
builds username/email/phone/domain variants, and scores leads for chaining.
"""
import re
from .models import Finding, FindingType


# Common free email providers for email generation
COMMON_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "aol.com", "icloud.com", "mail.com",
]

# Pages/paths to ignore when extracting usernames from URLs
IGNORE_USERNAMES = frozenset({
    "login", "signup", "about", "help", "settings", "home", "index",
    "search", "explore", "notifications", "messages", "privacy",
    "terms", "contact", "support", "legal", "blog", "press",
    "jobs", "careers", "api", "developers", "status", "security",
    "share", "embed", "watch", "channel", "playlist", "hashtag",
    "stories", "reels", "live", "static", "assets", "images",
    "p", "i", "s", "c", "r", "u", "t", "m",
})


class Correlator:
    """Cross-references findings to build intelligence graph."""

    def __init__(self, profile):
        self.profile = profile

    def correlate(self):
        """Run all correlation rules on current findings."""
        # Phase 1: Extract raw data into structured findings
        self._extract_usernames_from_profiles()
        self._extract_usernames_from_emails()
        self._extract_emails_from_raw()
        self._extract_emails_from_credentials()
        self._extract_phones_from_raw()
        self._extract_domains_from_emails()
        self._extract_names_from_metadata()
        self._extract_ips_from_raw()

        # Phase 2: Generate derivative leads (the 10x multiplier)
        self._generate_email_variants()
        self._generate_username_variants()
        self._infer_names_from_usernames()
        self._infer_names_from_emails()
        self._cross_reference_registered_sites()

        # Phase 3: Link everything together
        self._link_breach_to_email()
        self._link_credentials_to_breaches()
        self._link_profiles_to_usernames()
        self._link_emails_to_domains()
        self._link_names_across_findings()

        # Phase 4: Score and prioritize
        self._calculate_confidence_scores()
        self._score_leads()

        return self.profile

    # ---- Phase 1: Extraction ----

    def _extract_usernames_from_profiles(self):
        """Extract usernames from discovered social profile URLs."""
        profiles = self.profile.get_findings_by_type(FindingType.SOCIAL_PROFILE)
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.USERNAME, FindingType.RELATED_USERNAME)}

        for p in profiles:
            username = self._username_from_url(p.value)
            if username and len(username) > 1 and username.lower() not in existing:
                finding = Finding(
                    FindingType.RELATED_USERNAME,
                    username,
                    source_tool=f"correlator (from {p.source_tool})",
                    confidence=0.7,
                    metadata={"extracted_from": p.value},
                )
                finding.linked_to.append(p.id)
                self.profile.add_finding(finding)
                existing.add(username.lower())

    def _extract_usernames_from_emails(self):
        """Extract the local part of emails as potential usernames."""
        all_emails = (
            self.profile.get_findings_by_type(FindingType.EMAIL) +
            self.profile.get_findings_by_type(FindingType.RELATED_EMAIL)
        )
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.USERNAME, FindingType.RELATED_USERNAME)}

        for ef in all_emails:
            email = ef.value
            if "@" not in email:
                continue
            local_part = email.split("@")[0].lower()
            # Skip very short or numeric-only local parts
            if len(local_part) < 3 or local_part.isdigit():
                continue
            if local_part not in existing:
                finding = Finding(
                    FindingType.RELATED_USERNAME,
                    local_part,
                    source_tool="correlator (email→username)",
                    confidence=0.55,
                    metadata={"derived_from_email": email},
                )
                finding.linked_to.append(ef.id)
                self.profile.add_finding(finding)
                existing.add(local_part)

    def _extract_emails_from_raw(self):
        """Find email addresses in raw findings."""
        raw_findings = self.profile.get_findings_by_type(FindingType.RAW)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.EMAIL, FindingType.RELATED_EMAIL)}

        for raw in raw_findings:
            for email in email_pattern.findall(str(raw.value) + " " + str(raw.metadata)):
                if email.lower() not in existing:
                    finding = Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=f"correlator (from {raw.source_tool})",
                        confidence=0.6,
                    )
                    finding.linked_to.append(raw.id)
                    self.profile.add_finding(finding)
                    existing.add(email.lower())

    def _extract_emails_from_credentials(self):
        """Extract email addresses from leaked credential findings."""
        cred_findings = self.profile.get_findings_by_type(FindingType.LEAKED_CREDENTIAL)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.EMAIL, FindingType.RELATED_EMAIL)}

        for cred in cred_findings:
            text = f"{cred.value} {cred.metadata.get('identity', '')} {cred.metadata.get('email', '')} {cred.metadata.get('username', '')}"
            for email in email_pattern.findall(text):
                if email.lower() not in existing:
                    finding = Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=f"correlator (from {cred.source_tool})",
                        confidence=0.65,
                        metadata={"found_in_credential": True},
                    )
                    finding.linked_to.append(cred.id)
                    self.profile.add_finding(finding)
                    existing.add(email.lower())

    def _extract_phones_from_raw(self):
        """Find phone numbers in raw findings."""
        raw_findings = self.profile.get_findings_by_type(FindingType.RAW)
        phone_pattern = re.compile(r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}")
        existing = {f.value for f in self.profile.findings
                    if f.type in (FindingType.PHONE, FindingType.RELATED_PHONE)}

        for raw in raw_findings:
            for phone in phone_pattern.findall(str(raw.value)):
                cleaned = re.sub(r"[\s\-\.\(\)]", "", phone)
                if len(cleaned) >= 10 and cleaned not in existing:
                    finding = Finding(
                        FindingType.RELATED_PHONE,
                        cleaned,
                        source_tool=f"correlator (from {raw.source_tool})",
                        confidence=0.5,
                    )
                    finding.linked_to.append(raw.id)
                    self.profile.add_finding(finding)
                    existing.add(cleaned)

    def _extract_domains_from_emails(self):
        """Extract domains from email addresses for further investigation."""
        all_emails = (
            self.profile.get_findings_by_type(FindingType.EMAIL) +
            self.profile.get_findings_by_type(FindingType.RELATED_EMAIL)
        )
        existing_domains = {f.value.lower() for f in self.profile.findings
                           if f.type in (FindingType.DOMAIN, FindingType.RELATED_DOMAIN)}
        seed_domains = {v.lower() for v in self.profile.seeds.get("domain", []) if v} if isinstance(self.profile.seeds.get("domain"), list) else set()

        for ef in all_emails:
            if "@" not in ef.value:
                continue
            domain = ef.value.split("@")[1].lower()
            # Skip common free email providers — not interesting to investigate
            if domain in COMMON_EMAIL_DOMAINS:
                continue
            if domain not in existing_domains and domain not in seed_domains:
                finding = Finding(
                    FindingType.RELATED_DOMAIN,
                    domain,
                    source_tool="correlator (email→domain)",
                    confidence=0.6,
                    metadata={"extracted_from_email": ef.value},
                )
                finding.linked_to.append(ef.id)
                self.profile.add_finding(finding)
                existing_domains.add(domain)

    def _extract_names_from_metadata(self):
        """Extract full names from tool metadata (bios, profiles, breach data)."""
        existing_names = {f.value.lower() for f in self.profile.findings
                         if f.type == FindingType.FULL_NAME}

        for f in list(self.profile.findings):
            name = None
            if f.metadata.get("name"):
                name = f.metadata["name"]
            elif f.metadata.get("full_name"):
                name = f.metadata["full_name"]
            elif f.metadata.get("display_name"):
                name = f.metadata["display_name"]

            if name and isinstance(name, str) and len(name) > 3:
                name = name.strip()
                if name.lower() not in existing_names and " " in name:
                    finding = Finding(
                        FindingType.FULL_NAME,
                        name,
                        source_tool=f"correlator (from {f.source_tool})",
                        confidence=0.6,
                        metadata={"extracted_from": f.type},
                    )
                    finding.linked_to.append(f.id)
                    self.profile.add_finding(finding)
                    existing_names.add(name.lower())

    def _extract_ips_from_raw(self):
        """Extract IP addresses from raw findings."""
        raw_findings = self.profile.get_findings_by_type(FindingType.RAW)
        ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        existing = {f.value for f in self.profile.findings if f.type == FindingType.IP_ADDRESS}

        for raw in raw_findings:
            for ip in ip_pattern.findall(str(raw.value)):
                if ip not in existing and not ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "172.")):
                    finding = Finding(
                        FindingType.IP_ADDRESS,
                        ip,
                        source_tool=f"correlator (from {raw.source_tool})",
                        confidence=0.5,
                    )
                    finding.linked_to.append(raw.id)
                    self.profile.add_finding(finding)
                    existing.add(ip)

    # ---- Phase 2: Derivative lead generation (the 10x multiplier) ----

    def _generate_email_variants(self):
        """From a username, generate likely email addresses to check."""
        all_usernames = (
            self.profile.get_findings_by_type(FindingType.USERNAME) +
            self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        )
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.EMAIL, FindingType.RELATED_EMAIL)}

        # Only generate for seed usernames and high-confidence related ones
        for uf in all_usernames:
            if uf.confidence < 0.6:
                continue
            username = uf.value.lower()
            if len(username) < 3 or username.isdigit():
                continue

            # Generate email variants with top providers
            for domain in COMMON_EMAIL_DOMAINS[:4]:  # gmail, yahoo, hotmail, outlook
                email = f"{username}@{domain}"
                if email not in existing:
                    finding = Finding(
                        FindingType.RELATED_EMAIL,
                        email,
                        source_tool="correlator (username→email)",
                        confidence=0.35,
                        metadata={
                            "generated": True,
                            "from_username": username,
                            "needs_verification": True,
                        },
                    )
                    finding.linked_to.append(uf.id)
                    self.profile.add_finding(finding)
                    existing.add(email)

    def _generate_username_variants(self):
        """From usernames, generate common variants (dots, underscores, numbers)."""
        seed_usernames = self.profile.get_findings_by_type(FindingType.USERNAME)
        existing = {f.value.lower() for f in self.profile.findings
                    if f.type in (FindingType.USERNAME, FindingType.RELATED_USERNAME)}

        for uf in seed_usernames:
            username = uf.value.lower()
            variants = set()

            # john.doe → johndoe, john_doe, john-doe
            if "." in username:
                variants.add(username.replace(".", ""))
                variants.add(username.replace(".", "_"))
                variants.add(username.replace(".", "-"))
            # john_doe → johndoe, john.doe, john-doe
            if "_" in username:
                variants.add(username.replace("_", ""))
                variants.add(username.replace("_", "."))
                variants.add(username.replace("_", "-"))
            # johndoe → try with common separators if it looks like two words
            if not any(c in username for c in "._- ") and len(username) >= 6:
                # Try common split points (first+last name patterns)
                for i in range(3, len(username) - 2):
                    part1, part2 = username[:i], username[i:]
                    if part1.isalpha() and part2.isalpha():
                        variants.add(f"{part1}.{part2}")
                        variants.add(f"{part1}_{part2}")
                        break  # only try most likely split

            for variant in variants:
                if variant not in existing and variant != username:
                    finding = Finding(
                        FindingType.RELATED_USERNAME,
                        variant,
                        source_tool="correlator (username variant)",
                        confidence=0.4,
                        metadata={
                            "generated": True,
                            "variant_of": username,
                        },
                    )
                    finding.linked_to.append(uf.id)
                    self.profile.add_finding(finding)
                    existing.add(variant)

    def _infer_names_from_usernames(self):
        """Try to infer real names from username patterns."""
        all_usernames = (
            self.profile.get_findings_by_type(FindingType.USERNAME) +
            self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        )
        existing_names = {f.value.lower() for f in self.profile.findings
                         if f.type == FindingType.FULL_NAME}

        for uf in all_usernames:
            username = uf.value.lower()
            # Skip generated variants
            if uf.metadata.get("generated"):
                continue

            # Pattern: john.doe, john_doe, john-doe → John Doe
            for sep in [".", "_", "-"]:
                if sep in username:
                    parts = username.split(sep)
                    if len(parts) == 2 and all(p.isalpha() and len(p) >= 2 for p in parts):
                        name = f"{parts[0].title()} {parts[1].title()}"
                        if name.lower() not in existing_names:
                            finding = Finding(
                                FindingType.FULL_NAME,
                                name,
                                source_tool="correlator (username→name)",
                                confidence=0.35,
                                metadata={
                                    "inferred_from": username,
                                    "needs_verification": True,
                                },
                            )
                            finding.linked_to.append(uf.id)
                            self.profile.add_finding(finding)
                            existing_names.add(name.lower())
                    break

    def _infer_names_from_emails(self):
        """Try to infer real names from email local parts."""
        all_emails = self.profile.get_findings_by_type(FindingType.EMAIL)
        existing_names = {f.value.lower() for f in self.profile.findings
                         if f.type == FindingType.FULL_NAME}

        for ef in all_emails:
            if "@" not in ef.value:
                continue
            local = ef.value.split("@")[0].lower()
            # Strip trailing digits
            local = re.sub(r"\d+$", "", local)

            for sep in [".", "_", "-"]:
                if sep in local:
                    parts = local.split(sep)
                    if len(parts) == 2 and all(p.isalpha() and len(p) >= 2 for p in parts):
                        name = f"{parts[0].title()} {parts[1].title()}"
                        if name.lower() not in existing_names:
                            finding = Finding(
                                FindingType.FULL_NAME,
                                name,
                                source_tool="correlator (email→name)",
                                confidence=0.4,
                                metadata={"inferred_from": ef.value},
                            )
                            finding.linked_to.append(ef.id)
                            self.profile.add_finding(finding)
                            existing_names.add(name.lower())
                    break

    def _cross_reference_registered_sites(self):
        """If a site is registered, generate a profile URL to check."""
        registered = self.profile.get_findings_by_type(FindingType.REGISTERED_SITE)
        existing_profiles = {f.value.lower() for f in self.profile.findings
                            if f.type == FindingType.SOCIAL_PROFILE}
        all_usernames = (
            self.profile.get_findings_by_type(FindingType.USERNAME) +
            self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        )
        if not all_usernames:
            return

        # Map site names to URL patterns
        site_url_map = {
            "twitter": "https://twitter.com/{u}",
            "x": "https://x.com/{u}",
            "instagram": "https://instagram.com/{u}",
            "facebook": "https://facebook.com/{u}",
            "github": "https://github.com/{u}",
            "linkedin": "https://linkedin.com/in/{u}",
            "reddit": "https://reddit.com/user/{u}",
            "tiktok": "https://tiktok.com/@{u}",
            "pinterest": "https://pinterest.com/{u}",
            "tumblr": "https://{u}.tumblr.com",
            "medium": "https://medium.com/@{u}",
            "twitch": "https://twitch.tv/{u}",
            "snapchat": "https://snapchat.com/add/{u}",
            "spotify": "https://open.spotify.com/user/{u}",
            "steam": "https://steamcommunity.com/id/{u}",
            "discord": "https://discord.com/users/{u}",
        }

        primary_username = all_usernames[0].value

        for site_finding in registered:
            site_name = site_finding.value.lower().strip()
            for key, url_template in site_url_map.items():
                if key in site_name:
                    url = url_template.format(u=primary_username)
                    if url.lower() not in existing_profiles:
                        finding = Finding(
                            FindingType.SOCIAL_PROFILE,
                            url,
                            source_tool="correlator (site→profile)",
                            confidence=0.5,
                            metadata={
                                "generated": True,
                                "site": site_name,
                                "username": primary_username,
                            },
                        )
                        self.profile.add_finding(finding)
                        existing_profiles.add(url.lower())
                    break

    # ---- Phase 3: Link everything ----

    def _link_breach_to_email(self):
        """Link breach findings to the email they were found for."""
        breaches = self.profile.get_findings_by_type(FindingType.BREACH)
        emails = self.profile.get_findings_by_type(FindingType.EMAIL)
        for breach in breaches:
            breach_email = breach.metadata.get("email")
            if breach_email:
                for email_finding in emails:
                    if email_finding.value.lower() == breach_email.lower():
                        if email_finding.id not in breach.linked_to:
                            breach.linked_to.append(email_finding.id)

    def _link_credentials_to_breaches(self):
        """Link leaked credentials to their associated breaches and emails."""
        credentials = self.profile.get_findings_by_type(FindingType.LEAKED_CREDENTIAL)
        breaches = self.profile.get_findings_by_type(FindingType.BREACH)
        emails = self.profile.get_findings_by_type(FindingType.EMAIL)

        for cred in credentials:
            cred_email = cred.metadata.get("email", cred.metadata.get("identity", ""))
            if cred_email:
                for email_finding in emails:
                    if email_finding.value.lower() == cred_email.lower():
                        if email_finding.id not in cred.linked_to:
                            cred.linked_to.append(email_finding.id)

            cred_breach = cred.metadata.get("breach", "")
            if cred_breach:
                for breach in breaches:
                    if cred_breach.lower() in breach.value.lower() or breach.value.lower() in cred_breach.lower():
                        if breach.id not in cred.linked_to:
                            cred.linked_to.append(breach.id)

    def _link_profiles_to_usernames(self):
        """Link social profiles to their usernames."""
        profiles = self.profile.get_findings_by_type(FindingType.SOCIAL_PROFILE)
        usernames = (
            self.profile.get_findings_by_type(FindingType.USERNAME) +
            self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        )
        for profile in profiles:
            url_username = self._username_from_url(profile.value)
            if url_username:
                for un in usernames:
                    if un.value.lower() == url_username.lower():
                        if un.id not in profile.linked_to:
                            profile.linked_to.append(un.id)

    def _link_emails_to_domains(self):
        """Link email findings to their domain findings."""
        all_emails = (
            self.profile.get_findings_by_type(FindingType.EMAIL) +
            self.profile.get_findings_by_type(FindingType.RELATED_EMAIL)
        )
        domains = (
            self.profile.get_findings_by_type(FindingType.DOMAIN) +
            self.profile.get_findings_by_type(FindingType.RELATED_DOMAIN)
        )

        for ef in all_emails:
            if "@" not in ef.value:
                continue
            email_domain = ef.value.split("@")[1].lower()
            for df in domains:
                if df.value.lower() == email_domain:
                    if df.id not in ef.linked_to:
                        ef.linked_to.append(df.id)

    def _link_names_across_findings(self):
        """Link name findings to profiles, emails, and credentials that mention the same name."""
        names = self.profile.get_findings_by_type(FindingType.FULL_NAME)
        if not names:
            return

        for name_finding in names:
            name_lower = name_finding.value.lower()
            name_parts = name_lower.split()

            for f in self.profile.findings:
                if f.id == name_finding.id:
                    continue
                # Check metadata for name matches
                meta_str = str(f.metadata).lower()
                val_str = str(f.value).lower()
                combined = meta_str + " " + val_str

                if name_lower in combined:
                    if f.id not in name_finding.linked_to:
                        name_finding.linked_to.append(f.id)
                elif len(name_parts) >= 2:
                    # Check if both first and last name appear
                    if all(part in combined for part in name_parts):
                        if f.id not in name_finding.linked_to:
                            name_finding.linked_to.append(f.id)

    # ---- Phase 4: Scoring ----

    def _calculate_confidence_scores(self):
        """Boost confidence for findings corroborated by multiple tools."""
        value_sources = {}
        for f in self.profile.findings:
            key = (f.type, f.value.lower() if isinstance(f.value, str) else f.value)
            if key not in value_sources:
                value_sources[key] = set()
            value_sources[key].add(f.source_tool)

        for f in self.profile.findings:
            key = (f.type, f.value.lower() if isinstance(f.value, str) else f.value)
            num_sources = len(value_sources.get(key, set()))
            if num_sources > 1:
                f.confidence = min(1.0, f.confidence + 0.1 * (num_sources - 1))

    def _score_leads(self):
        """Score leads in the discovery queue by potential value."""
        # Boost confidence on findings that are linked to many others
        link_counts = {}
        for f in self.profile.findings:
            for linked_id in f.linked_to:
                link_counts[linked_id] = link_counts.get(linked_id, 0) + 1

        for f in self.profile.findings:
            incoming_links = link_counts.get(f.id, 0)
            if incoming_links > 2:
                f.confidence = min(1.0, f.confidence + 0.05 * incoming_links)

    # ---- Utility ----

    def _username_from_url(self, url):
        """Extract username from common social media URL patterns."""
        patterns = [
            r"(?:twitter|x)\.com/([^/?#]+)",
            r"instagram\.com/([^/?#]+)",
            r"facebook\.com/([^/?#]+)",
            r"github\.com/([^/?#]+)",
            r"linkedin\.com/in/([^/?#]+)",
            r"reddit\.com/u(?:ser)?/([^/?#]+)",
            r"tiktok\.com/@?([^/?#]+)",
            r"youtube\.com/@?([^/?#]+)",
            r"pinterest\.com/([^/?#]+)",
            r"medium\.com/@?([^/?#]+)",
            r"t\.me/([^/?#]+)",
            r"snapchat\.com/add/([^/?#]+)",
            r"twitch\.tv/([^/?#]+)",
            r"steamcommunity\.com/id/([^/?#]+)",
            r"open\.spotify\.com/user/([^/?#]+)",
            r"soundcloud\.com/([^/?#]+)",
            r"vimeo\.com/([^/?#]+)",
            r"flickr\.com/photos/([^/?#]+)",
            r"behance\.net/([^/?#]+)",
            r"dribbble\.com/([^/?#]+)",
            r"keybase\.io/([^/?#]+)",
            r"hackerone\.com/([^/?#]+)",
            r"bugcrowd\.com/([^/?#]+)",
            r"dev\.to/([^/?#]+)",
            r"mastodon\.\w+/@?([^/?#]+)",
            r"gitlab\.com/([^/?#]+)",
            r"bitbucket\.org/([^/?#]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                username = match.group(1).lstrip("@")
                if username.lower() not in IGNORE_USERNAMES:
                    return username
        return None

    # ---- Recommendations ----

    def get_tool_recommendations(self):
        """Recommend tools to run next based on current findings — much more aggressive."""
        recommendations = []
        completed_runs = {f"{tr.tool_name}:{tr.input_value}" for tr in self.profile.tool_runs}

        # Email tools
        all_emails = (
            self.profile.get_findings_by_type(FindingType.EMAIL) +
            self.profile.get_findings_by_type(FindingType.RELATED_EMAIL)
        )
        email_tools = [
            "holehe", "h8mail", "xposedornot", "cr3dov3r", "emailrep",
            "hudsonrock", "breachdirectory", "leakcheck", "dehashed_free",
            "psbdmp", "intelx_phonebook", "socialscan",
        ]
        for em in all_emails:
            # Skip generated/low-confidence emails unless they come from a tool
            if em.metadata.get("generated") and em.confidence < 0.5:
                continue
            for tool in email_tools:
                if f"{tool}:{em.value}" not in completed_runs:
                    recommendations.append({
                        "tool": tool,
                        "input_type": "email",
                        "input_value": em.value,
                        "reason": f"Email {em.value} → {tool}",
                        "priority": 1 if em.type == FindingType.EMAIL else 2,
                    })

        # Username tools
        all_usernames = (
            self.profile.get_findings_by_type(FindingType.USERNAME) +
            self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        )
        username_tools = [
            "sherlock", "maigret", "blackbird", "nexfil",
            "social_analyzer", "leaksearch", "comb2passlist", "socialscan",
        ]
        for un in all_usernames:
            if un.metadata.get("generated") and un.confidence < 0.5:
                continue
            for tool in username_tools:
                if f"{tool}:{un.value}" not in completed_runs:
                    recommendations.append({
                        "tool": tool,
                        "input_type": "username",
                        "input_value": un.value,
                        "reason": f"Username {un.value} → {tool}",
                        "priority": 1 if un.type == FindingType.USERNAME else 2,
                    })

        # Phone tools
        all_phones = (
            self.profile.get_findings_by_type(FindingType.PHONE) +
            self.profile.get_findings_by_type(FindingType.RELATED_PHONE)
        )
        phone_tools = ["phoneinfoga", "ignorant"]
        for phone in all_phones:
            for tool in phone_tools:
                if f"{tool}:{phone.value}" not in completed_runs:
                    recommendations.append({
                        "tool": tool,
                        "input_type": "phone",
                        "input_value": phone.value,
                        "reason": f"Phone {phone.value} → {tool}",
                        "priority": 1,
                    })

        # Domain tools
        all_domains = (
            self.profile.get_findings_by_type(FindingType.DOMAIN) +
            self.profile.get_findings_by_type(FindingType.RELATED_DOMAIN)
        )
        domain_tools = ["theharvester", "photon", "spiderfoot", "intelx_phonebook"]
        for dom in all_domains:
            for tool in domain_tools:
                if f"{tool}:{dom.value}" not in completed_runs:
                    recommendations.append({
                        "tool": tool,
                        "input_type": "domain",
                        "input_value": dom.value,
                        "reason": f"Domain {dom.value} → {tool}",
                        "priority": 2,
                    })

        # Sort by priority
        recommendations.sort(key=lambda r: r.get("priority", 99))
        return recommendations
