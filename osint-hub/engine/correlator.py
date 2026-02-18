"""
Correlation engine that cross-references findings from all tools.
Builds a knowledge graph linking identifiers to profiles, accounts, and breaches.
"""
import re
from .models import Finding, FindingType


class Correlator:
    """Cross-references findings to build intelligence."""

    def __init__(self, profile):
        self.profile = profile

    def correlate(self):
        """Run all correlation rules on current findings."""
        self._extract_usernames_from_profiles()
        self._extract_emails_from_raw()
        self._extract_emails_from_credentials()
        self._extract_phones_from_raw()
        self._link_breach_to_email()
        self._link_credentials_to_breaches()
        self._link_profiles_to_usernames()
        self._calculate_confidence_scores()
        return self.profile

    def _extract_usernames_from_profiles(self):
        """Extract usernames from discovered social profile URLs."""
        profiles = self.profile.get_findings_by_type(FindingType.SOCIAL_PROFILE)
        for p in profiles:
            url = p.value
            username = self._username_from_url(url)
            if username and len(username) > 2:
                existing = [f.value for f in self.profile.findings if f.type == FindingType.RELATED_USERNAME]
                if username not in existing:
                    finding = Finding(
                        FindingType.RELATED_USERNAME,
                        username,
                        source_tool=f"correlator (from {p.source_tool})",
                        confidence=0.7,
                        metadata={"extracted_from": url},
                    )
                    finding.linked_to.append(p.id)
                    self.profile.add_finding(finding)

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
        ]
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                username = match.group(1)
                if username not in ("login", "signup", "about", "help", "settings"):
                    return username
        return None

    def _extract_emails_from_raw(self):
        """Find email addresses in raw findings."""
        raw_findings = self.profile.get_findings_by_type(FindingType.RAW)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        existing_emails = {f.value.lower() for f in self.profile.findings
                          if f.type in (FindingType.EMAIL, FindingType.RELATED_EMAIL)}
        for raw in raw_findings:
            emails = email_pattern.findall(str(raw.value))
            for email in emails:
                if email.lower() not in existing_emails:
                    finding = Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=f"correlator (from {raw.source_tool})",
                        confidence=0.6,
                    )
                    finding.linked_to.append(raw.id)
                    self.profile.add_finding(finding)
                    existing_emails.add(email.lower())

    def _extract_emails_from_credentials(self):
        """Extract email addresses from leaked credential findings."""
        cred_findings = self.profile.get_findings_by_type(FindingType.LEAKED_CREDENTIAL)
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        existing_emails = {f.value.lower() for f in self.profile.findings
                          if f.type in (FindingType.EMAIL, FindingType.RELATED_EMAIL)}
        for cred in cred_findings:
            # Check both the value and the identity metadata
            text_to_check = str(cred.value)
            identity = cred.metadata.get("identity", "")
            if identity:
                text_to_check += " " + identity

            emails = email_pattern.findall(text_to_check)
            for email in emails:
                if email.lower() not in existing_emails:
                    finding = Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=f"correlator (from {cred.source_tool})",
                        confidence=0.65,
                        metadata={"found_in_credential": True},
                    )
                    finding.linked_to.append(cred.id)
                    self.profile.add_finding(finding)
                    existing_emails.add(email.lower())

    def _extract_phones_from_raw(self):
        """Find phone numbers in raw findings."""
        raw_findings = self.profile.get_findings_by_type(FindingType.RAW)
        phone_pattern = re.compile(r"\+?1?\d{10,15}")
        existing_phones = {f.value for f in self.profile.findings
                          if f.type in (FindingType.PHONE, FindingType.RELATED_PHONE)}
        for raw in raw_findings:
            phones = phone_pattern.findall(str(raw.value))
            for phone in phones:
                if phone not in existing_phones and len(phone) >= 10:
                    finding = Finding(
                        FindingType.RELATED_PHONE,
                        phone,
                        source_tool=f"correlator (from {raw.source_tool})",
                        confidence=0.5,
                    )
                    finding.linked_to.append(raw.id)
                    self.profile.add_finding(finding)
                    existing_phones.add(phone)

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

            # Link to matching email findings
            if cred_email:
                for email_finding in emails:
                    if email_finding.value.lower() == cred_email.lower():
                        if email_finding.id not in cred.linked_to:
                            cred.linked_to.append(email_finding.id)

            # Link to matching breach findings
            cred_breach = cred.metadata.get("breach", "")
            if cred_breach:
                for breach in breaches:
                    if cred_breach.lower() in breach.value.lower() or breach.value.lower() in cred_breach.lower():
                        if breach.id not in cred.linked_to:
                            cred.linked_to.append(breach.id)

    def _link_profiles_to_usernames(self):
        """Link social profiles to their usernames."""
        profiles = self.profile.get_findings_by_type(FindingType.SOCIAL_PROFILE)
        usernames = self.profile.get_findings_by_type(FindingType.USERNAME) + \
                    self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        for profile in profiles:
            url_username = self._username_from_url(profile.value)
            if url_username:
                for un in usernames:
                    if un.value.lower() == url_username.lower():
                        if un.id not in profile.linked_to:
                            profile.linked_to.append(un.id)

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

    def get_tool_recommendations(self):
        """Based on current findings, recommend which tools to run next."""
        recommendations = []
        completed_tools = {tr.tool_name for tr in self.profile.tool_runs}

        # If we have emails but haven't run holehe
        emails = self.profile.get_findings_by_type(FindingType.EMAIL)
        related_emails = self.profile.get_findings_by_type(FindingType.RELATED_EMAIL)
        all_emails = emails + related_emails

        if all_emails:
            email_tools = ["holehe", "h8mail", "xposedornot", "cr3dov3r"]
            for tool in email_tools:
                for em in all_emails:
                    run_key = f"{tool}:{em.value}"
                    if run_key not in {f"{tr.tool_name}:{tr.input_value}" for tr in self.profile.tool_runs}:
                        recommendations.append({
                            "tool": tool,
                            "input_type": "email",
                            "input_value": em.value,
                            "reason": f"Found email {em.value} - check with {tool}",
                        })

        # If we have usernames but haven't run username tools
        usernames = self.profile.get_findings_by_type(FindingType.USERNAME)
        related_usernames = self.profile.get_findings_by_type(FindingType.RELATED_USERNAME)
        all_usernames = usernames + related_usernames

        if all_usernames:
            username_tools = ["sherlock", "maigret", "blackbird", "nexfil", "social_analyzer"]
            for tool in username_tools:
                for un in all_usernames:
                    run_key = f"{tool}:{un.value}"
                    if run_key not in {f"{tr.tool_name}:{tr.input_value}" for tr in self.profile.tool_runs}:
                        recommendations.append({
                            "tool": tool,
                            "input_type": "username",
                            "input_value": un.value,
                            "reason": f"Found username {un.value} - check with {tool}",
                        })

        # If we have phone numbers
        phones = self.profile.get_findings_by_type(FindingType.PHONE)
        related_phones = self.profile.get_findings_by_type(FindingType.RELATED_PHONE)
        all_phones = phones + related_phones

        if all_phones:
            for phone in all_phones:
                run_key = f"phoneinfoga:{phone.value}"
                if run_key not in {f"{tr.tool_name}:{tr.input_value}" for tr in self.profile.tool_runs}:
                    recommendations.append({
                        "tool": "phoneinfoga",
                        "input_type": "phone",
                        "input_value": phone.value,
                        "reason": f"Found phone {phone.value} - check with phoneinfoga",
                    })

        return recommendations
