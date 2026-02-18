"""Threat Intelligence Enrichment - VirusTotal, AbuseIPDB, AlienVault OTX, Shodan."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class ThreatIntelTool(ToolWrapper):
    name = "threat_intel"
    description = "Threat intelligence enrichment - VirusTotal, AbuseIPDB, AlienVault OTX, URLScan for domains and IPs"
    accepts_input = ["domain", "email"]
    category = "recon"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        domain = input_value
        if input_type == "email" and "@" in input_value:
            domain = input_value.split("@")[1]

        # VirusTotal (free: 4 requests/min)
        self._search_virustotal(domain, headers, findings, tool_run)

        # AlienVault OTX (free, no API key needed for basic queries)
        self._search_alienvault_otx(domain, headers, findings, tool_run)

        # URLScan.io (free)
        self._search_urlscan(domain, headers, findings, tool_run)

        # ThreatCrowd (free)
        self._search_threatcrowd(domain, headers, findings, tool_run)

        # Resolve domain to IP and check AbuseIPDB
        ip = self._resolve_domain(domain)
        if ip:
            self._search_abuseipdb(ip, headers, findings, tool_run)
            self._search_ipinfo(ip, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.type}:{f.value}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _resolve_domain(self, domain):
        """Resolve domain to IP."""
        try:
            resp = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=5)
            if resp.status_code == 200:
                answers = resp.json().get("Answer", [])
                for a in answers:
                    data = a.get("data", "")
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", data):
                        return data
        except Exception:
            pass
        return None

    def _search_virustotal(self, domain, headers, findings, tool_run):
        """Search VirusTotal for domain reputation."""
        try:
            # VirusTotal v3 requires API key, but v2 has some free endpoints
            # Use the community endpoint
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            # Without API key, try the web scraping approach
            web_url = f"https://www.virustotal.com/gui/domain/{domain}/detection"

            findings.append(Finding(
                FindingType.WEB_MENTION,
                web_url,
                source_tool=self.name,
                confidence=0.5,
                metadata={
                    "type": "virustotal_report",
                    "domain": domain,
                    "note": "Open to see full VirusTotal report",
                },
            ))

            # Try community API (limited)
            api_url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}"
            resp = requests.get(api_url, headers=headers, timeout=10)
            tool_run.raw_output += f"VirusTotal: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()

                # Extract subdomains
                subdomains = data.get("subdomains", [])
                for sub in subdomains[:30]:
                    findings.append(Finding(
                        FindingType.SUBDOMAIN,
                        sub,
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={"source": "virustotal", "parent_domain": domain},
                    ))

                # Extract related URLs
                detected_urls = data.get("detected_urls", [])
                for url_entry in detected_urls[:10]:
                    if isinstance(url_entry, dict):
                        findings.append(Finding(
                            FindingType.RAW,
                            f"Malicious URL: {url_entry.get('url', '')}",
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "type": "malicious_url",
                                "positives": url_entry.get("positives", 0),
                                "total": url_entry.get("total", 0),
                                "scan_date": url_entry.get("scan_date", ""),
                            },
                        ))

                # WHOIS info
                whois = data.get("whois", "")
                if whois:
                    # Extract emails from WHOIS
                    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", whois)
                    for email in set(emails):
                        findings.append(Finding(
                            FindingType.RELATED_EMAIL,
                            email.lower(),
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"source": "virustotal_whois"},
                        ))

                    # Extract registrant info
                    registrant = re.search(r"Registrant[^:]*:\s*(.+)", whois)
                    if registrant:
                        findings.append(Finding(
                            FindingType.RAW,
                            f"Registrant: {registrant.group(1).strip()}",
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={"source": "virustotal_whois", "type": "registrant"},
                        ))

        except Exception as e:
            tool_run.raw_output += f"VirusTotal error: {e}\n"

    def _search_alienvault_otx(self, domain, headers, findings, tool_run):
        """Search AlienVault OTX for threat intelligence."""
        try:
            # General info
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"OTX general: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                alexa_rank = data.get("alexa", "")
                whois = data.get("whois", "")

                if pulse_count > 0:
                    findings.append(Finding(
                        FindingType.RAW,
                        f"OTX: {domain} appears in {pulse_count} threat pulses",
                        source_tool=self.name,
                        confidence=0.75,
                        metadata={
                            "type": "threat_pulse",
                            "domain": domain,
                            "pulse_count": pulse_count,
                            "source": "alienvault_otx",
                        },
                    ))

                # Passive DNS
                time.sleep(0.5)
                dns_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                dns_resp = requests.get(dns_url, headers={
                    **headers,
                    "Accept": "application/json",
                }, timeout=15)

                if dns_resp.status_code == 200:
                    dns_data = dns_resp.json()
                    records = dns_data.get("passive_dns", [])
                    seen_ips = set()

                    for record in records[:20]:
                        ip = record.get("address", "")
                        hostname = record.get("hostname", "")
                        record_type = record.get("record_type", "")
                        first_seen = record.get("first", "")
                        last_seen = record.get("last", "")

                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            findings.append(Finding(
                                FindingType.IP_ADDRESS,
                                ip,
                                source_tool=self.name,
                                confidence=0.75,
                                metadata={
                                    "source": "otx_passive_dns",
                                    "hostname": hostname,
                                    "record_type": record_type,
                                    "first_seen": first_seen,
                                    "last_seen": last_seen,
                                },
                            ))

                # URL list
                time.sleep(0.5)
                url_list = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
                url_resp = requests.get(url_list, headers={
                    **headers,
                    "Accept": "application/json",
                }, timeout=15)

                if url_resp.status_code == 200:
                    url_data = url_resp.json()
                    urls = url_data.get("url_list", [])
                    for url_entry in urls[:10]:
                        detected_url = url_entry.get("url", "")
                        if detected_url:
                            findings.append(Finding(
                                FindingType.WEB_MENTION,
                                detected_url,
                                source_tool=self.name,
                                confidence=0.6,
                                metadata={
                                    "source": "otx_url_list",
                                    "domain": domain,
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"OTX error: {e}\n"

    def _search_urlscan(self, domain, headers, findings, tool_run):
        """Search URLScan.io for domain scan results."""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"URLScan: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])

                for result in results[:10]:
                    page = result.get("page", {})
                    task = result.get("task", {})
                    scan_url = page.get("url", "")
                    server = page.get("server", "")
                    ip = page.get("ip", "")
                    country = page.get("country", "")
                    asn = page.get("asn", "")
                    result_url = result.get("result", "")

                    if result_url:
                        findings.append(Finding(
                            FindingType.WEB_MENTION,
                            result_url,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "source": "urlscan",
                                "scanned_url": scan_url,
                                "server": server,
                                "ip": ip,
                                "country": country,
                                "asn": asn,
                            },
                        ))

                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        findings.append(Finding(
                            FindingType.IP_ADDRESS,
                            ip,
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={
                                "source": "urlscan",
                                "domain": domain,
                                "country": country,
                                "asn": asn,
                            },
                        ))

                    if server:
                        findings.append(Finding(
                            FindingType.TECHNOLOGY,
                            f"Server: {server}",
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"source": "urlscan", "domain": domain},
                        ))

        except Exception as e:
            tool_run.raw_output += f"URLScan error: {e}\n"

    def _search_threatcrowd(self, domain, headers, findings, tool_run):
        """Search ThreatCrowd for domain intelligence."""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"ThreatCrowd: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()

                # Subdomains
                subdomains = data.get("subdomains", [])
                for sub in subdomains[:20]:
                    findings.append(Finding(
                        FindingType.SUBDOMAIN,
                        sub,
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"source": "threatcrowd"},
                    ))

                # Emails
                emails = data.get("emails", [])
                for email in emails[:10]:
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email.lower(),
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={"source": "threatcrowd"},
                    ))

                # Resolutions (IP history)
                resolutions = data.get("resolutions", [])
                for res in resolutions[:10]:
                    ip = res.get("ip_address", "")
                    last_resolved = res.get("last_resolved", "")
                    if ip:
                        findings.append(Finding(
                            FindingType.IP_ADDRESS,
                            ip,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "source": "threatcrowd",
                                "last_resolved": last_resolved,
                                "domain": domain,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"ThreatCrowd error: {e}\n"

    def _search_abuseipdb(self, ip, headers, findings, tool_run):
        """Search AbuseIPDB for IP reputation."""
        try:
            # AbuseIPDB requires API key for full access, but check endpoint exists
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            # Without API key, provide the link
            findings.append(Finding(
                FindingType.WEB_MENTION,
                f"https://www.abuseipdb.com/check/{ip}",
                source_tool=self.name,
                confidence=0.5,
                metadata={
                    "type": "abuse_report_url",
                    "ip": ip,
                    "note": "Check AbuseIPDB for abuse reports on this IP",
                },
            ))

        except Exception as e:
            tool_run.raw_output += f"AbuseIPDB error: {e}\n"

    def _search_ipinfo(self, ip, headers, findings, tool_run):
        """Get IP geolocation and ASN info from ipinfo.io (free tier)."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"ipinfo: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                city = data.get("city", "")
                region = data.get("region", "")
                country = data.get("country", "")
                org = data.get("org", "")
                loc = data.get("loc", "")
                hostname = data.get("hostname", "")

                location_str = ", ".join(filter(None, [city, region, country]))
                if location_str:
                    findings.append(Finding(
                        FindingType.LOCATION,
                        f"IP {ip}: {location_str}",
                        source_tool=self.name,
                        confidence=0.7,
                        metadata={
                            "ip": ip,
                            "city": city,
                            "region": region,
                            "country": country,
                            "org": org,
                            "coordinates": loc,
                            "hostname": hostname,
                            "source": "ipinfo",
                        },
                    ))

                if org:
                    findings.append(Finding(
                        FindingType.ORGANIZATION,
                        org,
                        source_tool=self.name,
                        confidence=0.65,
                        metadata={
                            "ip": ip,
                            "type": "hosting_provider",
                            "source": "ipinfo",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"ipinfo error: {e}\n"
