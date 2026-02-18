"""DNS/WHOIS/Certificate Transparency deep reconnaissance tool."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class DnsReconTool(ToolWrapper):
    name = "dns_recon"
    description = "DNS records, WHOIS, Certificate Transparency, subdomain enumeration, and infrastructure mapping"
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

        # Certificate Transparency via crt.sh (free, no auth)
        self._search_crtsh(domain, headers, findings, tool_run)

        # DNS records via dns.google
        self._search_dns_google(domain, headers, findings, tool_run)

        # SecurityTrails (free tier)
        self._search_securitytrails(domain, headers, findings, tool_run)

        # Shodan InternetDB (free, no API key)
        self._search_shodan_internetdb(domain, headers, findings, tool_run)

        # Censys search (free tier)
        self._search_censys(domain, headers, findings, tool_run)

        # ViewDNS.info
        self._search_viewdns(domain, headers, findings, tool_run)

        # HackerTarget (free tier)
        self._search_hackertarget(domain, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.type}:{f.value}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _search_crtsh(self, domain, headers, findings, tool_run):
        """Search crt.sh Certificate Transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, headers=headers, timeout=30)
            tool_run.raw_output += f"crt.sh: {resp.status_code}\n"

            if resp.status_code == 200:
                certs = resp.json()
                subdomains = set()
                emails_found = set()

                for cert in certs:
                    name_value = cert.get("name_value", "")
                    issuer = cert.get("issuer_name", "")
                    not_before = cert.get("not_before", "")
                    not_after = cert.get("not_after", "")
                    common_name = cert.get("common_name", "")

                    # Extract subdomains from certificate names
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and domain in name and name != domain:
                            if "*" not in name:
                                subdomains.add(name)

                    if common_name and domain in common_name.lower() and common_name.lower() != domain:
                        subdomains.add(common_name.lower())

                    # Look for emails in issuer
                    cert_emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", issuer)
                    for email in cert_emails:
                        emails_found.add(email.lower())

                tool_run.raw_output += f"crt.sh subdomains: {len(subdomains)}\n"

                for subdomain in subdomains:
                    findings.append(Finding(
                        FindingType.SUBDOMAIN,
                        subdomain,
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "source": "certificate_transparency",
                            "parent_domain": domain,
                        },
                    ))

                for email in emails_found:
                    findings.append(Finding(
                        FindingType.RELATED_EMAIL,
                        email,
                        source_tool=self.name,
                        confidence=0.6,
                        metadata={"source": "certificate_issuer"},
                    ))

                # Add certificate finding
                if certs:
                    findings.append(Finding(
                        FindingType.CERTIFICATE,
                        f"{len(certs)} certificates found for {domain}",
                        source_tool=self.name,
                        confidence=0.9,
                        metadata={
                            "total_certs": len(certs),
                            "unique_subdomains": len(subdomains),
                            "domain": domain,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"crt.sh error: {e}\n"

    def _search_dns_google(self, domain, headers, findings, tool_run):
        """Query Google DNS API for various record types."""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                resp = requests.get(url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])

                    for answer in answers:
                        record_data = answer.get("data", "")
                        record_name = answer.get("name", "")
                        record_type = answer.get("type", "")

                        findings.append(Finding(
                            FindingType.DNS_RECORD,
                            f"{rtype}: {record_data}",
                            source_tool=self.name,
                            confidence=0.95,
                            metadata={
                                "record_type": rtype,
                                "name": record_name,
                                "data": record_data,
                                "domain": domain,
                            },
                        ))

                        # Extract IPs
                        if rtype in ("A", "AAAA"):
                            findings.append(Finding(
                                FindingType.IP_ADDRESS,
                                record_data,
                                source_tool=self.name,
                                confidence=0.95,
                                metadata={
                                    "record_type": rtype,
                                    "domain": domain,
                                },
                            ))

                        # Extract email servers from MX
                        if rtype == "MX":
                            mx_domain = record_data.split()[-1].rstrip(".")
                            findings.append(Finding(
                                FindingType.RELATED_DOMAIN,
                                mx_domain,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "type": "mail_server",
                                    "mx_record": record_data,
                                },
                            ))

                        # Extract info from TXT records (SPF, DMARC, verification tokens)
                        if rtype == "TXT":
                            txt_emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", record_data)
                            for email in txt_emails:
                                findings.append(Finding(
                                    FindingType.RELATED_EMAIL,
                                    email.lower(),
                                    source_tool=self.name,
                                    confidence=0.7,
                                    metadata={"source": "dns_txt_record"},
                                ))

                time.sleep(0.2)

            except Exception as e:
                tool_run.raw_output += f"DNS {rtype} error: {e}\n"

    def _search_securitytrails(self, domain, headers, findings, tool_run):
        """Search SecurityTrails for subdomains and historical data."""
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
                "APIKEY": "",  # Free tier with empty key sometimes works for basic queries
            }, timeout=15)
            tool_run.raw_output += f"SecurityTrails: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                subdomains = data.get("subdomains", [])
                for sub in subdomains[:50]:
                    full_domain = f"{sub}.{domain}"
                    findings.append(Finding(
                        FindingType.SUBDOMAIN,
                        full_domain,
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "source": "securitytrails",
                            "parent_domain": domain,
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"SecurityTrails error: {e}\n"

    def _search_shodan_internetdb(self, domain, headers, findings, tool_run):
        """Use Shodan InternetDB (free, no API key) for basic host info."""
        try:
            # First resolve the domain to IP
            dns_url = f"https://dns.google/resolve?name={domain}&type=A"
            dns_resp = requests.get(dns_url, timeout=10)
            if dns_resp.status_code != 200:
                return

            dns_data = dns_resp.json()
            answers = dns_data.get("Answer", [])
            for answer in answers:
                ip = answer.get("data", "")
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    continue

                url = f"https://internetdb.shodan.io/{ip}"
                resp = requests.get(url, headers=headers, timeout=10)
                tool_run.raw_output += f"Shodan InternetDB ({ip}): {resp.status_code}\n"

                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    hostnames = data.get("hostnames", [])
                    tags = data.get("tags", [])
                    cpes = data.get("cpes", [])

                    # Port findings
                    if ports:
                        findings.append(Finding(
                            FindingType.DNS_RECORD,
                            f"Open ports on {ip}: {', '.join(str(p) for p in ports)}",
                            source_tool=self.name,
                            confidence=0.85,
                            metadata={
                                "ip": ip,
                                "ports": ports,
                                "source": "shodan_internetdb",
                            },
                        ))

                    # Vulnerability findings
                    for vuln in vulns[:10]:
                        findings.append(Finding(
                            FindingType.RAW,
                            f"Vulnerability {vuln} on {ip}",
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={
                                "ip": ip,
                                "cve": vuln,
                                "type": "vulnerability",
                                "source": "shodan_internetdb",
                            },
                        ))

                    # Additional hostnames
                    for hostname in hostnames:
                        if domain in hostname and hostname != domain:
                            findings.append(Finding(
                                FindingType.SUBDOMAIN,
                                hostname,
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={"source": "shodan_internetdb", "ip": ip},
                            ))

                    # Technologies
                    for cpe in cpes[:10]:
                        findings.append(Finding(
                            FindingType.TECHNOLOGY,
                            cpe,
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={"ip": ip, "source": "shodan_internetdb"},
                        ))

                break  # Only check first IP

        except Exception as e:
            tool_run.raw_output += f"Shodan InternetDB error: {e}\n"

    def _search_censys(self, domain, headers, findings, tool_run):
        """Search Censys for hosts (free search)."""
        try:
            encoded = urllib.parse.quote_plus(domain)
            url = f"https://search.censys.io/api/v1/search/certificates?q={encoded}"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"Censys: {resp.status_code}\n"

            # Censys requires auth for API, so fallback to web scraping approach
            if resp.status_code != 200:
                url = f"https://search.censys.io/search?resource=hosts&q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", resp.text)
                    for ip in set(ips[:10]):
                        if not ip.startswith(("0.", "127.", "255.")):
                            findings.append(Finding(
                                FindingType.IP_ADDRESS,
                                ip,
                                source_tool=self.name,
                                confidence=0.65,
                                metadata={
                                    "domain": domain,
                                    "source": "censys",
                                },
                            ))

        except Exception as e:
            tool_run.raw_output += f"Censys error: {e}\n"

    def _search_viewdns(self, domain, headers, findings, tool_run):
        """Use ViewDNS.info for reverse lookups."""
        try:
            # Reverse IP lookup
            url = f"https://api.viewdns.info/reverseip/?host={domain}&apikey=free&output=json"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"ViewDNS: {resp.status_code}\n"

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    response = data.get("response", {})
                    domains = response.get("domains", [])
                    for d in domains[:20]:
                        name = d.get("name", "")
                        if name and name.lower() != domain.lower():
                            findings.append(Finding(
                                FindingType.RELATED_DOMAIN,
                                name,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={
                                    "source": "viewdns_reverse_ip",
                                    "shared_host_with": domain,
                                },
                            ))
                except json.JSONDecodeError:
                    pass

        except Exception as e:
            tool_run.raw_output += f"ViewDNS error: {e}\n"

    def _search_hackertarget(self, domain, headers, findings, tool_run):
        """Use HackerTarget free APIs for recon."""
        endpoints = {
            "hostsearch": f"https://api.hackertarget.com/hostsearch/?q={domain}",
            "reversedns": f"https://api.hackertarget.com/reversedns/?q={domain}",
            "dnslookup": f"https://api.hackertarget.com/dnslookup/?q={domain}",
        }

        for endpoint_name, url in endpoints.items():
            try:
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 200 and "API count exceeded" not in resp.text:
                    lines = resp.text.strip().split("\n")
                    for line in lines[:30]:
                        if "," in line:
                            parts = line.split(",")
                            hostname = parts[0].strip()
                            ip = parts[1].strip() if len(parts) > 1 else ""

                            if hostname and domain in hostname and hostname != domain:
                                findings.append(Finding(
                                    FindingType.SUBDOMAIN,
                                    hostname,
                                    source_tool=self.name,
                                    confidence=0.8,
                                    metadata={
                                        "ip": ip,
                                        "source": f"hackertarget_{endpoint_name}",
                                    },
                                ))

                            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                                findings.append(Finding(
                                    FindingType.IP_ADDRESS,
                                    ip,
                                    source_tool=self.name,
                                    confidence=0.8,
                                    metadata={
                                        "hostname": hostname,
                                        "source": f"hackertarget_{endpoint_name}",
                                    },
                                ))

                time.sleep(0.5)

            except Exception as e:
                tool_run.raw_output += f"HackerTarget {endpoint_name} error: {e}\n"
