"""WiFi/Geolocation Intelligence - WiGLE, IP geolocation, timezone inference."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


class WifiGeoTool(ToolWrapper):
    name = "wifi_geo"
    description = "Geolocation intelligence - IP geolocation, WiFi network mapping (WiGLE), timezone inference"
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

        # Step 1: Resolve domain to IPs
        ips = self._resolve_domain_ips(domain)
        tool_run.raw_output += f"Resolved {domain} to {len(ips)} IPs\n"

        # Step 2: Geolocate each IP
        for ip in ips[:3]:
            self._geolocate_ip(ip, domain, headers, findings, tool_run)

        # Step 3: Search WiGLE for WiFi networks near domain's organization
        self._search_wigle(domain, headers, findings, tool_run)

        # Step 4: IP history via BGP tools
        self._search_bgp_info(domain, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.type}:{f.value}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _resolve_domain_ips(self, domain):
        """Resolve domain to all IPs."""
        ips = []
        try:
            for rtype in ["A", "AAAA"]:
                resp = requests.get(f"https://dns.google/resolve?name={domain}&type={rtype}", timeout=5)
                if resp.status_code == 200:
                    for answer in resp.json().get("Answer", []):
                        data = answer.get("data", "")
                        if data and not data.endswith("."):
                            ips.append(data)
        except Exception:
            pass
        return ips

    def _geolocate_ip(self, ip, domain, headers, findings, tool_run):
        """Geolocate an IP address using multiple services."""
        # Service 1: ip-api.com (free, no key needed)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            resp = requests.get(url, timeout=10)
            tool_run.raw_output += f"ip-api ({ip}): {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    city = data.get("city", "")
                    region = data.get("regionName", "")
                    country = data.get("country", "")
                    lat = data.get("lat", 0)
                    lon = data.get("lon", 0)
                    timezone = data.get("timezone", "")
                    isp = data.get("isp", "")
                    org = data.get("org", "")
                    asn = data.get("as", "")
                    is_proxy = data.get("proxy", False)
                    is_hosting = data.get("hosting", False)
                    is_mobile = data.get("mobile", False)

                    location_str = ", ".join(filter(None, [city, region, country]))

                    findings.append(Finding(
                        FindingType.LOCATION,
                        f"{ip}: {location_str}",
                        source_tool=self.name,
                        confidence=0.8,
                        metadata={
                            "ip": ip,
                            "domain": domain,
                            "city": city,
                            "region": region,
                            "country": country,
                            "latitude": lat,
                            "longitude": lon,
                            "timezone": timezone,
                            "isp": isp,
                            "org": org,
                            "asn": asn,
                            "is_proxy": is_proxy,
                            "is_hosting": is_hosting,
                            "is_mobile": is_mobile,
                            "source": "ip-api",
                            "map_url": f"https://www.google.com/maps?q={lat},{lon}",
                        },
                    ))

                    if is_proxy:
                        findings.append(Finding(
                            FindingType.RAW,
                            f"PROXY/VPN detected: {ip} ({isp})",
                            source_tool=self.name,
                            confidence=0.75,
                            metadata={
                                "type": "proxy_detection",
                                "ip": ip,
                                "isp": isp,
                            },
                        ))

                    if timezone:
                        findings.append(Finding(
                            FindingType.RAW,
                            f"Timezone: {timezone} (from {ip})",
                            source_tool=self.name,
                            confidence=0.7,
                            metadata={
                                "type": "timezone",
                                "timezone": timezone,
                                "ip": ip,
                                "source": "ip_geolocation",
                            },
                        ))

                    if org:
                        findings.append(Finding(
                            FindingType.ORGANIZATION,
                            org,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "type": "network_operator",
                                "ip": ip,
                                "asn": asn,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"ip-api error: {e}\n"

    def _search_wigle(self, domain, headers, findings, tool_run):
        """Search WiGLE for WiFi networks associated with the domain."""
        try:
            # WiGLE search by SSID (the domain name or org name)
            # This requires free WiGLE API registration, but we can search their web
            encoded = urllib.parse.quote_plus(domain)
            search_url = f"https://wigle.net/search?ssid={encoded}"

            findings.append(Finding(
                FindingType.WEB_MENTION,
                search_url,
                source_tool=self.name,
                confidence=0.4,
                metadata={
                    "type": "wigle_search",
                    "domain": domain,
                    "note": "Search WiGLE for WiFi networks matching this domain",
                },
            ))

            # Also try the WiGLE API (free tier)
            url = f"https://api.wigle.net/api/v2/network/search?ssid={encoded}&first=0&resultsPerPage=10"
            resp = requests.get(url, headers={
                **headers,
                "Accept": "application/json",
            }, timeout=15)
            tool_run.raw_output += f"WiGLE: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                for network in results[:10]:
                    ssid = network.get("ssid", "")
                    trilat = network.get("trilat", 0)
                    trilong = network.get("trilong", 0)
                    city = network.get("city", "")
                    region = network.get("region", "")
                    country = network.get("country", "")
                    encryption = network.get("encryption", "")

                    if ssid:
                        location_str = ", ".join(filter(None, [city, region, country]))
                        findings.append(Finding(
                            FindingType.LOCATION,
                            f"WiFi '{ssid}': {location_str}",
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "type": "wifi_network",
                                "ssid": ssid,
                                "latitude": trilat,
                                "longitude": trilong,
                                "city": city,
                                "country": country,
                                "encryption": encryption,
                                "source": "wigle",
                                "map_url": f"https://www.google.com/maps?q={trilat},{trilong}",
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"WiGLE error: {e}\n"

    def _search_bgp_info(self, domain, headers, findings, tool_run):
        """Get BGP/ASN information for the domain."""
        try:
            # BGPView API (free)
            ips = self._resolve_domain_ips(domain)
            for ip in ips[:2]:
                url = f"https://api.bgpview.io/ip/{ip}"
                resp = requests.get(url, headers={
                    **headers,
                    "Accept": "application/json",
                }, timeout=10)

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    prefixes = data.get("prefixes", [])

                    for prefix in prefixes[:5]:
                        asn_data = prefix.get("asn", {})
                        asn_number = asn_data.get("asn", "")
                        asn_name = asn_data.get("name", "")
                        asn_desc = asn_data.get("description", "")
                        cidr = prefix.get("prefix", "")
                        country = asn_data.get("country_code", "")

                        if asn_number:
                            findings.append(Finding(
                                FindingType.RAW,
                                f"ASN{asn_number}: {asn_name} - {cidr}",
                                source_tool=self.name,
                                confidence=0.8,
                                metadata={
                                    "type": "bgp_info",
                                    "asn": asn_number,
                                    "asn_name": asn_name,
                                    "description": asn_desc,
                                    "prefix": cidr,
                                    "country": country,
                                    "ip": ip,
                                },
                            ))

                time.sleep(0.5)

        except Exception as e:
            tool_run.raw_output += f"BGP error: {e}\n"
