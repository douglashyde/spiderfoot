"""Crypto/Blockchain Intelligence - track wallet addresses and cryptocurrency activity."""
import re
import json
import time
import urllib.parse
try:
    import requests
except ImportError:
    requests = None
from .base import ToolWrapper, Finding, FindingType


# Regex patterns for crypto addresses
BTC_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
ETH_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
BTC_BECH32_PATTERN = re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b')


class CryptoIntelTool(ToolWrapper):
    name = "crypto_intel"
    description = "Blockchain intelligence - find and track Bitcoin/Ethereum wallets, trace transactions, check balances"
    accepts_input = ["email", "username", "domain"]
    category = "deep_web"

    def is_available(self):
        return requests is not None

    def _execute(self, input_type, input_value, tool_run):
        findings = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        # Step 1: Search for crypto wallets associated with target
        self._search_wallets_web(input_value, headers, findings, tool_run)

        # Step 2: Search blockchain forums for mentions
        self._search_bitcointalk(input_value, headers, findings, tool_run)

        # Step 3: Search for donation pages / crypto addresses in code/bios
        self._search_donation_pages(input_value, input_type, headers, findings, tool_run)

        # Step 4: Check any found wallet addresses against blockchain explorers
        wallet_addresses = self._extract_wallets_from_findings(findings)
        for addr_type, address in wallet_addresses:
            if addr_type == "btc":
                self._check_btc_wallet(address, headers, findings, tool_run)
            elif addr_type == "eth":
                self._check_eth_wallet(address, headers, findings, tool_run)

        # Step 5: Search Etherscan for ENS names
        if input_type == "username":
            self._search_ens(input_value, headers, findings, tool_run)

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            if f.value not in seen:
                seen.add(f.value)
                unique.append(f)

        return unique

    def _search_wallets_web(self, query, headers, findings, tool_run):
        """Search web for crypto wallets associated with target."""
        try:
            dorks = [
                f'"{query}" bitcoin OR btc OR ethereum OR eth wallet OR address OR donation',
                f'"{query}" "bc1" OR "0x" OR "1" donate OR tip OR wallet',
                f'"{query}" site:bitcointalk.org OR site:bitcoinwhoswho.com',
            ]

            for dork in dorks:
                encoded = urllib.parse.quote_plus(dork)
                url = f"https://html.duckduckgo.com/html/?q={encoded}"
                resp = requests.get(url, headers=headers, timeout=15)

                if resp.status_code == 200:
                    # Extract crypto addresses from results
                    text = resp.text
                    for btc in BTC_PATTERN.findall(text):
                        findings.append(Finding(
                            FindingType.RAW,
                            f"BTC: {btc}",
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "type": "bitcoin_address",
                                "address": btc,
                                "target": query,
                            },
                        ))

                    for eth in ETH_PATTERN.findall(text):
                        findings.append(Finding(
                            FindingType.RAW,
                            f"ETH: {eth}",
                            source_tool=self.name,
                            confidence=0.6,
                            metadata={
                                "type": "ethereum_address",
                                "address": eth,
                                "target": query,
                            },
                        ))

                    # Extract URLs from results
                    links = re.findall(r'uddg=([^&"]+)', text)
                    for link in links[:5]:
                        decoded = urllib.parse.unquote(link)
                        if "bitcoin" in decoded.lower() or "crypto" in decoded.lower():
                            findings.append(Finding(
                                FindingType.WEB_MENTION,
                                decoded,
                                source_tool=self.name,
                                confidence=0.55,
                                metadata={
                                    "context": "crypto_mention",
                                    "target": query,
                                },
                            ))

                time.sleep(1)

        except Exception as e:
            tool_run.raw_output += f"Crypto web search error: {e}\n"

    def _search_bitcointalk(self, query, headers, findings, tool_run):
        """Search BitcoinTalk forum for mentions."""
        try:
            encoded = urllib.parse.quote_plus(f'site:bitcointalk.org "{query}"')
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            resp = requests.get(url, headers=headers, timeout=15)
            tool_run.raw_output += f"BitcoinTalk search: {resp.status_code}\n"

            if resp.status_code == 200:
                links = re.findall(r'uddg=([^&"]+)', resp.text)
                for link in links[:10]:
                    decoded = urllib.parse.unquote(link)
                    if "bitcointalk.org" in decoded:
                        findings.append(Finding(
                            FindingType.FORUM_POST,
                            decoded,
                            source_tool=self.name,
                            confidence=0.65,
                            metadata={
                                "platform": "bitcointalk",
                                "target": query,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"BitcoinTalk error: {e}\n"

    def _search_donation_pages(self, query, input_type, headers, findings, tool_run):
        """Search for donation/tip jar pages that reveal wallet addresses."""
        try:
            if input_type == "username":
                # Check common donation platforms
                donation_sites = [
                    f"https://github.com/{query}",
                    f"https://ko-fi.com/{query}",
                    f"https://www.buymeacoffee.com/{query}",
                    f"https://patreon.com/{query}",
                ]

                for site_url in donation_sites:
                    try:
                        resp = requests.get(site_url, headers=headers, timeout=10)
                        if resp.status_code == 200:
                            # Extract crypto addresses from page content
                            for btc in BTC_PATTERN.findall(resp.text):
                                findings.append(Finding(
                                    FindingType.RAW,
                                    f"BTC: {btc}",
                                    source_tool=self.name,
                                    confidence=0.75,
                                    metadata={
                                        "type": "bitcoin_address",
                                        "address": btc,
                                        "found_on": site_url,
                                        "context": "donation_page",
                                    },
                                ))

                            for btc in BTC_BECH32_PATTERN.findall(resp.text):
                                findings.append(Finding(
                                    FindingType.RAW,
                                    f"BTC: {btc}",
                                    source_tool=self.name,
                                    confidence=0.75,
                                    metadata={
                                        "type": "bitcoin_bech32_address",
                                        "address": btc,
                                        "found_on": site_url,
                                    },
                                ))

                            for eth in ETH_PATTERN.findall(resp.text):
                                findings.append(Finding(
                                    FindingType.RAW,
                                    f"ETH: {eth}",
                                    source_tool=self.name,
                                    confidence=0.75,
                                    metadata={
                                        "type": "ethereum_address",
                                        "address": eth,
                                        "found_on": site_url,
                                        "context": "donation_page",
                                    },
                                ))

                        time.sleep(0.5)
                    except Exception:
                        pass

        except Exception as e:
            tool_run.raw_output += f"Donation search error: {e}\n"

    def _check_btc_wallet(self, address, headers, findings, tool_run):
        """Check Bitcoin wallet balance and transaction count."""
        try:
            url = f"https://blockchain.info/rawaddr/{address}?limit=0"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"BTC wallet {address[:12]}...: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                balance = data.get("final_balance", 0) / 1e8  # satoshi to BTC
                total_received = data.get("total_received", 0) / 1e8
                total_sent = data.get("total_sent", 0) / 1e8
                n_tx = data.get("n_tx", 0)

                if n_tx > 0:
                    findings.append(Finding(
                        FindingType.RAW,
                        f"BTC Wallet: {address} - Balance: {balance:.8f} BTC, {n_tx} transactions",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "type": "bitcoin_wallet_info",
                            "address": address,
                            "balance_btc": balance,
                            "total_received_btc": total_received,
                            "total_sent_btc": total_sent,
                            "transaction_count": n_tx,
                            "explorer_url": f"https://www.blockchain.com/btc/address/{address}",
                        },
                    ))

        except Exception as e:
            tool_run.raw_output += f"BTC wallet check error: {e}\n"

    def _check_eth_wallet(self, address, headers, findings, tool_run):
        """Check Ethereum wallet via Etherscan (free tier)."""
        try:
            url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest"
            resp = requests.get(url, headers=headers, timeout=10)
            tool_run.raw_output += f"ETH wallet {address[:12]}...: {resp.status_code}\n"

            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "1":
                    balance_wei = int(data.get("result", 0))
                    balance_eth = balance_wei / 1e18

                    findings.append(Finding(
                        FindingType.RAW,
                        f"ETH Wallet: {address} - Balance: {balance_eth:.6f} ETH",
                        source_tool=self.name,
                        confidence=0.85,
                        metadata={
                            "type": "ethereum_wallet_info",
                            "address": address,
                            "balance_eth": balance_eth,
                            "balance_wei": balance_wei,
                            "explorer_url": f"https://etherscan.io/address/{address}",
                        },
                    ))

            # Check transaction count
            url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest"
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("result"):
                    tx_count = int(data["result"], 16)
                    if tx_count > 0:
                        findings.append(Finding(
                            FindingType.RAW,
                            f"ETH {address}: {tx_count} outgoing transactions",
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "type": "ethereum_tx_count",
                                "address": address,
                                "tx_count": tx_count,
                            },
                        ))

        except Exception as e:
            tool_run.raw_output += f"ETH wallet check error: {e}\n"

    def _search_ens(self, username, headers, findings, tool_run):
        """Search for Ethereum Name Service (ENS) domains."""
        try:
            # Check if username.eth resolves
            ens_names = [
                f"{username}.eth",
                f"{username.lower()}.eth",
            ]

            for ens_name in ens_names:
                # Use ENS public resolver via web3
                url = f"https://api.ensideas.com/ens/resolve/{ens_name}"
                resp = requests.get(url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    address = data.get("address", "")
                    avatar = data.get("avatar", "")
                    display = data.get("displayName", "")

                    if address and address != "0x0000000000000000000000000000000000000000":
                        findings.append(Finding(
                            FindingType.RAW,
                            f"ENS: {ens_name} → {address}",
                            source_tool=self.name,
                            confidence=0.8,
                            metadata={
                                "type": "ens_domain",
                                "ens_name": ens_name,
                                "eth_address": address,
                                "display_name": display,
                                "avatar": avatar,
                                "explorer_url": f"https://etherscan.io/address/{address}",
                            },
                        ))

                        if avatar and avatar.startswith("http"):
                            findings.append(Finding(
                                FindingType.PHOTO_URL,
                                avatar,
                                source_tool=self.name,
                                confidence=0.7,
                                metadata={"source": "ens_avatar", "ens_name": ens_name},
                            ))

        except Exception as e:
            tool_run.raw_output += f"ENS search error: {e}\n"

    def _extract_wallets_from_findings(self, findings):
        """Extract wallet addresses from current findings."""
        wallets = set()
        for f in findings:
            if f.metadata.get("type") == "bitcoin_address":
                wallets.add(("btc", f.metadata["address"]))
            elif f.metadata.get("type") == "bitcoin_bech32_address":
                wallets.add(("btc", f.metadata["address"]))
            elif f.metadata.get("type") == "ethereum_address":
                wallets.add(("eth", f.metadata["address"]))
        return list(wallets)[:5]  # Limit
