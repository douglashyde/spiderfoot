"""Kimi AI Analysis - uses Moonshot's Kimi API for intelligence analysis."""
import json
try:
    import requests
except ImportError:
    requests = None

from config import KIMI_API_KEY, KIMI_BASE_URL, KIMI_MODEL


class KimiAnalyzer:
    """Post-scan AI analysis using Kimi K2 API."""

    def __init__(self):
        self.api_key = KIMI_API_KEY
        self.base_url = KIMI_BASE_URL
        self.model = KIMI_MODEL

    def is_available(self):
        return bool(self.api_key) and requests is not None

    def analyze_findings(self, profile_data):
        """Analyze scan findings and produce intelligence report."""
        if not self.is_available():
            return {"error": "Kimi API key not configured. Set KIMI_API_KEY env var."}

        findings_summary = self._prepare_findings(profile_data)
        if not findings_summary:
            return {"error": "No findings to analyze."}

        prompt = self._build_analysis_prompt(profile_data, findings_summary)

        try:
            response = self._call_kimi(prompt)
            return {
                "analysis": response,
                "model": self.model,
                "findings_analyzed": len(findings_summary),
            }
        except Exception as e:
            return {"error": f"Kimi API error: {str(e)}"}

    def _prepare_findings(self, profile_data):
        """Extract and deduplicate important findings for analysis."""
        findings = []
        seeds = profile_data.get("seeds", {})
        seed_values = set()
        for v in seeds.values():
            if v:
                seed_values.add(v.lower().strip())

        fbt = profile_data.get("findings_by_type", {})
        seen = set()
        for ftype, items in fbt.items():
            for item in items:
                val = str(item.get("value", "")).strip()
                source = item.get("source_tool", "")
                if source == "user_input":
                    continue
                if val.lower() in seed_values:
                    continue
                key = f"{ftype}:{val}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type": ftype,
                    "value": val[:200],
                    "confidence": item.get("confidence", 0),
                    "source": source,
                    "metadata": {k: str(v)[:100] for k, v in item.get("metadata", {}).items()},
                })

        # Limit to most important findings to stay within context
        findings.sort(key=lambda x: -x.get("confidence", 0))
        return findings[:150]

    def _build_analysis_prompt(self, profile_data, findings):
        """Build the analysis prompt for Kimi."""
        seeds = profile_data.get("seeds", {})
        seed_str = ", ".join(f"{k}: {v}" for k, v in seeds.items() if v)

        # Group findings by type for cleaner presentation
        by_type = {}
        for f in findings:
            ft = f["type"]
            if ft not in by_type:
                by_type[ft] = []
            by_type[ft].append(f)

        findings_text = ""
        for ftype, items in by_type.items():
            findings_text += f"\n## {ftype.upper()} ({len(items)} items)\n"
            for item in items[:20]:
                meta_str = ", ".join(f"{k}={v}" for k, v in item.get("metadata", {}).items() if v)
                findings_text += f"- {item['value']} (conf={item['confidence']}, source={item['source']}"
                if meta_str:
                    findings_text += f", {meta_str}"
                findings_text += ")\n"
            if len(items) > 20:
                findings_text += f"  ... and {len(items) - 20} more\n"

        return f"""You are a professional OSINT (Open Source Intelligence) analyst. Analyze the following scan results and provide a comprehensive intelligence report.

INVESTIGATION SEEDS: {seed_str}

FINDINGS FROM {len(findings)} UNIQUE DATA POINTS:
{findings_text}

Provide your analysis in the following structure:

### 1. EXECUTIVE SUMMARY
Brief overview of what was discovered about this target.

### 2. DIGITAL FOOTPRINT
- Online presence across platforms
- Account registrations and social profiles found
- Email and username associations

### 3. SECURITY EXPOSURE
- Breaches and leaked credentials found
- Password patterns or reuse detected
- Infostealer/malware exposure
- Sensitive data exposure level (LOW/MEDIUM/HIGH/CRITICAL)

### 4. KEY INTELLIGENCE
- Most significant findings that provide NEW information
- Cross-platform connections discovered
- Patterns in the data (common passwords, location indicators, etc.)

### 5. RISK ASSESSMENT
Rate overall exposure: LOW / MEDIUM / HIGH / CRITICAL
Explain the rating.

### 6. RECOMMENDATIONS
Actionable steps for the target to improve their security posture.

Be concise but thorough. Focus on genuine intelligence, not restating the raw data. Highlight the most critical and actionable findings."""

    def _call_kimi(self, prompt, max_tokens=4096):
        """Call the Kimi API."""
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a professional OSINT intelligence analyst. Provide clear, actionable intelligence reports based on scan data. Be direct and factual.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.6,
            "max_tokens": max_tokens,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=120)
        if resp.status_code != 200:
            raise Exception(f"API returned {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        return data["choices"][0]["message"]["content"]
