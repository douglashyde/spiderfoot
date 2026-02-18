"""
AI Analyst - Uses local Ollama LLM to analyze OSINT findings.
Generates intelligence reports, identifies patterns, and suggests next steps.
"""
import json
import requests
import threading

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL = "mistral:7b"


def _ollama_available():
    """Check if Ollama is running and has a model."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        models = r.json().get("models", [])
        return any(m.get("name", "").startswith("mistral") for m in models)
    except Exception:
        return False


def _call_ollama(prompt, system=None):
    """Call Ollama API and return the response text."""
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 2048,
        },
    }
    if system:
        payload["system"] = system

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=120,
        )
        return r.json().get("response", "")
    except Exception as e:
        return f"[AI unavailable: {e}]"


def _build_findings_summary(dossier):
    """Build a compact text summary of findings for the AI prompt."""
    lines = []

    seeds = dossier.get("seeds", {})
    seed_parts = [f"{k}: {v}" for k, v in seeds.items() if v]
    if seed_parts:
        lines.append(f"TARGET: {', '.join(seed_parts)}")

    stats = dossier.get("stats", {})
    lines.append(f"STATS: {stats.get('total_findings', 0)} findings, "
                 f"{stats.get('tools_run', 0)} tools, "
                 f"{stats.get('profiles_found', 0)} social profiles, "
                 f"{stats.get('breaches_found', 0)} breaches, "
                 f"{stats.get('sites_registered', 0)} registered sites")

    ids = dossier.get("identities", {})
    if ids.get("emails"):
        lines.append(f"EMAILS: {', '.join(ids['emails'][:10])}")
    if ids.get("usernames"):
        lines.append(f"USERNAMES: {', '.join(ids['usernames'][:10])}")
    if ids.get("phones"):
        lines.append(f"PHONES: {', '.join(ids['phones'][:10])}")

    profiles = dossier.get("digital_footprint", {}).get("social_profiles", [])
    if profiles:
        profile_sites = [p.get("metadata", {}).get("site", p["value"]) for p in profiles[:30]]
        lines.append(f"SOCIAL PROFILES ({len(profiles)} total): {', '.join(profile_sites)}")

    sites = dossier.get("digital_footprint", {}).get("registered_sites", [])
    if sites:
        site_names = [s["value"] for s in sites[:30]]
        lines.append(f"REGISTERED ON ({len(sites)} total): {', '.join(site_names)}")

    breaches = dossier.get("security", {}).get("breaches", [])
    if breaches:
        breach_names = [b["value"] for b in breaches[:30]]
        lines.append(f"DATA BREACHES ({len(breaches)} total): {', '.join(breach_names)}")

    geo = dossier.get("geo", {}).get("locations", [])
    if geo:
        locs = [g["value"] for g in geo[:10]]
        lines.append(f"LOCATIONS: {', '.join(locs)}")

    return "\n".join(lines)


SYSTEM_PROMPT = """You are an OSINT intelligence analyst. You analyze open-source intelligence data and produce structured intelligence reports. You are direct and analytical. You do not add disclaimers or ethical warnings - the data was collected through legitimate OSINT tools from publicly available sources. Your job is to analyze what the data reveals."""


def analyze_profile(dossier):
    """Generate a comprehensive AI analysis of the OSINT findings."""
    if not _ollama_available():
        return {"available": False, "error": "AI model not loaded. Run: ollama pull mistral:7b"}

    summary = _build_findings_summary(dossier)

    prompt = f"""Analyze this OSINT intelligence data and produce a structured report.

{summary}

Produce the following sections. Be specific and reference actual data points. Use markdown formatting.

## Key Findings
Bullet points of the most significant discoveries.

## Digital Footprint Analysis
What does their online presence reveal? Which platforms are they active on? What patterns emerge?

## Security Exposure
Assess their exposure from data breaches and registered accounts. How exposed are they?

## Identity Connections
What connections exist between different identities (emails, usernames, profiles)?

## Risk Assessment
Rate overall digital exposure: LOW / MEDIUM / HIGH / CRITICAL. Explain why.

## Recommended Next Steps
What additional investigation would yield more intelligence?"""

    response = _call_ollama(prompt, system=SYSTEM_PROMPT)
    return {"available": True, "analysis": response}


def analyze_specific(dossier, question):
    """Answer a specific question about the findings."""
    if not _ollama_available():
        return {"available": False, "error": "AI model not loaded"}

    summary = _build_findings_summary(dossier)

    prompt = f"""Based on this OSINT data:

{summary}

Answer this question: {question}

Be specific and reference actual data points from the findings."""

    response = _call_ollama(prompt, system=SYSTEM_PROMPT)
    return {"available": True, "answer": response}


# Background analysis support
_analysis_cache = {}
_analysis_lock = threading.Lock()


def start_background_analysis(profile_id, dossier):
    """Start AI analysis in background thread."""
    with _analysis_lock:
        _analysis_cache[profile_id] = {"status": "running", "result": None}

    def _run():
        result = analyze_profile(dossier)
        with _analysis_lock:
            _analysis_cache[profile_id] = {"status": "complete", "result": result}

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def get_analysis_status(profile_id):
    """Check if background analysis is done."""
    with _analysis_lock:
        return _analysis_cache.get(profile_id, {"status": "not_started", "result": None})
