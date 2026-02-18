"""OSINT Hub - Unified OSINT Intelligence Platform."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from engine.orchestrator import Orchestrator
from tools.registry import get_all_tool_info

app = Flask(__name__)
orchestrator = Orchestrator()


@app.route("/")
def index():
    tools = get_all_tool_info()
    return render_template("index.html", tools=tools)


@app.route("/scan", methods=["GET"])
def scan_page():
    tools = get_all_tool_info()
    return render_template("scan.html", tools=tools)


@app.route("/results")
def results_page():
    return render_template("results.html")


@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    data = request.json
    seeds = {
        "email": data.get("email", "").strip(),
        "username": data.get("username", "").strip(),
        "phone": data.get("phone", "").strip(),
        "full_name": data.get("full_name", "").strip(),
        "domain": data.get("domain", "").strip(),
    }

    # Must have at least one input
    if not any(seeds.values()):
        return jsonify({"error": "Please provide at least one piece of information"}), 400

    result = orchestrator.start_scan(seeds)
    return jsonify(result)


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify(orchestrator.get_status())


@app.route("/api/scan/results")
def api_scan_results():
    return jsonify(orchestrator.get_results())


@app.route("/api/scan/stop", methods=["POST"])
def api_stop_scan():
    orchestrator.stop_scan()
    return jsonify({"status": "stopped"})


@app.route("/api/scan/recommendations")
def api_recommendations():
    return jsonify(orchestrator.get_recommendations())


@app.route("/api/scan/dossier")
def api_dossier():
    """Build a unified person dossier from all findings."""
    results = orchestrator.get_results()
    if not results:
        return jsonify({})

    fbt = results.get("findings_by_type", {})

    def _vals(ftype):
        return list({f["value"] for f in fbt.get(ftype, [])})

    def _vals_with_meta(ftype):
        seen = set()
        out = []
        for f in fbt.get(ftype, []):
            if f["value"] not in seen:
                seen.add(f["value"])
                out.append({"value": f["value"], "confidence": f["confidence"],
                            "source": f["source_tool"], "metadata": f.get("metadata", {})})
        return out

    # Build dossier
    dossier = {
        "seeds": results.get("seeds", {}),
        "identities": {
            "emails": _vals("email") + _vals("related_email"),
            "usernames": _vals("username") + _vals("related_username"),
            "phones": _vals("phone") + _vals("related_phone"),
            "names": _vals("full_name"),
        },
        "digital_footprint": {
            "social_profiles": _vals_with_meta("social_profile"),
            "registered_sites": _vals_with_meta("registered_site"),
        },
        "security": {
            "breaches": _vals_with_meta("breach"),
            "raw_intel": _vals_with_meta("raw"),
        },
        "geo": {
            "locations": _vals_with_meta("location"),
        },
        "stats": {
            "total_findings": results.get("total_findings", 0),
            "tools_run": results.get("total_tool_runs", 0),
            "profiles_found": len(fbt.get("social_profile", [])),
            "breaches_found": len(fbt.get("breach", [])),
            "sites_registered": len(fbt.get("registered_site", [])),
            "emails_found": len(fbt.get("email", [])) + len(fbt.get("related_email", [])),
            "usernames_found": len(fbt.get("username", [])) + len(fbt.get("related_username", [])),
        },
        "tool_runs": results.get("tool_runs", []),
    }
    return jsonify(dossier)


@app.route("/api/tools")
def api_tools():
    return jsonify(get_all_tool_info())


@app.route("/api/tools/diagnose")
def api_tools_diagnose():
    """Show which tools are available and why."""
    import shutil
    from tools.registry import ALL_TOOLS
    from config import TOOL_PATHS

    results = []
    for name, cls in ALL_TOOLS.items():
        instance = cls()
        info = {
            "name": name,
            "available": instance.is_available(),
            "cli_command": getattr(instance, 'cli_command', None),
            "cli_on_path": bool(shutil.which(instance.cli_command)) if getattr(instance, 'cli_command', None) else False,
            "pip_module": getattr(instance, 'pip_module', None),
            "tool_path": TOOL_PATHS.get(name, ''),
            "dir_exists": os.path.isdir(TOOL_PATHS.get(name, '')),
        }
        if info["pip_module"]:
            try:
                __import__(info["pip_module"])
                info["pip_importable"] = True
            except ImportError:
                info["pip_importable"] = False
        results.append(info)
    return jsonify(sorted(results, key=lambda x: (not x["available"], x["name"])))


if __name__ == "__main__":
    # Print tool availability on startup
    from tools.registry import get_tools_for_input
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"""
    ╔══════════════════════════════════════════╗
    ║          OSINT Hub v1.0                  ║
    ║   Unified OSINT Intelligence Platform    ║
    ╠══════════════════════════════════════════╣
    ║   http://{host}:{port}                   ║
    ╚══════════════════════════════════════════╝
    """)
    all_info = get_all_tool_info()
    available = [t for t in all_info if t["available"]]
    unavailable = [t for t in all_info if not t["available"]]
    print(f"  Tools available: {len(available)}/{len(all_info)}")
    for t in available:
        print(f"    [OK] {t['name']} - {t['description']}")
    if unavailable:
        print(f"  Tools unavailable: {len(unavailable)}")
        for t in unavailable:
            print(f"    [--] {t['name']}")
    print()
    app.run(host=host, port=port, debug=True, threaded=True)
