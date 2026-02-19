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


@app.route("/graph")
def graph_page():
    return render_template("graph.html")


@app.route("/api/scan/graph")
def api_scan_graph():
    """Return findings as a D3.js-compatible force graph."""
    results = orchestrator.get_results()
    if not results or not results.get("findings_by_type"):
        return jsonify({"nodes": [], "links": []})

    nodes = []
    links = []
    node_ids = set()

    # Add seed nodes
    seeds = results.get("seeds", {})
    for seed_type, seed_value in seeds.items():
        if seed_value:
            node_id = f"seed:{seed_type}:{seed_value}"
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": seed_value,
                    "type": seed_type,
                    "group": "seed",
                    "size": 20,
                })

    # Add finding nodes
    all_findings = []
    for ftype, items in results.get("findings_by_type", {}).items():
        for item in items:
            all_findings.append(item)
            node_id = f"{ftype}:{item.get('id', '')}"
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": str(item.get("value", ""))[:60],
                    "type": ftype,
                    "group": ftype,
                    "size": max(6, int(item.get("confidence", 0.5) * 16)),
                    "confidence": item.get("confidence", 0),
                    "source": item.get("source_tool", ""),
                    "metadata": item.get("metadata", {}),
                })

            # Link to seeds
            for seed_type, seed_value in seeds.items():
                if seed_value and (
                    seed_value.lower() in str(item.get("value", "")).lower()
                    or seed_value.lower() in str(item.get("metadata", {})).lower()
                ):
                    seed_node_id = f"seed:{seed_type}:{seed_value}"
                    if seed_node_id in node_ids:
                        links.append({
                            "source": seed_node_id,
                            "target": node_id,
                            "value": item.get("confidence", 0.5),
                        })

            # Link to other findings via linked_to
            for linked_id in item.get("linked_to", []):
                target_node_id = None
                for other in all_findings:
                    if other.get("id") == linked_id:
                        other_type = other.get("type", "raw")
                        target_node_id = f"{other_type}:{linked_id}"
                        break
                if target_node_id and target_node_id in node_ids:
                    links.append({
                        "source": node_id,
                        "target": target_node_id,
                        "value": 0.5,
                    })

    return jsonify({"nodes": nodes, "links": links})


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


@app.route("/api/scan/intelligence")
def api_new_intelligence():
    """Return only genuinely new intelligence — no seeds, no repetition, no filler."""
    results = orchestrator.get_results()
    if not results or not results.get("findings_by_type"):
        return jsonify({"items": [], "summary": {}})

    seeds = results.get("seeds", {})
    seed_values = set()
    for v in seeds.values():
        if v:
            seed_values.add(v.lower().strip())
            # Also add parts (e.g. "john doe" -> "john", "doe")
            for part in v.lower().split():
                if len(part) > 2:
                    seed_values.add(part)

    # Types that are just echoing back what the user entered
    echo_types = {"email", "username", "phone", "full_name", "domain"}
    # Types that are generated/speculative filler
    filler_sources = {"user_input", "correlator (username→email)", "correlator (username variant)",
                      "correlator (email→name)", "correlator (username→name)"}

    items = []
    seen_values = set()

    fbt = results.get("findings_by_type", {})
    for ftype, findings in fbt.items():
        for f in findings:
            val = (f.get("value") or "").strip()
            val_lower = val.lower()
            source = f.get("source_tool", "")
            meta = f.get("metadata", {})
            confidence = f.get("confidence", 0)

            # Skip: exact seed echo
            if ftype in echo_types and val_lower in seed_values:
                continue

            # Skip: user_input source
            if source == "user_input":
                continue

            # Skip: low-confidence generated/speculative stuff
            if meta.get("generated") or meta.get("needs_verification"):
                if confidence < 0.5:
                    continue

            # Skip: correlator filler (email variants, name guesses, username mutations)
            if source in filler_sources:
                continue

            # Skip: duplicates by value
            dedup_key = f"{ftype}:{val_lower}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)

            # Skip empty
            if not val or val.startswith("[TIMEOUT]") or val.startswith("[ERROR]"):
                continue

            items.append(f)

    # Sort: highest confidence first, then by type priority
    type_priority = {
        "leaked_credential": 0, "password_hash": 1, "breach": 2,
        "dark_web_mention": 3, "social_profile": 4, "messaging_profile": 5,
        "registered_site": 6, "code_repository": 7, "forum_post": 8,
        "paste": 9, "photo_url": 10, "location": 11, "address": 12,
        "employer": 13, "organization": 14, "education": 15,
        "related_email": 16, "related_username": 17, "related_phone": 18,
        "ip_address": 19, "dns_record": 20, "certificate": 21,
    }
    items.sort(key=lambda f: (type_priority.get(f.get("type", "raw"), 50), -f.get("confidence", 0)))

    # Build summary counts
    summary = {}
    for f in items:
        ft = f.get("type", "raw")
        summary[ft] = summary.get(ft, 0) + 1

    return jsonify({"items": items, "summary": summary, "total": len(items)})


@app.route("/api/tools")
def api_tools():
    return jsonify(get_all_tool_info())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"""
    ╔══════════════════════════════════════════╗
    ║          OSINT Hub V5                    ║
    ║   Unified OSINT Intelligence Platform    ║
    ║   41 tools | Expandable results | URLs   ║
    ╠══════════════════════════════════════════╣
    ║   http://{host}:{port}                   ║
    ╚══════════════════════════════════════════╝
    """)
    app.run(host=host, port=port, debug=True, threaded=True)
