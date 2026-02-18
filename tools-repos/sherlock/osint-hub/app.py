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


@app.route("/api/tools")
def api_tools():
    return jsonify(get_all_tool_info())


if __name__ == "__main__":
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
    app.run(host=host, port=port, debug=True, threaded=True)
