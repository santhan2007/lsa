"""
Routes for Linux Security Auditor
Handles HTTP requests and coordinates security scanning
"""

import io
import json
import socket
from datetime import datetime

from flask import Blueprint, Response, jsonify, render_template

from app.scanner import (
    get_system_scanner,
    run_all_checks,
    calculate_security_score,
)

main = Blueprint("main", __name__)


@main.route("/")
def home():
    """Serve the main dashboard page"""
    return render_template("index.html")


@main.route("/api/system")
def system():
    """Get system information"""
    from app.scanner.system import run as system_run
    return jsonify(system_run())


@main.route("/api/security")
def security():
    """Get all security checks"""
    return jsonify(run_all_checks())


@main.route("/api/ports")
def ports():
    """Get network connections/listening ports (for backward compatibility)"""
    from app.scanner.network import run as network_run
    return jsonify(network_run())


@main.route("/api/processes")
def processes():
    """Get running services/processes (for backward compatibility)"""
    from app.scanner.processes import run as processes_run
    return jsonify(processes_run())


@main.route("/api/score")
def score():
    """Calculate and return overall security score"""
    result = calculate_security_score(run_all_checks())
    return jsonify(result)


@main.route("/api/report")
def report():
    """Full audit report as a downloadable JSON file"""
    checks = [get_system_scanner()()]
    checks += run_all_checks()

    summary = calculate_security_score(checks)

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "summary": summary,
        "checks": checks,
    }

    json_bytes = json.dumps(payload, indent=2, default=str).encode("utf-8")

    return Response(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        },
    )


# Legacy compatibility - redirect to new endpoints
@main.route("/api/systeminfo")
def systeminfo():
    """Legacy endpoint for system info"""
    return system()


@main.route("/api/checksecurity")
def checksecurity():
    """Legacy endpoint for security checks"""
    return security()
