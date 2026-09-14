"""
Base scanner module for Linux Security Auditor
Contains common utilities and base classes for all security checks
"""

import os
import platform
import socket
import subprocess
import psutil
from typing import Dict, Any, Optional, List


def get_system_info() -> Dict[str, Any]:
    """Get basic system information"""
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": platform.processor() or "Unknown",
        "cpu_count": psutil.cpu_count(),
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "ram_total_gb": round(memory.total / (1024 ** 3), 2),
        "ram_used_percent": memory.percent,
        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "disk_used_percent": disk.percent,
    }


def run_command(command: List[str], timeout: int = 10) -> Optional[str]:
    """Safely run a command and return output"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
        return None


def check_file_permissions(filepath: str) -> Dict[str, Any]:
    """Check permissions of a file"""
    try:
        stat = os.stat(filepath)
        return {
            "exists": True,
            "readable": os.access(filepath, os.R_OK),
            "writable": os.access(filepath, os.W_OK),
            "executable": os.access(filepath, os.X_OK),
            "owner": stat.st_uid,
            "group": stat.st_gid,
            "permissions": oct(stat.st_mode)[-3:]
        }
    except (OSError, PermissionError):
        return {"exists": False}


def is_port_exposed(ip: str) -> str:
    """Determine if an IP address represents an exposed port"""
    if ip in ("127.0.0.1", "::1", "localhost"):
        return "LOCAL"
    elif ip in ("0.0.0.0", "::"):
        return "EXPOSED"
    else:
        return "NETWORK"


# Factory functions for each scanner
def get_system_scanner():
    from .system import run
    return run

def get_firewall_scanner():
    from .firewall import run
    return run

def get_network_scanner():
    from .network import run
    return run

def get_ssh_scanner():
    from .ssh import run
    return run

def get_accounts_scanner():
    from .accounts import run
    return run

def get_permissions_scanner():
    from .permissions import run
    return run

def get_processes_scanner():
    from .processes import run
    return run

def get_services_scanner():
    from .services import run
    return run

def get_kernel_scanner():
    from .kernel import run
    return run

def get_updates_scanner():
    from .updates import run
    return run

def get_authentication_scanner():
    from .authentication import run
    return run


# (scanner_id, category, display_name, factory) — single source of truth used
# by the web routes, the JSON report and the `lsa scan` terminal command.
SCANNER_SPECS = [
    ("firewall",       "ACCESS",     "Firewall Security",       get_firewall_scanner),
    ("network",        "NETWORK",    "Network Exposure",        get_network_scanner),
    ("ssh",            "ACCESS",     "SSH Security",            get_ssh_scanner),
    ("accounts",       "ACCOUNTS",   "User Account Security",   get_accounts_scanner),
    ("permissions",    "FILES",      "File Permissions",        get_permissions_scanner),
    ("processes",      "PROCESSES",  "Process Monitor",         get_processes_scanner),
    ("services",       "SERVICES",   "Running Services",        get_services_scanner),
    ("kernel",         "KERNEL",     "Kernel Security",         get_kernel_scanner),
    ("updates",        "UPDATES",    "System Updates",          get_updates_scanner),
    ("authentication", "AUTH",       "Authentication Activity", get_authentication_scanner),
]


def run_all_checks():
    """Run every security scanner and return normalized check results."""
    from .common import format_check

    checks = []
    for scanner_id, category, display_name, get_scanner in SCANNER_SPECS:
        try:
            raw = get_scanner()()
        except Exception as e:
            raw = {
                "name": display_name,
                "status": "UNKNOWN",
                "score": 0,
                "max_score": 10,
                "summary": f"Scanner error: {str(e)}",
                "details": {},
                "recommendation": "Check scanner implementation and system permissions.",
            }
        checks.append(format_check(raw, scanner_id=scanner_id, category=category))
    return checks


def calculate_security_score(checks):
    """Calculate overall security score from individual check results"""
    if not checks:
        return {"score": 0, "rating": "UNKNOWN", "checks": {"pass": 0, "warning": 0, "critical": 0}}
    
    score = 100
    passed = 0
    warnings = 0
    failed = 0
    
    for check in checks:
        status = check.get("status", "UNKNOWN")
        if status == "PASS":
            passed += 1
        elif status == "WARNING":
            warnings += 1
            score -= 10  # Deduct 10 points per warning
        elif status == "FAIL":
            failed += 1
            score -= 20  # Deduct 20 points per failure
        # INFO and UNKNOWN don't affect score
    
    score = max(0, score)  # Don't go below 0
    
    # Determine rating
    if score >= 90:
        rating = "EXCELLENT"
    elif score >= 75:
        rating = "GOOD"
    elif score >= 50:
        rating = "MODERATE"
    elif score >= 25:
        rating = "POOR"
    else:
        rating = "CRITICAL"
    
    return {
        "score": score,
        "rating": rating,
        "checks": {
            "pass": passed,
            "warning": warnings,
            "critical": failed,
            "failed": failed
        }
    }
