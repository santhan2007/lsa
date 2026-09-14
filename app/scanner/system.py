"""
System Information Scanner
Collects basic system information for the auditor
"""

from . import get_system_info
import datetime
import psutil


def run() -> dict:
    """Collect system information"""
    try:
        info = get_system_info()
        
        # Add boot time
        boot_time = psutil.boot_time()
        info["boot_time"] = datetime.datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S")
        
        # Add uptime
        uptime_seconds = psutil.boot_time()
        info["uptime_hours"] = round((psutil.time.time() - uptime_seconds) / 3600, 1)
        
        # Use common formatter to ensure full schema
        from .common import format_check
        base = {
            "name": "System Overview",
            "status": "INFO",
            "score": 10,
            "max_score": 10,
            "summary": f"System information collected for {info['hostname']}",
            "details": info,
            "recommendation": "This is informational data about the system being audited.",
            "why_it_matters": "Provides context for other security findings.",
            "evidence": []
        }
        return format_check(base, scanner_id="system", category="SYSTEM")
    except Exception as e:
        return {
            "name": "System Overview",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Failed to collect system information: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
