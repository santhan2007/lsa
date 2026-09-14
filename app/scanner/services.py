"""
Services Scanner
Checks running services on the system (systemd, init.d, etc.)
"""

import os
import subprocess


def run() -> dict:
    """Check running services"""
    try:
        services = []
        service_issues = []
        
        # Try systemctl first (systemd systems)
        if os.path.exists("/bin/systemctl") or os.path.exists("/usr/bin/systemctl"):
            try:
                # Get list of active services
                output = subprocess.check_output(
                    ["systemctl", "list-units", "--type=service", "--state=running"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=10
                )
                # Parse output
                for line in output.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('UNIT') and not line.endswith('loaded'):
                        # Extract service name (first column)
                        parts = line.split()
                        if parts:
                            service_name = parts[0]
                            # Remove .service suffix if present
                            if service_name.endswith('.service'):
                                service_name = service_name[:-8]
                            services.append(service_name)
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass  # Fall back to other methods
        
        # If we didn't get services from systemctl, try init.d (legacy)
        if not services and os.path.exists("/etc/init.d"):
            try:
                for item in os.listdir("/etc/init.d"):
                    item_path = os.path.join("/etc/init.d", item)
                    if os.path.isfile(item_path) and os.access(item_path, os.X_OK):
                        # Check if service is running (this is approximate)
                        # We could try to check status, but that might require root
                        # For now, just list the init scripts
                        services.append(item)
            except (OSError, PermissionError):
                pass
        
        # If still no services, try service command (SysV)
        if not services and (os.path.exists("/usr/sbin/service") or os.path.exists("/bin/service")):
            try:
                output = subprocess.check_output(
                    ["service", "--status-all"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=10
                )
                # Look for lines with + (running) or - (stopped)
                for line in output.split('\n'):
                    if line.strip() and ('[' in line and ']' in line):
                        # Extract service name (this is rough)
                        parts = line.split()
                        if len(parts) >= 4:
                            service_name = parts[3]
                            services.append(service_name)
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # Limit to a reasonable number for reporting
        services = sorted(list(set(services)))[:50]  # Remove duplicates, sort, limit
        
        # Determine status - mostly informational
        status = "INFO"
        score = 10
        
        if len(services) == 0:
            summary = "No services detected (may require elevated privileges to view all services)."
        elif len(services) < 10:
            summary = f"{len(services)} service(s) detected running."
        else:
            summary = f"{len(services)} service(s) detected running."
        
        details = {
            "total_services": len(services),
            "services": services[:20],  # Limit output
            "detection_method": "systemd/init.d/service"
        }
        
        return {
            "name": "Running Services",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": "Review running services regularly. Disable or stop unnecessary services to reduce attack surface."
        }
    except Exception as e:
        return {
            "name": "Running Services",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking services: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
