import os
import platform
import socket
import psutil


def get_system_info():
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
    "cpu_per_core": psutil.cpu_percent(interval=None, percpu=True),
    "ram_total_gb": round(memory.total / (1024 ** 3), 2),
    "ram_used_percent": memory.percent,
    "disk_total_gb": round(disk.total / (1024 ** 3), 2),
    "disk_used_percent": disk.percent,
    }

def get_running_services():
    services = []

    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            info = process.info
            services.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return services


def get_network_connections():
    connections = []

    for connection in psutil.net_connections(kind="inet"):
        if connection.status == psutil.CONN_LISTEN:
            connections.append({
                "address": str(connection.laddr),
                "pid": connection.pid,
            })

    return connections

def analyze_ports():
    results = []

    for connection in psutil.net_connections(kind="inet"):
        if connection.status != psutil.CONN_LISTEN:
            continue

        address = connection.laddr
        ip = address.ip
        port = address.port

        if ip in ("127.0.0.1", "::1"):
            exposure = "LOCAL"
            severity = "INFO"
            message = "Only accessible from this machine."
        elif ip in ("0.0.0.0", "::"):
            exposure = "EXPOSED"
            severity = "WARNING"
            message = "Listening on all network interfaces."
        else:
            exposure = "NETWORK"
            severity = "WARNING"
            message = "Listening on a network interface."

        results.append({
            "ip": ip,
            "port": port,
            "exposure": exposure,
            "severity": severity,
            "message": message,
            "pid": connection.pid
        })

    return sorted(results, key=lambda x: x["port"])

def check_security():
    checks = []

    # Check if running as root
    if os.geteuid() == 0:
        checks.append({
            "name": "Root execution",
            "status": "WARNING",
            "message": "The application is running with root privileges."
        })
    else:
        checks.append({
            "name": "Root execution",
            "status": "PASS",
            "message": "The application is running as a normal user."
        })

    # Check SSH configuration
    ssh_config = "/etc/ssh/sshd_config"

    if os.path.exists(ssh_config):
        try:
            with open(ssh_config, "r") as file:
                config = file.read()

            if "PermitRootLogin yes" in config:
                checks.append({
                    "name": "SSH root login",
                    "status": "WARNING",
                    "message": "SSH root login appears to be enabled."
                })
            else:
                checks.append({
                    "name": "SSH root login",
                    "status": "PASS",
                    "message": "No explicit SSH root-login permission was found."
                })

        except PermissionError:
            checks.append({
                "name": "SSH configuration",
                "status": "INFO",
                "message": "SSH configuration could not be read."
            })
    else:
        checks.append({
            "name": "SSH service",
            "status": "PASS",
            "message": "SSH configuration file was not found."
        })

    checks.append(check_ports())
    checks.append(check_firewall())
    return checks

def get_network_connections():
    connections = []

    for connection in psutil.net_connections(kind="inet"):
        if connection.status == psutil.CONN_LISTEN:
            address = connection.laddr

            connections.append({
                "ip": address.ip,
                "port": address.port,
                "protocol": "TCP" if connection.type == socket.SOCK_STREAM else "UDP",
                "pid": connection.pid,
            })

    return sorted(connections, key=lambda x: x["port"])

def calculate_security_score(checks):
    score = 100

    for check in checks:
        if check["status"] == "WARNING":
            score -= 15
        elif check["status"] == "CRITICAL":
            score -= 30

    score = max(0, score)

    if score >= 90:
        rating = "EXCELLENT"
    elif score >= 75:
        rating = "GOOD"
    elif score >= 50:
        rating = "MODERATE"
    else:
        rating = "POOR"

    return {
        "score": score,
        "rating": rating
    }

def check_firewall():
    """Check whether a common Linux firewall is active."""
    import shutil
    import subprocess

    # UFW
    if shutil.which("ufw"):
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.lower()

            if "status: active" in output:
                return {
                    "name": "Firewall",
                    "status": "PASS",
                    "message": "UFW firewall is active."
                }

            return {
                "name": "Firewall",
                "status": "WARNING",
                "message": "UFW is installed but does not appear to be active."
            }

        except (subprocess.SubprocessError, OSError):
            pass

    # firewalld
    if shutil.which("firewall-cmd"):
        try:
            result = subprocess.run(
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.stdout.strip().lower() == "running":
                return {
                    "name": "Firewall",
                    "status": "PASS",
                    "message": "firewalld is running."
                }

        except (subprocess.SubprocessError, OSError):
            pass

    return {
        "name": "Firewall",
        "status": "WARNING",
        "message": "No active supported firewall was detected."
    }

def check_ports():
    ports = analyze_ports()

    exposed = [
        port for port in ports
        if port["exposure"] in ("EXPOSED", "NETWORK")
    ]

    if exposed:
        return {
            "name": "Network exposure",
            "status": "WARNING",
            "message": f"{len(exposed)} listening port(s) are exposed to the network."
        }

    return {
        "name": "Network exposure",
        "status": "PASS",
        "message": "No listening ports were detected on external network interfaces."
    }
