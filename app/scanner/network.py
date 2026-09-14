"""
Network Exposure Scanner
Detects listening ports and evaluates their exposure level
"""

from . import get_system_info, is_port_exposed
import psutil
import socket


def run() -> dict:
    """Check for listening ports and their exposure"""
    try:
        connections = []
        exposed_ports = []
        local_ports = []
        network_ports = []
        
        # Get all network connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == psutil.CONN_LISTEN:
                try:
                    # Get process info if available
                    pid = conn.pid
                    process_name = "Unknown"
                    if pid:
                        try:
                            process = psutil.Process(pid)
                            process_name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    # Get local address info
                    if conn.laddr:
                        ip, port = conn.laddr
                        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        
                        # Determine exposure
                        exposure = is_port_exposed(ip)
                        
                        port_info = {
                            "ip": ip,
                            "port": port,
                            "protocol": protocol,
                            "pid": pid,
                            "process": process_name,
                            "exposure": exposure
                        }
                        
                        connections.append(port_info)
                        
                        # Categorize by exposure
                        if exposure == "EXPOSED":
                            exposed_ports.append(port_info)
                        elif exposure == "LOCAL":
                            local_ports.append(port_info)
                        else:  # NETWORK
                            network_ports.append(port_info)
                            
                except (AttributeError, TypeError):
                    # Skip malformed connections
                    continue
        
        # Determine status based on exposure
        if len(exposed_ports) == 0 and len(network_ports) == 0:
            status = "PASS"
            score = 10
            summary = "No external network exposure detected."
            recommendation = "Good! All listening services are bound to localhost only."
        elif len(exposed_ports) == 0:
            status = "WARNING"
            score = 7
            summary = f"{len(network_ports)} service(s) listening on network interfaces."
            recommendation = "Review whether these services need to be accessible from other network interfaces."
        else:
            status = "WARNING"
            # Score based on number of exposed ports (more exposed = lower score)
            exposed_count = len(exposed_ports)
            score = max(0, 10 - (exposed_count * 2))  # Deduct 2 points per exposed port
            summary = f"{exposed_count} service(s) exposed to external networks."
            recommendation = "Review firewall rules to restrict access to these services where possible."
        
        details = {
            "total_listening": len(connections),
            "exposed_ports": exposed_ports,
            "local_ports": local_ports,
            "network_ports": network_ports,
            "connections": connections[:20]  # Limit to prevent huge responses
        }
        
        base = {
            "name": "Network Exposure",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": recommendation,
            "why_it_matters": "Exposed services can be accessed by attackers; limiting exposure reduces risk.",
            "evidence": []
        }
        from .common import format_check
        return format_check(base, scanner_id="network", category="NETWORK")
    except Exception as e:
        base = {
            "name": "Network Exposure",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking network exposure: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again.",
            "why_it_matters": "",
            "evidence": []
        }
        from .common import format_check
        return format_check(base, scanner_id="network", category="NETWORK")
