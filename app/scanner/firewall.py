"""
Firewall Security Scanner
Checks for installed and active firewall systems
"""

from . import run_command
import shutil


def run() -> dict:
    """Check firewall status"""
    try:
        # Check for UFW
        if shutil.which("ufw"):
            output = run_command(["ufw", "status"])
            if output and "Status: active" in output:
                from .common import format_check
                base = {
                    "name": "Firewall Security",
                    "status": "PASS",
                    "score": 10,
                    "max_score": 10,
                    "summary": "UFW firewall is active and protecting the system.",
                    "details": {
                        "firewall": "ufw",
                        "installed": True,
                        "active": True,
                        "status_output": output[:200]  # Limit output size
                    },
                    "recommendation": "Keep UFW enabled and regularly review rules.",
                    "why_it_matters": "Controls inbound/outbound traffic, reducing attack surface.",
                    "evidence": []
                }
                return format_check(base, scanner_id="firewall", category="ACCESS")
            elif output:
                from .common import format_check
                base = {
                    "name": "Firewall Security",
                    "status": "WARNING",
                    "score": 5,
                    "max_score": 10,
                    "summary": "UFW is installed but does not appear to be active.",
                    "details": {
                        "firewall": "ufw",
                        "installed": True,
                        "active": False,
                        "status_output": output[:200]
                    },
                    "recommendation": "Enable UFW with: sudo ufw enable",
                    "why_it_matters": "A firewall provides a first line of defense.",
                    "evidence": []
                }
                return format_check(base, scanner_id="firewall", category="ACCESS")
        
        # Check for firewalld
        if shutil.which("firewall-cmd"):
            output = run_command(["firewall-cmd", "--state"])
            if output and output.strip().lower() == "running":
                return {
                    "name": "Firewall Security",
                    "status": "PASS",
                    "score": 10,
                    "max_score": 10,
                    "summary": "firewalld is running and protecting the system.",
                    "details": {
                        "firewall": "firewalld",
                        "installed": True,
                        "active": True,
                        "status": output.strip()
                    },
                    "recommendation": "Keep firewalld enabled and regularly review zones and rules."
                }
            else:
                return {
                    "name": "Firewall Security",
                    "status": "WARNING",
                    "score": 5,
                    "max_score": 10,
                    "summary": "firewalld is installed but not running.",
                    "details": {
                        "firewall": "firewalld",
                        "installed": True,
                        "active": False,
                        "status": output.strip() if output else "unknown"
                    },
                    "recommendation": "Start firewalld with: sudo systemctl start firewalld"
                }
        
        # Check for iptables/nftables directly
        iptables_output = run_command(["iptables", "-L"])
        nft_output = run_command(["nft", "list ruleset"])
        
        has_rules = False
        if iptables_output and len(iptables_output) > 50:  # More than just headers
            has_rules = True
        if nft_output and len(nft_output) > 50:
            has_rules = True
        
        if has_rules:
            return {
                "name": "Firewall Security",
                "status": "PASS",
                "score": 8,
                "max_score": 10,
                "summary": "iptables/nftables firewall rules are configured.",
                "details": {
                    "firewall": "iptables/nftables",
                    "installed": True,
                    "active": True,
                    "has_rules": True
                },
                "recommendation": "Review firewall rules regularly to ensure they meet your security needs."
            }
        else:
            return {
                "name": "Firewall Security",
                "status": "WARNING",
                "score": 3,
                "max_score": 10,
                "summary": "No active firewall management system detected.",
                "details": {
                    "firewall": "none",
                    "installed": False,
                    "active": False
                },
                "recommendation": "Consider installing and configuring a firewall (ufw, firewalld, or iptables/nftables)."
            }
            
    except Exception as e:
        return {
            "name": "Firewall Security",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking firewall status: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
