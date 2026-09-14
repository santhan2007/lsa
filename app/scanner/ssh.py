"""
SSH Security Scanner
Checks SSH configuration for security best practices
"""

from . import check_file_permissions
import os


def run() -> dict:
    """Check SSH server configuration"""
    ssh_config_path = "/etc/ssh/sshd_config"

    try:
        # Check if SSH config file exists
        if not os.path.exists(ssh_config_path):
            return {
                "name": "SSH Security",
                "status": "INFO",
                "score": 5,
                "max_score": 10,
                "summary": "SSH server configuration file not found.",
                "details": {
                    "ssh_installed": False,
                    "config_exists": False
                },
                "recommendation": "If SSH server is not needed, this is fine. Otherwise, install and configure OpenSSH server."
            }

        # Check file permissions
        perm_info = check_file_permissions(ssh_config_path)
        if not perm_info["exists"]:
            return {
                "name": "SSH Security",
                "status": "UNKNOWN",
                "score": 0,
                "max_score": 10,
                "summary": "Cannot access SSH configuration file.",
                "details": {"error": "Permission denied or file inaccessible"},
                "recommendation": "Check file permissions and try again with appropriate privileges."
            }

        # Read SSH config
        try:
            with open(ssh_config_path, 'r') as f:
                config_content = f.read()
        except (PermissionError, OSError):
            return {
                "name": "SSH Security",
                "status": "UNKNOWN",
                "score": 0,
                "max_score": 10,
                "summary": "Cannot read SSH configuration file due to permissions.",
                "details": {"error": "Permission denied"},
                "recommendation": "Run auditor with sufficient privileges to read SSH config, or skip this check."
            }

        # Parse key settings
        permit_root_login = "yes"  # Default/insecure
        password_auth = "yes"      # Default/insecure
        pubkey_auth = "yes"        # Default/secure
        port = "22"                # Default

        for line in config_content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(None, 1)  # Split on first whitespace
            if len(parts) == 2:
                key, value = parts
                key = key.lower()

                if key == "permitrootlogin":
                    permit_root_login = value.lower()
                elif key == "passwordauthentication":
                    password_auth = value.lower()
                elif key == "pubkeyauthentication":
                    pubkey_auth = value.lower()
                elif key == "port":
                    port = value

        # Evaluate security
        score = 10
        issues = []

        # Check root login
        if permit_root_login == "yes":
            score -= 4
            issues.append("Root login is permitted (PermitRootLogin yes)")
        elif permit_root_login == "prohibit-password":
            score -= 2
            issues.append("Root login requires key-based authentication (PermitRootLogin prohibit-password)")
        # permit_root_login == "no" or "without-password" is good (no points deducted)

        # Check password authentication
        if password_auth == "yes":
            score -= 3
            issues.append("Password authentication is enabled")
        # password_auth == "no" is good

        # Check if on non-standard port (minor security through obscurity benefit)
        if port != "22":
            score += 1  # Small bonus for non-standard port
            if score > 10:
                score = 10

        # Determine status
        if score >= 9:
            status = "PASS"
        elif score >= 6:
            status = "WARNING"
        else:
            status = "FAIL"

        # Build summary
        if score == 10:
            summary = "SSH configuration follows security best practices."
        elif score >= 8:
            summary = "SSH configuration is mostly secure with minor issues."
        elif score >= 6:
            summary = "SSH configuration has some security issues that should be addressed."
        else:
            summary = "SSH configuration has significant security issues."

        details = {
            "ssh_installed": True,
            "config_exists": True,
            "config_file": ssh_config_path,
            "permit_root_login": permit_root_login,
            "password_authentication": password_auth,
            "pubkey_authentication": pubkey_auth,
            "port": port,
            "file_permissions": perm_info,
            "issues_found": issues
        }

        recommendation_parts = ["Review SSH configuration and consider:"]
        if permit_root_login == "yes":
            recommendation_parts.append("Set PermitRootLogin to 'no' or 'prohibit-password'")
        if password_auth == "yes":
            recommendation_parts.append("Set PasswordAuthentication to 'no' and use key-based authentication")
        if port == "22":
            recommendation_parts.append("Consider changing port from default 22 for reduced automated attack surface")

        recommendation = " ".join(recommendation_parts)

        from .common import format_check
        base = {
            "name": "SSH Security",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": recommendation,
            "why_it_matters": "SSH provides remote access; misconfiguration can lead to unauthorized root login.",
            "evidence": []
        }
        return format_check(base, scanner_id="ssh", category="ACCESS")

    except Exception as e:
        return {
            "name": "SSH Security",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking SSH configuration: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
