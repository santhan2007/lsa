"""
User Account Security Scanner
Checks for potential security issues with user accounts
"""

from . import run_command
import os
import pwd


def run() -> dict:
    """Check user account security"""
    try:
        issues = []
        warnings = []
        info = []
        
        # Get all users
        users = []
        try:
            users = pwd.getpwall()
        except Exception:
            # Fallback to /etc/passwd if pwd module fails
            passwd_path = "/etc/passwd"
            if os.path.exists(passwd_path):
                with open(passwd_path, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            parts = line.strip().split(':')
                            if len(parts) >= 7:
                                users.append(type('User', (), {
                                    'pw_name': parts[0],
                                    'pw_uid': int(parts[2]),
                                    'pw_gid': int(parts[3]),
                                    'pw_gecos': parts[4],
                                    'pw_dir': parts[5],
                                    'pw_shell': parts[6]
                                })())
        
        # Check for UID 0 accounts (root)
        zero_uid_users = [u for u in users if u.pw_uid == 0]
        if len(zero_uid_users) > 1:
            warnings.append(f"Multiple UID 0 accounts found: {[u.pw_name for u in zero_uid_users]}")
            issues.append("Additional UID 0 accounts detected")
        elif len(zero_uid_users) == 1:
            info.append(f"Single UID 0 account: {zero_uid_users[0].pw_name} (expected)")
        else:
            warnings.append("No UID 0 account found")
            issues.append("No root account detected")
        
        # Check for accounts with empty passwords (if we can check shadow file)
        shadow_path = "/etc/shadow"
        if os.path.exists(shadow_path):
            try:
                # This requires root privileges, so we'll just note if we can't read it
                if os.access(shadow_path, os.R_OK):
                    with open(shadow_path, 'r') as f:
                        for line in f:
                            if line.strip() and not line.startswith('#'):
                                parts = line.strip().split(':')
                                if len(parts) >= 2:
                                    username = parts[0]
                                    password_field = parts[1]
                                    # Check for empty password or certain indicators
                                    if password_field == "" or password_field == "!" or password_field == "*":
                                        warnings.append(f"Account '{username}' has empty or disabled password")
                                        issues.append(f"Account {username} has weak password status")
                else:
                    info.append("Cannot read /etc/shadow (requires root privileges)")
            except Exception:
                info.append("Could not check shadow file for empty passwords")
        else:
            info.append("/etc/shadow not found (may use alternative authentication)")
        
        # Check for accounts with non-standard shells (optional security check)
        nonstandard_shells = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]
        unusual_shells = []
        for user in users:
            if user.pw_shell not in nonstandard_shells and user.pw_shell not in ["/usr/sbin/nologin", "/bin/false"]:
                unusual_shells.append((user.pw_name, user.pw_shell))
        
        if unusual_shells:
            info.append(f"Found {len(unusual_shells)} account(s) with non-standard shells")
            # This is informational, not necessarily a security issue
        
        # Determine status
        if len(issues) == 0:
            status = "PASS"
            score = 10
            summary = "No account security issues detected."
        elif len(issues) <= 1:
            status = "WARNING"
            score = 7
            summary = f"Minor account security issue(s) detected."
        else:
            status = "WARNING"
            score = max(0, 10 - len(issues))
            summary = f"{len(issues)} account security issue(s) detected."
        
        details = {
            "total_users": len(users),
            "zero_uid_accounts": [u.pw_name for u in zero_uid_users],
            "zero_uid_count": len(zero_uid_users),
            "warnings": warnings,
            "info": info,
            "issues": issues
        }
        
        return {
            "name": "User Account Security",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": "Review user accounts regularly. Ensure only authorized users have access, and consider disabling unused accounts."
        }
    except Exception as e:
        return {
            "name": "User Account Security",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking user accounts: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
