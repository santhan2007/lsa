"""
Authentication Activity Scanner
Checks for failed authentication attempts and authentication-related security
"""

import os
import re
from . import run_command


def run() -> dict:
    """Check authentication activity"""
    try:
        failed_attempts = 0
        auth_sources = []
        details = {}
        
        # Check journalctl first (systemd systems)
        journal_output = run_command(["journalctl", "-p", "warning", "--since", "24 hours ago"])
        if journal_output:
            # Look for authentication failures in journal
            auth_patterns = [
                r'Failed password',
                r'authentication failure',
                r'Invalid user',
                r'Connection closed by authenticating user',
                r'pam_unix\(sshd:auth\): authentication failure'
            ]
            
            for pattern in auth_patterns:
                matches = re.findall(pattern, journal_output, re.IGNORECASE)
                failed_attempts += len(matches)
            
            if failed_attempts > 0:
                auth_sources.append("journalctl")
                details["journalctl_matches"] = failed_attempts
        
        # Check traditional log files if journal didn't give us much
        if failed_attempts < 5:  # Only check logs if journal didn't find many
            log_files = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/audit/audit.log"
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                    try:
                        # Look for recent failed attempts (last 24 hours would be ideal, but we'll do a simple check)
                        output = run_command(["grep", "-i", "failed", log_file])
                        if output:
                            lines = output.split('\n')
                            # Count non-empty lines that look like auth failures
                            auth_lines = [line for line in lines if any(keyword in line.lower() for keyword in 
                                                          ['failed', 'invalid user', 'authentication failure'])]
                            file_count = len(auth_lines)
                            failed_attempts += file_count
                            
                            if file_count > 0:
                                auth_sources.append(log_file)
                                details[f"{log_file}_matches"] = file_count
                    except Exception:
                        continue  # Skip if we can't read the file
        
        # Determine status based on failed attempts
        if failed_attempts == 0:
            status = "PASS"
            score = 10
            summary = "No failed authentication attempts detected in recent logs."
        elif failed_attempts <= 3:
            status = "WARNING"
            score = 8
            summary = f"{failed_attempts} failed authentication attempt(s) detected."
        elif failed_attempts <= 10:
            status = "WARNING"
            score = 6
            summary = f"{failed_attempts} failed authentication attempts detected."
        else:
            status = "WARNING"
            score = max(0, 10 - (failed_attempts // 2))  # More aggressive penalty for many attempts
            summary = f"{failed_attempts} failed authentication attempts detected - elevated activity."
        
        # Additional detail: check if SSH service is running (common target)
        ssh_running = False
        try:
            output = run_command(["systemctl", "is-active", "ssh"])
            if output and "active" in output.lower():
                ssh_running = True
        except Exception:
            try:
                output = run_command(["systemctl", "is-active", "sshd"])
                if output and "active" in output.lower():
                    ssh_running = True
            except Exception:
                pass
        
        details.update({
            "failed_attempts_total": failed_attempts,
            "authentication_sources": auth_sources,
            "ssh_service_running": ssh_running,
            "time_period": "Last 24 hours (approximate)"
        })
        
        return {
            "name": "Authentication Activity",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": "Monitor authentication logs regularly. Consider implementing fail2ban or similar brute-force protection if seeing repeated failed attempts."
        }
    except Exception as e:
        return {
            "name": "Authentication Activity",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking authentication activity: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
