"""
System Updates Scanner
Checks for available package updates
"""

import os
import subprocess


def run() -> dict:
    """Check for system updates"""
    try:
        # Check for pacman (Arch/Garuda)
        if os.path.exists("/usr/bin/pacman"):
            try:
                # Check for updates without actually upgrading
                output = subprocess.check_output(
                    ["pacman", "-Qu"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=15
                )
                # Count lines (each line is a package that can be upgraded)
                if output.strip():
                    update_count = len([line for line in output.split('\n') if line.strip()])
                else:
                    update_count = 0
                
                if update_count == 0:
                    return {
                        "name": "System Updates",
                        "status": "PASS",
                        "score": 10,
                        "max_score": 10,
                        "summary": "System is up to date.",
                        "details": {
                            "package_manager": "pacman",
                            "updates_available": 0,
                            "updates": []
                        },
                        "recommendation": "System is current. Continue regular update schedule."
                    }
                else:
                    # Score based on number of updates (more updates = lower score, but not critical)
                    score = max(5, 10 - min(update_count // 5, 5))  # Deduct up to 5 points
                    status = "WARNING" if update_count > 0 else "PASS"
                    
                    return {
                        "name": "System Updates",
                        "status": status,
                        "score": score,
                        "max_score": 10,
                        "summary": f"{update_count} package update(s) available.",
                        "details": {
                            "package_manager": "pacman",
                            "updates_available": update_count,
                            "updates": output.split('\n')[:10]  # Limit output
                        },
                        "recommendation": "Consider updating packages: sudo pacman -Syu"
                    }
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass  # Try other package managers
        
        # Check for apt (Debian/Ubuntu)
        if os.path.exists("/usr/bin/apt"):
            try:
                # Update package list first (non-blocking, just check if we can)
                subprocess.run(["apt", "update"], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL, 
                             timeout=10)
                
                # Check for upgradable packages
                output = subprocess.check_output(
                    ["apt", "list", "--upgradable"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=15
                )
                # Count lines that are actual packages (skip header lines)
                lines = [line.strip() for line in output.split('\n') if line.strip() and not line.startswith('Listing...') and not line == '']
                update_count = len(lines)
                
                if update_count == 0:
                    return {
                        "name": "System Updates",
                        "status": "PASS",
                        "score": 10,
                        "max_score": 10,
                        "summary": "System is up to date.",
                        "details": {
                            "package_manager": "apt",
                            "updates_available": 0,
                            "updates": []
                        },
                        "recommendation": "System is current. Continue regular update schedule."
                    }
                else:
                    score = max(5, 10 - min(update_count // 5, 5))
                    status = "WARNING" if update_count > 0 else "PASS"
                    
                    return {
                        "name": "System Updates",
                        "status": status,
                        "score": score,
                        "max_score": 10,
                        "summary": f"{update_count} package update(s) available.",
                        "details": {
                            "package_manager": "apt",
                            "updates_available": update_count,
                            "updates": lines[:10]  # Limit output
                        },
                        "recommendation": "Consider updating packages: sudo apt upgrade"
                    }
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass  # Try other package managers
        
        # Check for dnf (Fedora/RHEL)
        if os.path.exists("/usr/bin/dnf"):
            try:
                output = subprocess.check_output(
                    ["dnf", "check-update"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=15
                )
                # dnf check-update returns exit code 100 if updates available, 0 if none
                # But we'll parse output anyway
                lines = [line.strip() for line in output.split('\n') if line.strip() and not line.startswith('Last metadata expiration check:')]
                update_count = len([line for line in lines if not line.startswith('@') and not line.startswith('http')])  # Rough filtering
                
                if update_count == 0:
                    return {
                        "name": "System Updates",
                        "status": "PASS",
                        "score": 10,
                        "max_score": 10,
                        "summary": "System is up to date.",
                        "details": {
                            "package_manager": "dnf",
                            "updates_available": 0,
                            "updates": []
                        },
                        "recommendation": "System is current. Continue regular update schedule."
                    }
                else:
                    score = max(5, 10 - min(update_count // 5, 5))
                    status = "WARNING" if update_count > 0 else "PASS"
                    
                    return {
                        "name": "System Updates",
                        "status": status,
                        "score": score,
                        "max_score": 10,
                        "summary": f"{update_count} package update(s) available.",
                        "details": {
                            "package_manager": "dnf",
                            "updates_available": update_count,
                            "updates": lines[:10]
                        },
                        "recommendation": "Consider updating packages: sudo dnf upgrade"
                    }
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # Check for zypper (openSUSE)
        if os.path.exists("/usr/bin/zypper"):
            try:
                output = subprocess.check_output(
                    ["zypper", "list-updates"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=15
                )
                # Count lines that look like updates
                lines = [line.strip() for line in output.split('\n') if line.strip() and '|' in line and not line.startswith('Repository') and not line == '']
                update_count = len(lines)
                
                if update_count == 0:
                    return {
                        "name": "System Updates",
                        "status": "PASS",
                        "score": 10,
                        "max_score": 10,
                        "summary": "System is up to date.",
                        "details": {
                            "package_manager": "zypper",
                            "updates_available": 0,
                            "updates": []
                        },
                        "recommendation": "System is current. Continue regular update schedule."
                    }
                else:
                    score = max(5, 10 - min(update_count // 5, 5))
                    status = "WARNING" if update_count > 0 else "PASS"
                    
                    return {
                        "name": "System Updates",
                        "status": status,
                        "score": score,
                        "max_score": 10,
                        "summary": f"{update_count} package update(s) available.",
                        "details": {
                            "package_manager": "zypper",
                            "updates_available": update_count,
                            "updates": lines[:10]
                        },
                        "recommendation": "Consider updating packages: sudo zypper update"
                    }
            except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # If we got here, no supported package manager found or all checks failed
        return {
            "name": "System Updates",
            "status": "INFO",
            "score": 5,
            "max_score": 10,
            "summary": "No supported package manager detected for update checking.",
            "details": {
                "package_manager": "none",
                "updates_available": 0,
                "updates": []
            },
            "recommendation": "Manually check for system updates using your distribution's package manager."
        }
    except Exception as e:
        return {
            "name": "System Updates",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking for updates: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
