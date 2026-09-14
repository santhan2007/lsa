"""
Kernel Security Scanner
Checks kernel version and selected security-related kernel parameters
"""

from . import run_command
import os


def run() -> dict:
    """Check kernel security aspects"""
    try:
        import platform
        
        # Get basic kernel info
        kernel_version = platform.release()
        kernel_version_info = platform.version()
        machine = platform.machine()
        
        checks = []
        score = 10
        max_score = 10
        
        # Check ASLR (Address Space Layout Randomization)
        aslr_path = "/proc/sys/kernel/randomize_va_space"
        aslr_status = "UNKNOWN"
        aslr_value = None
        
        if os.path.exists(aslr_path):
            try:
                with open(aslr_path, 'r') as f:
                    aslr_value = f.read().strip()
                
                if aslr_value == "2":
                    aslr_status = "ENABLED (Full)"
                elif aslr_value == "1":
                    aslr_status = "ENABLED (Partial)"
                    score -= 2  # Partial is good but not optimal
                elif aslr_value == "0":
                    aslr_status = "DISABLED"
                    score -= 4  # Disabled is a security concern
                else:
                    aslr_status = f"UNKNOWN VALUE: {aslr_value}"
                    
                checks.append({
                    "name": "ASLR (Address Space Layout Randomization)",
                    "status": aslr_status,
                    "value": aslr_value
                })
            except (PermissionError, OSError):
                checks.append({
                    "name": "ASLR (Address Space Layout Randomization)",
                    "status": "UNKNOWN",
                    "value": "Permission denied to read"
                })
        else:
            checks.append({
                "name": "ASLR (Address Space Layout Randomization)",
                "status": "UNKNOWN",
                "value": "Not available on this system"
            })
        
        # Check ExecShield (if available)
        execshield_path = "/proc/sys/kernel/exec-shield"
        if os.path.exists(execshield_path):
            try:
                with open(execshield_path, 'r') as f:
                    execshield_value = f.read().strip()
                
                if execshield_value == "1":
                    execshield_status = "ENABLED"
                elif execshield_value == "0":
                    execshield_status = "DISABLED"
                    score -= 1  # Minor deduction
                else:
                    execshield_status = f"UNKNOWN: {execshield_value}"
                    
                checks.append({
                    "name": "ExecShield",
                    "status": execshield_status,
                    "value": execshield_value
                })
            except (PermissionError, OSError):
                checks.append({
                    "name": "ExecShield",
                    "status": "UNKNOWN",
                    "value": "Permission denied"
                })
        
        # Check modules loading restrictions (modules_disabled)
        modules_path = "/proc/sys/kernel/modules_disabled"
        if os.path.exists(modules_path):
            try:
                with open(modules_path, 'r') as f:
                    modules_value = f.read().strip()
                
                if modules_value == "1":
                    modules_status = "ENABLED (modules loading disabled)"
                elif modules_value == "0":
                    modules_status = "DISABLED (modules can be loaded)"
                    score -= 1  # Minor deduction for allowing module loading
                else:
                    modules_status = f"UNKNOWN: {modules_value}"
                    
                checks.append({
                    "name": "Kernel Modules Loading Restriction",
                    "status": modules_status,
                    "value": modules_value
                })
            except (PermissionError, OSError):
                checks.append({
                    "name": "Kernel Modules Loading Restriction",
                    "status": "UNKNOWN",
                    "value": "Permission denied"
                })
        
        # Determine overall status
        if score >= 9:
            status = "PASS"
        elif score >= 7:
            status = "WARNING"
        else:
            status = "WARNING"  # Still warning, not fail for kernel checks
        
        # Build summary
        if score == 10:
            summary = "Kernel security features are properly configured."
        elif score >= 8:
            summary = "Kernel security is mostly good with minor improvements possible."
        elif score >= 6:
            summary = "Kernel has some security features enabled but could be improved."
        else:
            summary = "Kernel security configuration needs attention."
        
        details = {
            "kernel_version": kernel_version,
            "kernel_version_info": kernel_version_info,
            "architecture": machine,
            "checks": checks,
            "aslr_value": aslr_value if 'aslr_value' in locals() else None
        }
        
        return {
            "name": "Kernel Security",
            "status": status,
            "score": score,
            "max_score": max_score,
            "summary": summary,
            "details": details,
            "recommendation": "Consider enabling security features like ASLR (set to 2) and restricting kernel module loading for enhanced security."
        }
    except Exception as e:
        return {
            "name": "Kernel Security",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking kernel security: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
