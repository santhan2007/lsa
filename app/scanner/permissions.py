"""
File Permissions Scanner
Checks for world-writable files and directories in sensitive locations
"""

from . import check_file_permissions
import os
import stat


def run() -> dict:
    """Check for risky file permissions"""
    try:
        # Define sensitive directories to check (limit scope for performance)
        sensitive_dirs = [
            "/etc",
            "/var",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/tmp",
            "/var/tmp",
            "/home"
        ]
        
        # Filter to only existing directories
        dirs_to_check = [d for d in sensitive_dirs if os.path.isdir(d)]
        
        world_writable = []
        suspicious_files = []
        dirs_checked = 0
        files_checked = 0
        
        # Check each directory (limit depth to avoid scanning entire filesystem)
        for directory in dirs_to_check:
            try:
                for root, dirs, files in os.walk(directory):
                    # Limit depth to prevent excessive scanning
                    level = root.replace(directory, '').count(os.sep)
                    if level >= 2:  # Only check top 2 levels
                        # Clear dirs list to prevent descending further
                        dirs[:] = []
                    
                    # Check directories
                    for dir_name in dirs:
                        dirs_checked += 1
                        full_path = os.path.join(root, dir_name)
                        try:
                            mode = os.stat(full_path).st_mode
                            if mode & stat.S_IWOTH:  # World writable
                                world_writable.append({
                                    "path": full_path,
                                    "type": "directory",
                                    "permissions": oct(mode & 0o777)
                                })
                        except (OSError, PermissionError):
                            pass  # Skip if we can't access
                    
                    # Check files (limit to certain types to avoid too many results)
                    for file_name in files:
                        # Only check certain file types that are more likely to be problematic
                        if any(file_name.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb', '.conf', '.config', '.service', '.socket']):
                            files_checked += 1
                            full_path = os.path.join(root, file_name)
                            try:
                                mode = os.stat(full_path).st_mode
                                if mode & stat.S_IWOTH:  # World writable
                                    suspicious_files.append({
                                        "path": full_path,
                                        "type": "file",
                                        "permissions": oct(mode & 0o777)
                                    })
                            except (OSError, PermissionError):
                                pass  # Skip if we can't access
            except (OSError, PermissionError):
                continue  # Skip directory if we can't access it
        
        # Also check for world-writable files in home directories (sample)
        home_dir = os.path.expanduser("~")
        if os.path.isdir(home_dir):
            try:
                for item in os.listdir(home_dir):
                    item_path = os.path.join(home_dir, item)
                    if os.path.isfile(item_path):
                        files_checked += 1
                        try:
                            mode = os.stat(item_path).st_mode
                            if mode & stat.S_IWOTH:  # World writable
                                suspicious_files.append({
                                    "path": item_path,
                                    "type": "file",
                                    "permissions": oct(mode & 0o777)
                                })
                        except (OSError, PermissionError):
                            pass
            except (OSError, PermissionError):
                pass
        
        total_world_writable = len(world_writable) + len(suspicious_files)
        
        # Determine status
        if total_world_writable == 0:
            status = "PASS"
            score = 10
            summary = "No world-writable files detected in checked locations."
        elif total_world_writable <= 3:
            status = "WARNING"
            score = 7
            summary = f"{total_world_writable} world-writable file(s) detected."
        else:
            status = "WARNING"
            score = max(0, 10 - total_world_writable)
            summary = f"{total_world_writable} world-writable file(s) detected."
        
        # Prepare details (limit output size)
        details = {
            "dirs_checked": dirs_checked,
            "files_checked": files_checked,
            "world_writable_count": total_world_writable,
            "world_writable_items": world_writable[:5] + suspicious_files[:5],  # Limit to 10 total
            "locations_scanned": dirs_to_check
        }
        
        return {
            "name": "File Permissions",
            "status": status,
            "score": score,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": "Review world-writable files and directories. Ensure only necessary files have write access for all users."
        }
    except Exception as e:
        return {
            "name": "File Permissions",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking file permissions: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again."
        }
