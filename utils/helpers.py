"""
Helper utilities for TrustVault
"""

import os
import platform
import socket
import shutil
from datetime import datetime
from pathlib import Path

def get_system_info():
    """Get system information"""
    return {
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'platform': platform.system(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 Bytes"
    
    size_names = ("Bytes", "KB", "MB", "GB", "TB")
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def validate_email(email):
    """Simple email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_available_port(start_port=5000, max_attempts=100):
    """Find an available port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result != 0:
                return port
        except:
            continue
    return start_port

def backup_data_files():
    """Create backup of all data files"""
    from config import constants
    import json
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join(constants.BACKUP_DIR, f"backup_{timestamp}")
    
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        files_to_backup = [
            (constants.CONFIG_FILE, "config.json"),
            (constants.EMAIL_CONFIG_FILE, "email_config.json"),
            (constants.HASH_DB_FILE, "file_hashes.json"),
            (constants.REVOKED_FILE, "revoked.json")
        ]
        
        for source, dest_name in files_to_backup:
            if os.path.exists(source):
                shutil.copy2(source, os.path.join(backup_dir, dest_name))
        
        # Also backup logs
        log_backup_dir = os.path.join(backup_dir, "logs")
        os.makedirs(log_backup_dir, exist_ok=True)
        
        if os.path.exists("logs"):
            for log_file in Path("logs").glob("*"):
                if log_file.is_file():
                    shutil.copy2(log_file, os.path.join(log_backup_dir, log_file.name))
        
        return backup_dir
    except Exception as e:
        print(f"Error creating backup: {e}")
        return None

def rotate_logs(max_logs=100):
    """Rotate log files to prevent them from growing too large"""
    log_files = [
        "logs/audit_log.json",
        "logs/system.log"
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    data = json.load(f)
                
                if isinstance(data, list) and len(data) > max_logs:
                    data = data[-max_logs:]
                    
                    with open(log_file, 'w') as f:
                        json.dump(data, f, indent=2)
            except Exception as e:
                print(f"Error rotating log {log_file}: {e}")
    
    return True

def cleanup_temp_files():
    """Clean up temporary files"""
    temp_patterns = ['.tmp', '.temp', '~', '.swp', '.bak', '.cache']
    
    for pattern in temp_patterns:
        for temp_file in Path('.').glob(f"**/*{pattern}"):
            try:
                if temp_file.is_file():
                    temp_file.unlink()
            except Exception as e:
                print(f"Error deleting temp file {temp_file}: {e}")
    
    return True


