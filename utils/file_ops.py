"""
File operations utilities for TrustVault
"""

import os
import shutil
from datetime import datetime

def ensure_directory(path):
    """Ensure a directory exists"""
    os.makedirs(path, exist_ok=True)
    return path

def backup_file(src_path, backup_dir="backups"):
    """Backup a file to backup directory"""
    ensure_directory(backup_dir)
    
    filename = os.path.basename(src_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"{filename}_{timestamp}")
    
    shutil.copy2(src_path, backup_path)
    return backup_path

def get_file_info(filepath):
    """Get detailed file information"""
    if not os.path.exists(filepath):
        return None
    
    stat = os.stat(filepath)
    info = {
        'path': filepath,
        'filename': os.path.basename(filepath),
        'size': stat.st_size,
        'modified': datetime.fromtimestamp(stat.st_mtime),
        'created': datetime.fromtimestamp(stat.st_ctime),
        'is_file': os.path.isfile(filepath),
        'is_dir': os.path.isdir(filepath),
        'permissions': oct(stat.st_mode)[-3:],
        'absolute_path': os.path.abspath(filepath)
    }
    
    return info

def count_files_in_directory(directory, recursive=True):
    """Count files in a directory"""
    if not os.path.exists(directory) or not os.path.isdir(directory):
        return 0
    
    count = 0
    if recursive:
        for root, dirs, files in os.walk(directory):
            count += len(files)
    else:
        count = len([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
    
    return count