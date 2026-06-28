"""
Data package for TrustVault
"""

import os
import json
from datetime import datetime

def init_data_directory():
    """Initialize all necessary data directories and files"""
    directories = [
        'logs',
        'CSV_logs',
        'certs',
        'keys',
        'data',
        'backups'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Initialize config files with default values
    init_config_files()
    
    return True

def init_config_files():
    """Initialize configuration files with default values"""
    
    # config.json
    config_file = "data/config.json"
    if not os.path.exists(config_file):
        default_config = {
            "theme": "white",
            "alert_sound": True,
            "alert_popup": True,
            "window_size": "1400x900",
            "anomaly_detection": True,
            "web_dashboard": False,
            "dashboard_port": 5000,
            "hash_verification": False,
            "email_alerts": False,
            "ransomware_detection": True,
            "log_verbosity": "NORMAL",
            "monitor_recursive": True,
            "last_user": "admin",
            "alert_popup_normal": False,
            "auto_save": True,
            "check_updates": True,
            "auto_clean_logs": True
        }
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
    
    # email_config.json
    email_config_file = "data/email_config.json"
    if not os.path.exists(email_config_file):
        default_email_config = {
            "enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "",
            "sender_password": "",
            "recipients": [],
            "alert_levels": {"CRITICAL": True, "WARNING": True, "INFO": False},
            "use_ssl": False,
            "timeout": 30,
            "test_mode": False
        }
        with open(email_config_file, 'w') as f:
            json.dump(default_email_config, f, indent=2)
    
    # file_hashes.json
    hash_file = "data/file_hashes.json"
    if not os.path.exists(hash_file):
        default_hashes = {}
        with open(hash_file, 'w') as f:
            json.dump(default_hashes, f, indent=2)
    
    # revoked.json
    revoked_file = "data/revoked.json"
    if not os.path.exists(revoked_file):
        default_revoked = []
        with open(revoked_file, 'w') as f:
            json.dump(default_revoked, f, indent=2)
    
    # audit_log.json
    audit_file = "logs/audit_log.json"
    if not os.path.exists(audit_file):
        default_audit = []
        with open(audit_file, 'w') as f:
            json.dump(default_audit, f, indent=2)
    
    return True

def get_data_paths():
    """Return all data file paths"""
    return {
        "config": "data/config.json",
        "email_config": "data/email_config.json",
        "hash_database": "data/file_hashes.json",
        "revoked": "data/revoked.json",
        "audit_log": "logs/audit_log.json",
        "logs_dir": "logs",
        "csv_logs_dir": "CSV_logs",
        "certs_dir": "certs",
        "keys_dir": "keys",
        "backups_dir": "backups"
    }

def cleanup_old_logs(days=7):
    """Clean up log files older than specified days"""
    import time
    from pathlib import Path
    
    current_time = time.time()
    cutoff = current_time - (days * 24 * 60 * 60)
    
    log_dirs = ["logs", "CSV_logs"]
    
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            for file_path in Path(log_dir).glob("*"):
                if file_path.is_file():
                    try:
                        if file_path.stat().st_mtime < cutoff:
                            file_path.unlink()
                    except Exception as e:
                        print(f"Error cleaning up {file_path}: {e}")
    
    return True
