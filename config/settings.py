"""
Configuration management for TrustVault 
"""

import json
import os
import shutil
from datetime import datetime
from config import constants

def load_config():
    """Load application configuration from file"""
    try:
        if os.path.exists(constants.CONFIG_FILE):
            with open(constants.CONFIG_FILE, 'r') as f:
                config = json.load(f)
            
            # Ensure all default keys exist in loaded config
            for key, value in constants.DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value

            if config.get("theme") not in constants.THEMES:
                config["theme"] = constants.DEFAULT_THEME
                save_config(config)
            
            # Update version if needed
            if "version" not in config or config["version"] != constants.APP_VERSION:
                config["version"] = constants.APP_VERSION
                save_config(config)
            
            return config
    except Exception as e:
        print(f"Error loading config: {e}")
    
    # Return default config if file doesn't exist or error
    return constants.DEFAULT_CONFIG.copy()

def save_config(config):
    """Save application configuration to file"""
    try:
        # Ensure data directory exists
        os.makedirs(constants.DATA_DIR, exist_ok=True)
        
        # Add/update metadata
        config["last_save"] = datetime.now().isoformat()
        config["version"] = constants.APP_VERSION
        
        with open(constants.CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def update_config(config, key, value):
    """Update a configuration key and save if auto-save is enabled"""
    old_value = config.get(key)
    config[key] = value
    
    # Log configuration change
    if key not in ["last_save", "install_date", "last_user", "first_run"]:
        log_audit_event("CONFIG_CHANGE", f"Changed {key} from {old_value} to {value}")
    
    # Auto-save if enabled
    if config.get("auto_save", True):
        return save_config(config)
    
    return True

def load_email_config():
    """Load email configuration"""
    try:
        if os.path.exists(constants.EMAIL_CONFIG_FILE):
            with open(constants.EMAIL_CONFIG_FILE, 'r') as f:
                email_config = json.load(f)
            
            # Ensure all default keys exist
            for key, value in constants.DEFAULT_EMAIL_CONFIG.items():
                if key not in email_config:
                    email_config[key] = value
            
            return email_config
    except Exception as e:
        print(f"Error loading email config: {e}")
    
    return constants.DEFAULT_EMAIL_CONFIG.copy()

def save_email_config(email_config):
    """Save email configuration"""
    try:
        os.makedirs(constants.DATA_DIR, exist_ok=True)
        
        with open(constants.EMAIL_CONFIG_FILE, "w") as f:
            json.dump(email_config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving email config: {e}")
        return False

def load_hash_database():
    """Load hash database"""
    try:
        if os.path.exists(constants.HASH_DB_FILE):
            with open(constants.HASH_DB_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading hash database: {e}")
    
    return {}

def save_hash_database(hash_data):
    """Save hash database"""
    try:
        os.makedirs(constants.DATA_DIR, exist_ok=True)
        
        with open(constants.HASH_DB_FILE, "w") as f:
            json.dump(hash_data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving hash database: {e}")
        return False

def load_revoked_certs():
    """Load revoked certificates"""
    try:
        if os.path.exists(constants.REVOKED_FILE):
            with open(constants.REVOKED_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading revoked certificates: {e}")
    
    return []

def save_revoked_certs(revoked_list):
    """Save revoked certificates"""
    try:
        os.makedirs(constants.DATA_DIR, exist_ok=True)
        
        with open(constants.REVOKED_FILE, "w") as f:
            json.dump(revoked_list, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving revoked certificates: {e}")
        return False

def log_audit_event(action, details, user="system"):
    """Log an audit event"""
    try:
        # Load existing audit log
        audit_log = []
        if os.path.exists(constants.AUDIT_LOG_FILE):
            with open(constants.AUDIT_LOG_FILE, 'r') as f:
                audit_log = json.load(f)
        
        # Add new event
        event = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "details": details,
            "ip": "127.0.0.1"  # In a real app, get actual IP
        }
        
        audit_log.append(event)
        
        # Keep only last 1000 events
        if len(audit_log) > 1000:
            audit_log = audit_log[-1000:]
        
        # Save audit log
        os.makedirs(constants.LOG_DIR, exist_ok=True)
        with open(constants.AUDIT_LOG_FILE, 'w') as f:
            json.dump(audit_log, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error logging audit event: {e}")
        return False

def get_audit_logs(limit=100):
    """Get recent audit logs"""
    try:
        if os.path.exists(constants.AUDIT_LOG_FILE):
            with open(constants.AUDIT_LOG_FILE, 'r') as f:
                audit_log = json.load(f)
            
            return audit_log[-limit:] if len(audit_log) > limit else audit_log
    except Exception as e:
        print(f"Error getting audit logs: {e}")
    
    return []

def clear_audit_logs():
    """Clear audit logs"""
    try:
        if os.path.exists(constants.AUDIT_LOG_FILE):
            with open(constants.AUDIT_LOG_FILE, 'w') as f:
                json.dump([], f, indent=2)
            return True
    except Exception as e:
        print(f"Error clearing audit logs: {e}")
    
    return False

def backup_config():
    """Create a backup of all configuration files"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join(constants.BACKUP_DIR, f"config_backup_{timestamp}")
        os.makedirs(backup_dir, exist_ok=True)
        
        files_to_backup = [
            (constants.CONFIG_FILE, "config.json"),
            (constants.EMAIL_CONFIG_FILE, "email_config.json"),
            (constants.HASH_DB_FILE, "file_hashes.json"),
            (constants.REVOKED_FILE, "revoked.json"),
            (constants.AUDIT_LOG_FILE, "audit_log.json")
        ]
        
        backed_up = []
        for source, dest_name in files_to_backup:
            if os.path.exists(source):
                shutil.copy2(source, os.path.join(backup_dir, dest_name))
                backed_up.append(dest_name)
        
        # Create backup info file
        backup_info = {
            "timestamp": datetime.now().isoformat(),
            "files": backed_up,
            "version": constants.APP_VERSION
        }
        
        with open(os.path.join(backup_dir, "backup_info.json"), 'w') as f:
            json.dump(backup_info, f, indent=2)
        
        return backup_dir
    except Exception as e:
        print(f"Error creating backup: {e}")
        return None

def restore_config(backup_dir):
    """Restore configuration from backup"""
    try:
        if not os.path.exists(backup_dir):
            return False, "Backup directory not found"
        
        # Read backup info
        backup_info_file = os.path.join(backup_dir, "backup_info.json")
        if not os.path.exists(backup_info_file):
            return False, "Backup info file not found"
        
        with open(backup_info_file, 'r') as f:
            backup_info = json.load(f)
        
        # Restore files
        restored = []
        files_to_restore = [
            ("config.json", constants.CONFIG_FILE),
            ("email_config.json", constants.EMAIL_CONFIG_FILE),
            ("file_hashes.json", constants.HASH_DB_FILE),
            ("revoked.json", constants.REVOKED_FILE),
            ("audit_log.json", constants.AUDIT_LOG_FILE)
        ]
        
        for source_name, dest_path in files_to_restore:
            source_path = os.path.join(backup_dir, source_name)
            if os.path.exists(source_path):
                shutil.copy2(source_path, dest_path)
                restored.append(source_name)
        
        return True, f"Restored {len(restored)} files from backup"
    except Exception as e:
        return False, f"Error restoring backup: {str(e)}"

def reset_to_defaults():
    """Reset all configuration to defaults"""
    try:
        # Create backup before resetting
        backup_dir = backup_config()
        
        # Reset config files
        config = constants.DEFAULT_CONFIG.copy()
        config["install_date"] = datetime.now().isoformat()
        config["first_run"] = False
        save_config(config)
        
        save_email_config(constants.DEFAULT_EMAIL_CONFIG.copy())
        save_hash_database({})
        save_revoked_certs([])
        
        # Clear audit log
        clear_audit_logs()
        
        return True, f"Reset to defaults. Backup saved to: {backup_dir}"
    except Exception as e:
        return False, f"Error resetting to defaults: {str(e)}"

def get_config_info():
    """Get information about configuration"""
    config = load_config()
    
    info = {
        "config_file": constants.CONFIG_FILE,
        "email_config_file": constants.EMAIL_CONFIG_FILE,
        "hash_db_file": constants.HASH_DB_FILE,
        "config_exists": os.path.exists(constants.CONFIG_FILE),
        "email_config_exists": os.path.exists(constants.EMAIL_CONFIG_FILE),
        "hash_db_exists": os.path.exists(constants.HASH_DB_FILE),
        "config_size": os.path.getsize(constants.CONFIG_FILE) if os.path.exists(constants.CONFIG_FILE) else 0,
        "version": config.get("version", "unknown"),
        "theme": config.get("theme", "unknown"),
        "last_user": config.get("last_user", "unknown")
    }
    
    return info
