"""
Constants and theme definitions for TrustVault 
"""

import os
import json
from datetime import datetime

# === PATHS & DIRECTORIES ===
# Directories that will be auto-created
CERT_DIR = "certs"
KEY_DIR = "keys"
LOG_DIR = "logs"
CSV_LOG_DIR = "CSV_logs"
BACKUP_DIR = "backups"
DATA_DIR = "data"

# Ensure directories exist
for directory in [CERT_DIR, KEY_DIR, LOG_DIR, CSV_LOG_DIR, BACKUP_DIR, DATA_DIR]:
    os.makedirs(directory, exist_ok=True)

# === FILE PATHS ===
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
EMAIL_CONFIG_FILE = os.path.join(DATA_DIR, "email_config.json")
HASH_DB_FILE = os.path.join(DATA_DIR, "file_hashes.json")
REVOKED_FILE = os.path.join(DATA_DIR, "revoked.json")
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "audit_log.json")

# === THEME ===
DEFAULT_THEME = "white"
THEME_FONT = "Segoe UI"

DARK_THEME = {
    "bg": "#020617",
    "fg": "#e5f3ff",
    "btn": "#00d4ff",
    "btn_fg": "#03111f",
    "entry_bg": "#0b1220",
    "text_bg": "#0f172a",
    "text_fg": "#e5f3ff",
    "select": "#00d4ff",
    "panel": "#0f172a",
    "panel_alt": "#111c33",
    "border": "#1f3b55",
    "muted": "#8ea4b8",
    "accent": "#00d4ff",
    "accent_hover": "#38e4ff",
    "danger": "#ef4444",
    "success": "#22c55e",
    "warning": "#f59e0b"
}

THEMES = {
    # Keep the original key for saved config compatibility while rendering
    # the whole application with the modern TrustVault dark interface.
    "white": DARK_THEME,
    "dark": DARK_THEME
}

# === DEFAULT CONFIGURATIONS ===
DEFAULT_CONFIG = {
    "theme": DEFAULT_THEME, 
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
    "auto_clean_logs": True,
    "version": "3.0",
    "first_run": True,
    "install_date": None,
    "license_accepted": False
}

DEFAULT_EMAIL_CONFIG = {
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

# === AUTHENTICATION ===
def verify_login(username, password):
    """Verify a stored multi-user password. Certificate login is handled separately."""
    try:
        from security.users import verify_password
        return verify_password(username, password)
    except Exception:
        return False

def get_valid_users():
    """Get list of valid usernames"""
    try:
        from security.users import list_users
        return [user.get("username") for user in list_users()]
    except Exception:
        return []

# === APPLICATION CONSTANTS ===
APP_NAME = "TrustVault"
APP_VERSION = "3.0"
APP_AUTHOR = "Oman Ryne"
APP_DESCRIPTION = "A PKI-Based Real-Time Cryptographic Monitoring System"

# === MONITORING CONSTANTS ===
MONITOR_EVENT_TYPES = ["CREATED", "MODIFIED", "DELETED", "MOVED"]
MONITOR_LOG_VERBOSITY = ["MINIMAL", "NORMAL", "VERBOSE"]

# === SECURITY CONSTANTS ===
ANOMALY_DETECTION_WINDOW = 60  # seconds
ANOMALY_THRESHOLD = 2.5  # sigma
RANSOMWARE_MASS_RENAME_THRESHOLD = 15
RANSOMWARE_MASS_DELETE_THRESHOLD = 20
RANSOMWARE_DETECTION_WINDOW = 120  # seconds

# === EMAIL CONSTANTS ===
EMAIL_ALERT_LEVELS = ["CRITICAL", "WARNING", "INFO"]
DEFAULT_SMTP_PORTS = {
    "gmail": 587,
    "yahoo": 465,
    "outlook": 587,
    "custom": 587
}

# === FILE HASHING ===
HASH_ALGORITHMS = ["sha256", "sha512", "md5"]
DEFAULT_HASH_ALGORITHM = "sha256"

# === LOGGING CONSTANTS ===
LOG_FILE_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_RETENTION_DAYS = 30

# === WEB DASHBOARD ===
DEFAULT_DASHBOARD_PORT = 5000
DASHBOARD_HOST = "0.0.0.0"
MAX_WEB_EVENTS = 1000

def ensure_default_files():
    """Ensure default configuration files exist with proper values"""
    
    # Create config.json if it doesn't exist
    if not os.path.exists(CONFIG_FILE):
        default_config = DEFAULT_CONFIG.copy()
        default_config["install_date"] = datetime.now().isoformat()
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=4)
    
    # Create email_config.json if it doesn't exist
    if not os.path.exists(EMAIL_CONFIG_FILE):
        with open(EMAIL_CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_EMAIL_CONFIG, f, indent=2)
    
    # Create file_hashes.json if it doesn't exist
    if not os.path.exists(HASH_DB_FILE):
        with open(HASH_DB_FILE, 'w') as f:
            json.dump({}, f, indent=2)
    
    # Create revoked.json if it doesn't exist
    if not os.path.exists(REVOKED_FILE):
        with open(REVOKED_FILE, 'w') as f:
            json.dump([], f, indent=2)
    
    # Create audit_log.json if it doesn't exist
    if not os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump([], f, indent=2)

# Call this to ensure files exist when module is imported
ensure_default_files()
