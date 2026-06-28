# utils/logging.py
import logging
import os
import json
from datetime import datetime
from pathlib import Path

def setup_logger(name, log_dir="logs"):
    """Setup logger with file and console handlers"""
    
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)
    
    # Create formatters
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler
    log_file = os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger

class AuditLogger:
    """Logger for audit trail"""
    
    def __init__(self, log_file="logs/audit_log.json"):
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Initialize empty log file if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                json.dump([], f)
    
    def log_event(self, event_type, user, description, ip_address="localhost", severity="INFO"):
        """Log an audit event"""
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'user': user,
                'ip_address': ip_address,
                'description': description,
                'severity': severity
            }
            
            # Read existing logs
            logs = []
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            
            # Add new event
            logs.append(event)
            
            # Write back (keep only last 1000 events)
            if len(logs) > 1000:
                logs = logs[-1000:]
            
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error logging audit event: {e}")
            return False
    
    def get_events(self, limit=100):
        """Get recent audit events"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
                return logs[-limit:] if limit else logs
            return []
        except:
            return []

def get_system_logger():
    """Get system-wide logger"""
    return setup_logger('system')

def get_audit_logger():
    """Get audit logger instance"""
    return AuditLogger()