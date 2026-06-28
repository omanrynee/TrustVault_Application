"""
Monitoring observer setup for TrustVault
"""

import os
import time
import threading
from watchdog.observers import Observer
from monitoring.handler import EnhancedRealtimeHandler

class FileMonitor:
    """File monitoring controller with enhanced logging"""
    def __init__(self, path, recursive=True, app=None, config=None):
        self.path = os.path.abspath(path) if path else None
        self.recursive = recursive
        self.app = app
        self.config = config or {}
        self.observer = None
        self.handler = None
        self.is_running = False
        self.event_count = 0
        self.debug = self.config.get('debug_mode', False)
        
    def _debug_log(self, message):
        """Debug logging"""
        if self.debug:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[DEBUG {timestamp}] {message}")
    
    def start(self):
        """Start monitoring"""
        if self.is_running:
            self._debug_log("Monitor already running")
            return False, "Monitoring is already running"
        
        if not self.path or not os.path.exists(self.path):
            error_msg = f"Path does not exist: {self.path}"
            self._debug_log(error_msg)
            return False, error_msg
        
        if not os.path.isdir(self.path):
            error_msg = f"Path is not a directory: {self.path}"
            self._debug_log(error_msg)
            return False, error_msg
        
        self._debug_log(f"Starting monitor on path: {self.path}")
        self._debug_log(f"Recursive: {self.recursive}")
        
        try:
            # Get log callback - FIXED: Use log_message instead of log_callback
            log_callback = None
            if self.app and hasattr(self.app, 'monitor_tab'):
                if hasattr(self.app.monitor_tab, 'log_message'):
                    # Wrap the log_message to match handler's expected signature
                    def log_wrapper(message, level="INFO"):
                        try:
                            self.app.monitor_tab.log_message(message)
                        except Exception as e:
                            print(f"Error in log callback: {e}")
                    log_callback = log_wrapper
                    self._debug_log("Using monitor_tab.log_message as callback")
                else:
                    self._debug_log("monitor_tab.log_message not available")
            else:
                self._debug_log("No app or monitor_tab available")
            
            # Create handler
            self._debug_log("Creating EnhancedRealtimeHandler...")
            self.handler = EnhancedRealtimeHandler(
                log_callback=log_callback,
                anomaly_detector=getattr(self.app, 'anomaly_detector', None),
                web_dashboard=getattr(self.app, 'web_dashboard', None),
                hash_verifier=getattr(self.app, 'hash_verifier', None),
                email_system=getattr(self.app, 'email_system', None),
                ransomware_detector=getattr(self.app, 'ransomware_detector', None),
                app=self.app,
                config=self.config
            )
            
            # Create and start observer
            self._debug_log("Creating Observer...")
            self.observer = Observer()
            
            self._debug_log(f"Scheduling handler for path: {self.path}")
            self.observer.schedule(self.handler, self.path, recursive=self.recursive)
            
            self._debug_log("Starting observer...")
            self.observer.start()
            
            self.is_running = True
            self.event_count = 0
            
            self._debug_log(f"Observer started successfully")
            self._debug_log(f"Observer alive: {self.observer.is_alive()}")
            return True, f"Started monitoring {self.path}"
            
        except Exception as e:
            error_msg = f"Failed to start monitoring: {str(e)}"
            self._debug_log(error_msg)
            import traceback
            traceback.print_exc()
            return False, error_msg
    
    def stop(self):
        """Stop monitoring"""
        if not self.is_running or not self.observer:
            self._debug_log("No monitoring to stop")
            return False, "No monitoring to stop"
        
        self._debug_log("Stopping monitor...")
        
        try:
            self.is_running = False
            # Stop observer
            if self.observer:
                self._debug_log("Stopping observer...")
                self.observer.stop()
                self._debug_log("Waiting for observer to join...")
                self.observer.join(timeout=5)
                self.observer = None
                self._debug_log("Observer stopped")
            # Clean up handler
            self.handler = None
            
            self._debug_log(f"Monitoring stopped. Total events: {self.event_count}")
            
            return True, "Monitoring stopped"
            
        except Exception as e:
            error_msg = f"Error stopping monitoring: {str(e)}"
            self._debug_log(error_msg)
            return False, error_msg
    
    def get_status(self):
        """Get monitoring status"""
        observer_alive = False
        if self.observer and hasattr(self.observer, 'is_alive'):
            observer_alive = self.observer.is_alive()
        
        return {
            "is_running": self.is_running,
            "path": self.path,
            "recursive": self.recursive,
            "observer_alive": observer_alive,
            "event_count": self.event_count,
            "path_exists": os.path.exists(self.path) if self.path else False
        }

# Legacy functions
def setup_monitoring(path, recursive, app):
    """Setup and start monitoring for a given path (legacy)"""
    if not path or not app:
        return None, "Invalid path or app instance"

    try:
        log_callback = None
        if hasattr(app, 'monitor_tab') and hasattr(app.monitor_tab, 'log_message'):
            def log_wrapper(message, level="INFO"):
                app.monitor_tab.log_message(message)
            log_callback = log_wrapper

        handler = EnhancedRealtimeHandler(
            log_callback=log_callback,
            anomaly_detector=getattr(app, 'anomaly_detector', None),
            web_dashboard=getattr(app, 'web_dashboard', None),
            hash_verifier=getattr(app, 'hash_verifier', None),
            email_system=getattr(app, 'email_system', None),
            ransomware_detector=getattr(app, 'ransomware_detector', None),
            app=app,
            config=getattr(app, 'config', {})
        )

        observer = Observer()
        observer.schedule(handler, path, recursive=recursive)
        observer.start()
        return observer, None

    except Exception as e:
        return None, f"Failed to start monitoring: {str(e)}"


def stop_monitoring(observer, app=None):
    """Stop monitoring (legacy)"""
    if observer:
        try:
            observer.stop()
            observer.join(timeout=5)
            return True, None
        except Exception as e:
            return False, f"Error stopping observer: {str(e)}"
    return False, "No observer to stop"