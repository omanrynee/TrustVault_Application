"""
File monitoring handlers for TrustVault
"""

import os
import hashlib
from datetime import datetime
from watchdog.events import FileSystemEventHandler


class FileEventHandler(FileSystemEventHandler):
    """Basic file event handler"""
    def __init__(self, log_callback=None, **kwargs):
        super().__init__()
        self.log_callback = log_callback
        self.event_counter = 0
        
    def log(self, message, level="INFO"):
        """Log message"""
        if self.log_callback:
            try:
                if callable(self.log_callback):
                    try:
                        self.log_callback(message, level)
                    except TypeError:
                        self.log_callback(message)
            except Exception as e:
                print(f"Error in log callback: {e}")
    
    def on_created(self, event):
        self.event_counter += 1
        if not event.is_directory:
            message = f"File created: {event.src_path}"
            self.log(message)
    
    def on_modified(self, event):
        self.event_counter += 1
        if not event.is_directory:
            message = f"File modified: {event.src_path}"
            self.log(message)
    
    def on_deleted(self, event):
        self.event_counter += 1
        if not event.is_directory:
            message = f"File deleted: {event.src_path}"
            self.log(message)
    
    def on_moved(self, event):
        self.event_counter += 1
        if not event.is_directory:
            message = f"File moved: {event.src_path} -> {event.dest_path}"
            self.log(message)


class EnhancedRealtimeHandler(FileEventHandler):
    """Enhanced handler with email, dashboard, and detection integrations."""
    
    def __init__(self, log_callback=None, anomaly_detector=None, 
                 web_dashboard=None, hash_verifier=None, email_system=None, 
                 ransomware_detector=None, app=None, config=None):
        super().__init__(log_callback)
        
        self.anomaly_detector = anomaly_detector
        self.web_dashboard = web_dashboard
        self.hash_verifier = hash_verifier
        self.email_system = email_system
        self.ransomware_detector = ransomware_detector
        self.app = app
        self.config = config or {}
        
        self.alert_thresholds = {
            'critical_events': ['DELETED', 'RANSOMWARE', 'ANOMALY'],
            'send_email_alerts': self.config.get('send_email_alerts', True)
        }
    
    def on_created(self, event):
        super().on_created(event)
        if not event.is_directory:
            self._process_event(event, "CREATED")
    
    def on_modified(self, event):
        super().on_modified(event)
        if not event.is_directory:
            self._process_event(event, "MODIFIED")
    
    def on_deleted(self, event):
        super().on_deleted(event)
        if not event.is_directory:
            self._process_event(event, "DELETED")
    
    def on_moved(self, event):
        super().on_moved(event)
        if not event.is_directory:
            self._process_event(event, "MOVED")
    
    def _process_event(self, event, event_type):
        """Process file event with all alert systems"""
        try:
            file_path = event.src_path
            dest_path = getattr(event, 'dest_path', '')
            
            if event.is_directory or self._is_temp_file(file_path):
                return
            
            file_size = 0
            file_hash = None
            
            if os.path.exists(file_path):
                try:
                    file_size = os.path.getsize(file_path)
                    file_hash = self._calculate_file_hash(file_path)
                except:
                    pass
            
            event_data = {
                'event_type': event_type,
                'file_path': file_path,
                'dest_path': dest_path if dest_path else None,
                'file_size': file_size,
                'file_hash': file_hash,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            if self.anomaly_detector:
                try:
                    if hasattr(self.anomaly_detector, 'detect'):
                        is_anomaly = self.anomaly_detector.detect(event_data)
                        event_data['is_anomaly'] = is_anomaly
                        
                        if is_anomaly:
                            self._handle_anomaly(event_data)
                except Exception as e:
                    print(f"Error in anomaly detection: {e}")
            
            if self.ransomware_detector and os.path.exists(file_path):
                try:
                    is_ransomware = self.ransomware_detector.check_file(file_path)
                    event_data['is_ransomware'] = is_ransomware
                    
                    if is_ransomware:
                        self._handle_ransomware(event_data)
                except Exception as e:
                    print(f"Error in ransomware detection: {e}")
            
            if self.web_dashboard:
                try:
                    self.web_dashboard.send_event(event_data)
                except Exception as e:
                    print(f"Error sending to web dashboard: {e}")
            
            self._send_alerts(event_data)
            
        except Exception as e:
            self.log(f"Error processing event: {e}", "ERROR")
    
    def _is_temp_file(self, file_path):
        """Check if file is temporary"""
        temp_extensions = ['.tmp', '.temp', '.swp', '.bak', '.log', '.cache']
        temp_folders = ['temp', 'tmp', 'cache', 'logs']
        
        ext = os.path.splitext(file_path)[1].lower()
        folder_name = os.path.basename(os.path.dirname(file_path)).lower()
        
        return ext in temp_extensions or folder_name in temp_folders
    
    def _calculate_file_hash(self, file_path, algorithm='sha256'):
        """Calculate file hash"""
        try:
            hash_func = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except:
            return None
    
    def _handle_anomaly(self, event_data):
        """Handle anomaly detection"""
        self.log(f"ANOMALY DETECTED: {event_data['event_type']} on {event_data['file_path']}", "ANOMALY")
        if self.email_system and self.alert_thresholds['send_email_alerts']:
            try:
                self.email_system.send_alert(
                    subject=f"ANOMALY: {event_data['event_type']} on {os.path.basename(event_data['file_path'])}",
                    message=f"Anomaly detected in file: {event_data['file_path']}",
                    priority="HIGH"
                )
            except Exception as e:
                print(f"Error sending email alert: {e}")
    
    def _handle_ransomware(self, event_data):
        """Handle ransomware detection"""
        self.log(f"RANSOMWARE SUSPECTED: {event_data['file_path']}", "CRITICAL")
        if self.email_system and self.alert_thresholds['send_email_alerts']:
            try:
                self.email_system.send_alert(
                    subject=f"CRITICAL: Ransomware detected - {os.path.basename(event_data['file_path'])}",
                    message=f"Ransomware activity detected!\n\nFile: {event_data['file_path']}\n\nTake immediate action!",
                    priority="CRITICAL"
                )
            except Exception as e:
                print(f"Error sending email alert: {e}")
    
    def _send_alerts(self, event_data):
        """Send appropriate alerts for the event"""
        event_type = event_data['event_type']
        
        if event_data.get('is_ransomware', False):
            alert_level = "RANSOMWARE"
        elif event_data.get('is_anomaly', False):
            alert_level = "ANOMALY"
        elif event_type in ['DELETED', 'MOVED']:
            alert_level = "WARNING"
        else:
            alert_level = "INFO"
        if (self.email_system and self.alert_thresholds['send_email_alerts'] and 
            alert_level in ["ANOMALY", "RANSOMWARE"]):
            try:
                subject = f"{alert_level}: File {event_type.lower()} - {os.path.basename(event_data['file_path'])}"
                message = f"""
                File Event Alert - {alert_level}
                
                Time: {event_data.get('timestamp')}
                Event Type: {event_type}
                File: {event_data['file_path']}
                
                Details:
                - File Size: {event_data.get('file_size', 0)} bytes
                - Hash: {event_data.get('file_hash', 'N/A')}
                - Destination: {event_data.get('dest_path', 'N/A')}
                """
                self.email_system.send_alert(
                    subject=subject,
                    message=message,
                    priority=alert_level
                )
            except Exception as e:
                print(f"Error sending email alert: {e}")