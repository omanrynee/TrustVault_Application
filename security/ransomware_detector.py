"""
Enhanced ransomware detection with behavioral analysis and automatic alerts
"""

import os
import time
from typing import List, Tuple, Optional, Dict, Any, Callable
from datetime import datetime

class RansomwareDetector:
    """Enhanced ransomware detection with behavioral analysis and alerts"""
    
    def __init__(self, alert_callback: Callable = None):
        self.suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
            '.locky', '.zepto', '.odin', '.aesir', '.thor',
            '.cerber', '.wallet', '.wncry', '.wcry', '.aaa',
            '.ccc', '.vvv', '.xxx', '.zzz', '.abc', '.xyz',
            '.ransom', '.crypz', '.cryp1', '.cryptolocker', '.cryptowall'
        ]
        
        self.ransom_note_patterns = [
            'README', 'DECRYPT', 'RESTORE', 'HOW_TO', 'HELP',
            'INSTRUCTIONS', 'RANSOM', 'PAYMENT', 'BITCOIN',
            'PAY', 'RECOVER', 'ENCRYPTED', 'YOUR_FILES', '_INFO_',
            '_README_', '_DECRYPT_', 'RECOVERY_KEY', 'PERSONAL_KEY'
        ]
        
        self.encryption_keywords = [
            'encryption_key', 'decryption_key', 'bitcoin_address',
            'wallet', 'send_money', 'payment', 'tor', 'ransom',
            'bitcoin', 'crypto', 'recover_files', 'decrypt_files'
        ]
        
        self.recent_renames = []  # (timestamp, old_name, new_name)
        self.recent_creates = []  # (timestamp, filename)
        self.recent_deletes = []  # (timestamp, filename)
        self.recent_modifies = []  # (timestamp, filename)
        
        self.detection_window = 120  # 2 minutes window for detection
        self.mass_rename_threshold = 15  # Files renamed in window
        self.mass_create_threshold = 30  # Files created in window
        self.mass_delete_threshold = 20  # Files deleted in window
        self.mass_modify_threshold = 50  # Files modified in window
        
        self.alert_history = []
        self.detection_enabled = True
        self.alert_callback = alert_callback  # Callback for alerts
        
    def check_suspicious_extension(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Check if file has suspicious encryption extension"""
        filename_lower = filename.lower()
        
        # Check for double extensions (common in ransomware)
        parts = filename_lower.split('.')
        if len(parts) > 2:
            if any(ext in parts[-1] for ext in self.suspicious_extensions):
                return True, 'DOUBLE_EXTENSION'
        
        # Check regular suspicious extensions
        for ext in self.suspicious_extensions:
            if filename_lower.endswith(ext):
                return True, ext
        
        return False, None
    
    def check_ransom_note(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Check if filename matches ransom note pattern"""
        filename_lower = filename.lower()
        filename_upper = filename.upper()
        
        # Check if it's a text file with suspicious name
        is_text_file = filename_lower.endswith(('.txt', '.html', '.htm', '.rtf', '.md', '.log'))
        
        if is_text_file:
            for pattern in self.ransom_note_patterns:
                if pattern in filename_upper:
                    return True, pattern
        
        # Check content if small file (for text files)
        if is_text_file and os.path.exists(filename):
            try:
                if os.path.getsize(filename) < 10240:  # 10KB
                    with open(filename, 'r', errors='ignore') as f:
                        content = f.read(5000).upper()
                        for keyword in self.encryption_keywords:
                            if keyword.upper() in content:
                                return True, 'KEYWORD_IN_CONTENT'
            except:
                pass
        
        return False, None
    
    def record_rename(self, old_path: str, new_path: str) -> Tuple[bool, Optional[Dict]]:
        """Record file rename and detect mass encryption patterns with alert"""
        current_time = time.time()
        old_name = os.path.basename(old_path)
        new_name = os.path.basename(new_path)
        
        # Clean old records
        self.recent_renames = [(t, o, n) for t, o, n in self.recent_renames 
                               if current_time - t < self.detection_window]
        
        # Add new record
        self.recent_renames.append((current_time, old_name, new_name))
        
        # Check for suspicious extension in new name
        is_suspicious, reason = self.check_suspicious_extension(new_name)
        
        if is_suspicious:
            suspicious_count = sum(1 for t, o, n in self.recent_renames 
                                  if self.check_suspicious_extension(n)[0])
            
            if suspicious_count >= self.mass_rename_threshold:
                alert_data = {
                    'pattern': 'MASS_ENCRYPTION',
                    'files_affected': suspicious_count,
                    'extension': reason,
                    'timeframe': self.detection_window,
                    'timestamp': current_time,
                    'location': os.path.dirname(new_path),
                    'old_file': old_name,
                    'new_file': new_name
                }
                
                # Trigger alert
                if self.alert_callback:
                    self.alert_callback(
                        alert_type='RANSOMWARE',
                        title="🚨 Mass File Encryption Detected",
                        message=f"{suspicious_count} files renamed with suspicious extension {reason}",
                        details=alert_data,
                        file_path=new_path
                    )
                
                self.log_alert(alert_data)
                return True, alert_data
        
        # Check for ransom note creation via rename
        is_ransom_note, note_pattern = self.check_ransom_note(new_name)
        if is_ransom_note:
            alert_data = {
                'pattern': 'RANSOM_NOTE_RENAME',
                'filename': new_name,
                'note_type': note_pattern,
                'timestamp': current_time,
                'full_path': new_path
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Ransomware Note Detected",
                    message=f"Ransomware note renamed: {new_name}",
                    details=alert_data,
                    file_path=new_path
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        return False, None

    def check_mass_rename(self, old_name: str, new_name: str, timestamp: float = None) -> Tuple[bool, Optional[Dict]]:
        """Compatibility wrapper for tests that simulate rename events by filename."""
        detected, alert = self.record_rename(old_name, new_name)
        if detected:
            self.mass_renames_detected = getattr(self, "mass_renames_detected", 0) + 1
        return detected, alert
    
    def record_create(self, filepath: str) -> Tuple[bool, Optional[Dict]]:
        """Record file creation and detect ransom notes with alert"""
        current_time = time.time()
        filename = os.path.basename(filepath)
        
        # Clean old records
        self.recent_creates = [(t, f) for t, f in self.recent_creates 
                              if current_time - t < self.detection_window]
        
        # Add new record
        self.recent_creates.append((current_time, filename))
        
        # Check for ransom note
        is_ransom_note, note_pattern = self.check_ransom_note(filepath)
        if is_ransom_note:
            alert_data = {
                'pattern': 'RANSOM_NOTE_CREATE',
                'filename': filename,
                'note_type': note_pattern,
                'timestamp': current_time,
                'full_path': filepath
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Ransomware Note Created",
                    message=f"Ransomware note created: {filename}",
                    details=alert_data,
                    file_path=filepath
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        # Check for suspicious extension
        is_suspicious, reason = self.check_suspicious_extension(filename)
        if is_suspicious:
            suspicious_count = sum(1 for t, f in self.recent_creates 
                                  if self.check_suspicious_extension(f)[0])
            
            if suspicious_count >= self.mass_create_threshold:
                alert_data = {
                    'pattern': 'MASS_SUSPICIOUS_CREATE',
                    'files_affected': suspicious_count,
                    'extension': reason,
                    'timeframe': self.detection_window,
                    'timestamp': current_time,
                    'location': os.path.dirname(filepath)
                }
                
                # Trigger alert
                if self.alert_callback:
                    self.alert_callback(
                        alert_type='RANSOMWARE',
                        title="🚨 Mass Suspicious File Creation",
                        message=f"{suspicious_count} suspicious files created with extension {reason}",
                        details=alert_data,
                        file_path=filepath
                    )
                
                self.log_alert(alert_data)
                return True, alert_data
        
        return False, None
    
    def record_delete(self, filepath: str) -> Tuple[bool, Optional[Dict]]:
        """Record file deletion for ransomware detection with alert"""
        current_time = time.time()
        filename = os.path.basename(filepath)
        
        # Clean old records
        self.recent_deletes = [(t, f) for t, f in self.recent_deletes 
                              if current_time - t < self.detection_window]
        
        # Add new record
        self.recent_deletes.append((current_time, filename))
        
        # Check for mass deletions
        delete_count = len(self.recent_deletes)
        
        if delete_count >= self.mass_delete_threshold:
            alert_data = {
                'pattern': 'MASS_DELETION',
                'files_affected': delete_count,
                'timeframe': self.detection_window,
                'timestamp': current_time,
                'location': os.path.dirname(filepath)
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Mass File Deletion Detected",
                    message=f"{delete_count} files deleted in {self.detection_window} seconds",
                    details=alert_data,
                    file_path=filepath
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        return False, None
    
    def record_modify(self, filepath: str) -> Tuple[bool, Optional[Dict]]:
        """Record file modification for detection with alert"""
        current_time = time.time()
        filename = os.path.basename(filepath)
        
        # Clean old records
        self.recent_modifies = [(t, f) for t, f in self.recent_modifies 
                               if current_time - t < self.detection_window]
        
        # Add new record
        self.recent_modifies.append((current_time, filename))
        
        # Check for mass modifications
        modify_count = len(self.recent_modifies)
        
        if modify_count >= self.mass_modify_threshold:
            alert_data = {
                'pattern': 'MASS_MODIFICATION',
                'files_affected': modify_count,
                'timeframe': self.detection_window,
                'timestamp': current_time,
                'location': os.path.dirname(filepath)
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Mass File Modification Detected",
                    message=f"{modify_count} files modified in {self.detection_window} seconds",
                    details=alert_data,
                    file_path=filepath
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        return False, None
    
    def analyze_behavior(self) -> Tuple[bool, Optional[Dict]]:
        """Analyze recent behavior for ransomware patterns with alert"""
        current_time = time.time()
        
        # Combine all events for overall analysis
        recent_renames = len([t for t, _, _ in self.recent_renames 
                             if current_time - t < 60])
        recent_creates = len([t for t, _ in self.recent_creates 
                             if current_time - t < 60])
        recent_deletes = len([t for t, _ in self.recent_deletes 
                             if current_time - t < 60])
        recent_modifies = len([t for t, _ in self.recent_modifies 
                              if current_time - t < 60])
        
        total_recent_events = recent_renames + recent_creates + recent_deletes + recent_modifies
        
        # High activity detection
        if total_recent_events > 100:
            alert_data = {
                'pattern': 'EXTREME_ACTIVITY_SPIKE',
                'renames': recent_renames,
                'creates': recent_creates,
                'deletes': recent_deletes,
                'modifies': recent_modifies,
                'total': total_recent_events,
                'timestamp': current_time
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Extreme File System Activity",
                    message=f"{total_recent_events} events in 60 seconds - Possible ransomware activity!",
                    details=alert_data
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        # Pattern: Lots of renames + creates (encryption in progress)
        if recent_renames > 10 and recent_creates > 20:
            alert_data = {
                'pattern': 'ENCRYPTION_IN_PROGRESS',
                'renames': recent_renames,
                'creates': recent_creates,
                'timestamp': current_time
            }
            
            # Trigger alert
            if self.alert_callback:
                self.alert_callback(
                    alert_type='RANSOMWARE',
                    title="🚨 Possible Encryption in Progress",
                    message=f"{recent_renames} renames + {recent_creates} creates in 60 seconds",
                    details=alert_data
                )
            
            self.log_alert(alert_data)
            return True, alert_data
        
        return False, None
    
    def check_file_content(self, filepath: str) -> Tuple[bool, Optional[Dict]]:
        """Check file content for ransomware indicators with alert"""
        if not os.path.exists(filepath):
            return False, None
        
        try:
            size = os.path.getsize(filepath)
            
            # Read first 1KB of file
            with open(filepath, 'rb') as f:
                header = f.read(1024)
            
            # Check for known ransomware signatures
            ransomware_signatures = [
                b'GANDCRAB', b'RYUK', b'REvil', b'WANNACRY',
                b'MAZE', b'DOUBLEEXTORTION', b'CLOP', b'CONTI',
                b'RANSOMWARE', b'ENCRYPTED', b'DECRYPT'
            ]
            
            for sig in ransomware_signatures:
                if sig in header:
                    alert_data = {
                        'pattern': 'KNOWN_RANSOMWARE_SIGNATURE',
                        'signature': sig.decode('ascii', errors='ignore'),
                        'filepath': filepath,
                        'size': size
                    }
                    
                    # Trigger alert
                    if self.alert_callback:
                        self.alert_callback(
                            alert_type='RANSOMWARE',
                            title="🚨 Known Ransomware Signature Detected",
                            message=f"Known ransomware signature found in {os.path.basename(filepath)}",
                            details=alert_data,
                            file_path=filepath
                        )
                    
                    self.log_alert(alert_data)
                    return True, alert_data
            
            # Check for high entropy (encrypted files have high entropy)
            if size > 1024:
                entropy = self.calculate_entropy(header)
                if entropy > 7.5:
                    alert_data = {
                        'pattern': 'HIGH_ENTROPY_FILE',
                        'entropy': entropy,
                        'filepath': filepath,
                        'size': size
                    }
                    
                    # Trigger alert
                    if self.alert_callback:
                        self.alert_callback(
                            alert_type='RANSOMWARE',
                            title="🚨 High Entropy File Detected",
                            message=f"File {os.path.basename(filepath)} has high entropy (possible encryption)",
                            details=alert_data,
                            file_path=filepath
                        )
                    
                    self.log_alert(alert_data)
                    return True, alert_data
                    
        except Exception as e:
            print(f"Error checking file content: {e}")
        
        return False, None
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1) / 0.6931471805599453
        
        return entropy
    
    def log_alert(self, alert_data: Dict):
        """Log ransomware alert for history"""
        self.alert_history.append({
            'timestamp': time.time(),
            'data': alert_data,
            'type': 'RANSOMWARE_ALERT'
        })
        
        # Keep only last 100 alerts
        if len(self.alert_history) > 100:
            self.alert_history = self.alert_history[-100:]
    
    def get_alerts(self, limit: int = 20) -> List[Dict]:
        """Get recent alerts"""
        return self.alert_history[-limit:] if self.alert_history else []

    def get_detection_stats(self) -> Dict:
        """Return compact detection stats for tests and dashboards."""
        return {
            "mass_renames_detected": getattr(self, "mass_renames_detected", 0),
            "alert_count": len(self.alert_history),
            "enabled": self.detection_enabled,
        }
    
    def clear_alerts(self):
        """Clear alert history"""
        self.alert_history.clear()
    
    def disable_detection(self):
        """Temporarily disable ransomware detection"""
        self.detection_enabled = False
    
    def enable_detection(self):
        """Enable ransomware detection"""
        self.detection_enabled = True
    
    def set_alert_callback(self, callback: Callable):
        """Set the callback function for alerts"""
        self.alert_callback = callback
    
    def process_file_event(self, event_type: str, src_path: str, dest_path: str = None) -> Tuple[bool, Optional[Dict]]:
        """
        Process a file system event and check for ransomware patterns
        Returns: (detected, alert_data)
        """
        if not self.detection_enabled:
            return False, None
        
        detected = False
        alert_data = None
        
        if event_type == 'created':
            detected, alert_data = self.record_create(src_path)
            # Also check content of newly created files
            if not detected:
                detected, alert_data = self.check_file_content(src_path)
        
        elif event_type == 'deleted':
            detected, alert_data = self.record_delete(src_path)
        
        elif event_type == 'modified':
            detected, alert_data = self.record_modify(src_path)
            # Check content of modified files
            if not detected:
                detected, alert_data = self.check_file_content(src_path)
        
        elif event_type == 'moved' and dest_path:
            detected, alert_data = self.record_rename(src_path, dest_path)
            # Check the new file for ransomware patterns
            if not detected:
                detected, alert_data = self.check_file_content(dest_path)
        
        # Run behavior analysis every 10 events
        if len(self.recent_creates) % 10 == 0:
            behavior_detected, behavior_data = self.analyze_behavior()
            if behavior_detected:
                detected = True
                alert_data = behavior_data
        
        return detected, alert_data
