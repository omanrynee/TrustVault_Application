"""
File integrity verification using SHA-256 hashes with automatic alerts
"""

import os
import json
import hashlib
import queue
import threading
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Callable

HASH_DB_FILE = "data/file_hashes.json"

class FileHashVerifier:
    """Verify file integrity using SHA-256 hashes with batch operations and alerts"""
    
    def __init__(self, hash_db_file: str = HASH_DB_FILE, alert_callback: Callable = None):
        self.hash_db_file = hash_db_file
        self.hash_database = self.load_hash_database()
        self.verification_queue = queue.Queue()
        self.running = True
        self.alert_callback = alert_callback  # NEW: Callback for alerts
        self.verification_thread = threading.Thread(target=self._verification_worker, daemon=True)
        self.verification_thread.start()
    
    def load_hash_database(self) -> Dict[str, Any]:
        if os.path.exists(self.hash_db_file):
            try:
                with open(self.hash_db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading hash database: {e}")
                return {}
        return {}
    
    def save_hash_database(self) -> bool:
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.hash_db_file, 'w') as f:
                json.dump(self.hash_database, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error saving hash database: {e}")
            return False
    
    def calculate_hash(self, filepath: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file"""
        try:
            if not os.path.exists(filepath):
                return None
                
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def register_file(self, filepath: str) -> Tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "File does not exist"
        
        file_hash = self.calculate_hash(filepath)
        if file_hash:
            self.hash_database[filepath] = {
                'hash': file_hash,
                'registered': datetime.now().isoformat(),
                'last_verified': datetime.now().isoformat(),
                'filename': os.path.basename(filepath),
                'size': os.path.getsize(filepath),
                'modified_time': os.path.getmtime(filepath),
                'permissions': oct(os.stat(filepath).st_mode)[-3:]
            }
            self.save_hash_database()
            return True, f"✅ File registered: {os.path.basename(filepath)}"
        return False, "❌ Failed to calculate hash"
    
    def register_folder(self, folder_path: str, recursive: bool = True) -> Tuple[bool, str]:
        """Register all files in a folder"""
        if not os.path.exists(folder_path):
            return False, "Folder does not exist"
        
        registered = []
        failed = []
        
        for root, _, files in os.walk(folder_path) if recursive else [folder_path]:
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    success, message = self.register_file(filepath)
                    if success:
                        registered.append(file)
                    else:
                        failed.append(file)
                except:
                    failed.append(file)
        
        return True, f"Registered {len(registered)} files, failed: {len(failed)}"
    
    def unregister_file(self, filepath: str) -> Tuple[bool, str]:
        if filepath in self.hash_database:
            del self.hash_database[filepath]
            self.save_hash_database()
            return True, f"✅ File unregistered"
        return False, "File not in database"
    
    def verify_file(self, filepath: str, trigger_alert: bool = True) -> Tuple[str, str, Optional[Dict]]:
        """Verify a single file's integrity with optional alert"""
        if filepath not in self.hash_database:
            return "NOT_REGISTERED", "File not in database", None
        
        if not os.path.exists(filepath):
            return "MISSING", "File no longer exists", None
        
        current_hash = self.calculate_hash(filepath)
        if not current_hash:
            return "ERROR", "Cannot calculate hash", None
        
        stored_info = self.hash_database[filepath]
        stored_hash = stored_info['hash']
        
        # Update last verification time
        self.hash_database[filepath]['last_verified'] = datetime.now().isoformat()
        self.save_hash_database()
        
        if current_hash == stored_hash:
            return "VERIFIED", "✅ File integrity verified", None
        else:
            tamper_info = {
                'filepath': filepath,
                'original_hash': stored_hash,
                'current_hash': current_hash,
                'registered': stored_info['registered'],
                'filename': os.path.basename(filepath),
                'size_change': os.path.getsize(filepath) - stored_info.get('size', 0),
                'modified_time': os.path.getmtime(filepath),
                'original_modified': stored_info.get('modified_time')
            }
            
            # Trigger alert if callback is set
            if trigger_alert and self.alert_callback:
                self.alert_callback(
                    alert_type='TAMPER',
                    title="File Tampering Detected",
                    message=f"File {os.path.basename(filepath)} has been modified!",
                    details=tamper_info,
                    file_path=filepath
                )
            
            return "TAMPERED", "🚨 FILE TAMPERED!", tamper_info
    
    def verify_and_alert(self, filepath: str) -> Tuple[str, str, Optional[Dict]]:
        """Shortcut method to verify and always trigger alert if tampered"""
        return self.verify_file(filepath, trigger_alert=True)
    
    def schedule_verification(self, filepath: str, trigger_alert: bool = True):
        """Schedule a file for background verification with alert option"""
        self.verification_queue.put((filepath, trigger_alert))
    
    def _verification_worker(self):
        """Background worker for scheduled verifications with alerts"""
        while self.running:
            try:
                filepath, trigger_alert = self.verification_queue.get(timeout=1)
                if filepath is None:
                    break
                    
                if os.path.exists(filepath) and filepath in self.hash_database:
                    status, message, tamper_info = self.verify_file(filepath, trigger_alert)
                    if status == "TAMPERED":
                        print(f"TAMPERED: {filepath}")
                        # Alert already triggered in verify_file if trigger_alert is True
                self.verification_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Verification worker error: {e}")
    
    def verify_all_files(self, trigger_alerts: bool = True) -> Dict[str, List]:
        """Verify all registered files with alert option"""
        results = {
            'verified': [],
            'tampered': [],
            'missing': [],
            'errors': [],
            'total': len(self.hash_database)
        }
        
        for filepath in list(self.hash_database.keys()):
            status, message, tamper_info = self.verify_file(filepath, trigger_alerts)
            
            if status == "VERIFIED":
                results['verified'].append(filepath)
            elif status == "TAMPERED":
                results['tampered'].append(tamper_info)
            elif status == "MISSING":
                results['missing'].append(filepath)
            else:
                results['errors'].append(filepath)
        
        return results
    
    def get_registered_files(self) -> List[str]:
        return list(self.hash_database.keys())
    
    def is_registered(self, filepath: str) -> bool:
        return filepath in self.hash_database
    
    def cleanup_missing_files(self) -> List[str]:
        """Remove missing files from database"""
        missing = []
        for filepath in list(self.hash_database.keys()):
            if not os.path.exists(filepath):
                missing.append(filepath)
                del self.hash_database[filepath]
        
        if missing:
            self.save_hash_database()
        
        return missing
    
    def get_file_info(self, filepath: str) -> Optional[Dict]:
        """Get detailed information about a registered file"""
        if filepath in self.hash_database:
            info = self.hash_database[filepath].copy()
            info['exists'] = os.path.exists(filepath)
            if os.path.exists(filepath):
                info['current_size'] = os.path.getsize(filepath)
                info['current_modified'] = os.path.getmtime(filepath)
            return info
        return None
    
    def set_alert_callback(self, callback: Callable):
        """Set the callback function for alerts"""
        self.alert_callback = callback
