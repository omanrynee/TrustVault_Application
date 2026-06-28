"""
Central Alert Notifier for TrustVault
Handles sound, popup, local history, and local alert logs
"""

import winsound
import tkinter.messagebox as messagebox
from typing import Dict, Any, List
from datetime import datetime
import os
import json

class AlertNotifier:
    """Handle local alerts, sound, popup, and alert history."""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.alert_history = []
        self.load_alert_history()
    
    def load_alert_history(self):
        """Load alert history from file"""
        try:
            if os.path.exists("data/alert_history.json"):
                with open("data/alert_history.json", "r") as f:
                    self.alert_history = json.load(f)
        except:
            self.alert_history = []
    
    def save_alert_history(self):
        """Save alert history to file"""
        try:
            os.makedirs("data", exist_ok=True)
            with open("data/alert_history.json", "w") as f:
                json.dump(self.alert_history[-1000:], f, indent=2, default=str)
        except:
            pass
    
    def notify(self, alert_type: str, title: str, message: str, 
               details: Dict = None, file_path: str = None, channel: str = None) -> Dict:
        """
        Send alert through all configured channels
        
        Args:
            alert_type: Type of alert (TAMPER, RANSOMWARE, ANOMALY, etc.)
            title: Alert title
            message: Alert message
            details: Additional details
            file_path: Affected file path
            channel: Reserved for compatibility with existing callbacks
            
        Returns:
            Dictionary with alert entry information
        """
        alert_entry = {
            'type': alert_type,
            'title': title,
            'message': message,
            'details': details,
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
        }
        
        # Add to history
        self.alert_history.append(alert_entry)
        
        # Limit history size
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]
        
        # Save history periodically
        if len(self.alert_history) % 10 == 0:
            self.save_alert_history()
        
        # Local sound alert
        if self.config.get('alert_sound', True):
            self._play_alert_sound(alert_type)
        
        # Local popup alert (only for critical alerts to avoid annoyance)
        if self.config.get('alert_popup', True) and alert_type in ['RANSOMWARE', 'CRITICAL', 'TAMPER']:
            self._show_popup_alert(title, message, alert_type)
        
        # Log to file
        self._log_alert(alert_entry)
        
        return alert_entry
    
    def notify_file_tamper(self, file_path: str, original_hash: str, 
                          current_hash: str, additional_details: Dict = None) -> Dict:
        """Specialized notification for file tampering"""
        details = {
            "Original Hash": original_hash[:16] + "...",
            "Current Hash": current_hash[:16] + "...",
            "Status": "MODIFIED",
            "Verification Time": datetime.now().strftime("%H:%M:%S")
        }
        
        if additional_details:
            details.update(additional_details)
        
        # Create alert entry
        alert_entry = {
            'type': 'TAMPER',
            'title': "File Tampering Detected",
            'message': f"File {os.path.basename(file_path)} has been modified",
            'details': details,
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
        }
        
        self.alert_history.append(alert_entry)
        
        # Local alerts
        if self.config.get('alert_sound', True):
            winsound.Beep(800, 300)
            winsound.Beep(600, 200)
        
        if self.config.get('alert_popup', True):
            messagebox.showwarning(
                "File Tampering Detected",
                f"File {os.path.basename(file_path)} has been modified!\n\n"
                f"Original: {original_hash[:16]}...\n"
                f"Current:  {current_hash[:16]}..."
            )
        
        return alert_entry
    
    def _play_alert_sound(self, alert_type: str):
        """Play appropriate sound for alert type"""
        try:
            if alert_type == 'CRITICAL' or alert_type == 'RANSOMWARE':
                winsound.Beep(1000, 500)
                winsound.Beep(800, 300)
            elif alert_type == 'TAMPER':
                winsound.Beep(800, 300)
                winsound.Beep(600, 200)
            elif alert_type == 'WARNING':
                winsound.Beep(600, 200)
            else:
                winsound.Beep(440, 100)
        except:
            pass  # Sound not available on this system
    
    def _show_popup_alert(self, title: str, message: str, alert_type: str):
        """Show popup alert based on type"""
        try:
            if alert_type in ['CRITICAL', 'RANSOMWARE']:
                messagebox.showerror(title, message)
            elif alert_type == 'TAMPER':
                messagebox.showwarning(title, message)
            else:
                messagebox.showinfo(title, message)
        except:
            pass  # GUI might not be ready
    
    def _log_alert(self, alert_entry: Dict):
        """Log alert to file"""
        try:
            log_file = "logs/alerts.log"
            os.makedirs("logs", exist_ok=True)
            with open(log_file, 'a') as f:
                f.write(f"{alert_entry['timestamp']} [{alert_entry['type']}] "
                       f"{alert_entry['title']}: {alert_entry['message']}\n")
        except:
            pass
    
    def get_recent_alerts(self, limit: int = 50) -> list:
        """Get recent alert history"""
        return self.alert_history[-limit:] if self.alert_history else []
    
    def get_alerts_by_type(self, alert_type: str, limit: int = 20) -> List[Dict]:
        """Get alerts filtered by type"""
        filtered = [a for a in self.alert_history if a['type'] == alert_type]
        return filtered[-limit:] if filtered else []
    
    def clear_alerts(self):
        """Clear alert history"""
        self.alert_history.clear()
        self.save_alert_history()
