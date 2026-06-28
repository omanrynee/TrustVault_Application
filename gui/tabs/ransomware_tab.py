"""
Ransomware detection tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from config import constants

class RansomwareTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.build_ui()
        self.update_ransomware_stats()
    
    def build_ui(self):
        """Build the ransomware detection tab UI"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Main frame
        main_frame = tk.Frame(self.frame, bg=t["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(main_frame, text="🚨 Ransomware Detection System", 
                font=("Segoe UI", 24, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=30)
        
        # Status and controls frame
        control_frame = tk.LabelFrame(main_frame, text="🛡️ Protection Status", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                     padx=25, pady=25)
        control_frame.pack(fill="x", pady=20)
        
        # Status row
        status_row = tk.Frame(control_frame, bg=t["bg"])
        status_row.pack(fill="x", pady=10)
        
        tk.Label(status_row, text="Detection Status:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=20, anchor="w").pack(side="left")
        
        self.ransomware_status = tk.Label(status_row, text="✅ ACTIVE", 
                                         fg="#27ae60", bg=t["bg"],
                                         font=("Segoe UI", 12, "bold"))
        self.ransomware_status.pack(side="left", padx=20)
        
        # Alerts count
        alert_row = tk.Frame(control_frame, bg=t["bg"])
        alert_row.pack(fill="x", pady=10)
        
        tk.Label(alert_row, text="Alerts Triggered:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=20, anchor="w").pack(side="left")
        
        self.ransomware_alerts_count = tk.Label(alert_row, text="0", 
                                               fg=t["select"], bg=t["bg"],
                                               font=("Segoe UI", 12, "bold"))
        self.ransomware_alerts_count.pack(side="left", padx=20)
        
        # Control buttons
        button_frame = tk.Frame(control_frame, bg=t["bg"])
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="⚙️ Configure Detection", 
                 command=self.configure_ransomware_detection,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=8).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="📊 View Alert History", 
                 command=self.view_ransomware_history,
                 bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=8).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="🧹 Clear History", 
                 command=self.clear_ransomware_history,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=8).pack(side="left", padx=10)
        
        # Detection patterns frame
        patterns_frame = tk.LabelFrame(main_frame, text="🔍 Detection Patterns", 
                                      bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                      padx=25, pady=25)
        patterns_frame.pack(fill="x", pady=20)
        
        # Patterns list with scrollbar
        patterns_scroll = tk.Scrollbar(patterns_frame, bg=t["bg"])
        patterns_scroll.pack(side="right", fill="y")
        
        patterns_text = tk.Text(patterns_frame, height=8, 
                               bg=t["text_bg"], fg=t["text_fg"],
                               font=("Segoe UI", 10), wrap="word",
                               yscrollcommand=patterns_scroll.set)
        patterns_text.pack(fill="both", expand=True)
        
        patterns_scroll.config(command=patterns_text.yview)
        
        # Populate patterns
        patterns_info = """
🚨 RANSOMWARE DETECTION PATTERNS:

1. SUSPICIOUS FILE EXTENSIONS:
   • .encrypted, .locked, .crypto, .crypt, .enc
   • .locky, .zepto, .odin, .aesir, .thor
   • .cerber, .wallet, .wncry, .wcry

2. MASS FILE OPERATIONS:
   • Multiple files renamed with suspicious extensions (>15 in 2 minutes)
   • Mass file deletions (>20 in 2 minutes)
   • Rapid file modifications (>50 in 2 minutes)

3. RANSOM NOTES:
   • Files named: README, DECRYPT, HOW_TO, INSTRUCTIONS
   • Files containing: bitcoin, payment, decrypt, ransom

4. BEHAVIORAL PATTERNS:
   • High entropy files (encrypted content)
   • Known ransomware signatures in files
   • Unusual file activity spikes

5. COMPOSITE DETECTION:
   • Combination of patterns increases confidence
   • Time-based correlation of events
   • Statistical anomaly detection
        """
        
        patterns_text.insert("1.0", patterns_info)
        patterns_text.configure(state="disabled")
        
        # Alert history frame
        history_frame = tk.LabelFrame(main_frame, text="📜 Recent Alerts", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                     padx=25, pady=25)
        history_frame.pack(fill="both", expand=True, pady=20)
        
        # History list with scrollbar
        history_scroll = tk.Scrollbar(history_frame, bg=t["bg"])
        history_scroll.pack(side="right", fill="y")
        
        self.ransomware_history = tk.Text(history_frame, height=10, 
                                         bg=t["text_bg"], fg=t["text_fg"],
                                         font=("Segoe UI", 9), wrap="word",
                                         yscrollcommand=history_scroll.set)
        self.ransomware_history.pack(fill="both", expand=True)
        
        history_scroll.config(command=self.ransomware_history.yview)
        
        # Initialize history
        self.update_ransomware_history()
    
    def update_ransomware_stats(self):
        """Update ransomware statistics"""
        if not hasattr(self, 'ransomware_alerts_count'):
            return
        
        # Update alert count
        count = len(self.app.ransomware_detector.alert_history)
        self.ransomware_alerts_count.config(text=str(count))
        
        # Update status
        if self.app.config.get("ransomware_detection", True):
            self.ransomware_status.config(text="✅ ACTIVE", fg="#27ae60")
        else:
            self.ransomware_status.config(text="⏸️ PAUSED", fg="#f39c12")
        
        # Schedule next update
        self.frame.after(3000, self.update_ransomware_stats)
    
    def configure_ransomware_detection(self):
        """Configure ransomware detection settings"""
        config_window = tk.Toplevel(self.frame)
        config_window.title("Ransomware Detection Configuration")
        config_window.geometry("600x500")
        config_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        config_window.resizable(False, False)
        config_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(config_window, text="⚙️ Ransomware Detection Settings", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Enable/disable detection
        enable_frame = tk.Frame(config_window, bg=t["bg"])
        enable_frame.pack(fill="x", padx=30, pady=20)
        
        self.ransomware_enable_var = tk.BooleanVar(value=self.app.config.get("ransomware_detection", True))
        enable_cb = tk.Checkbutton(enable_frame, text="Enable ransomware detection", 
                                  variable=self.ransomware_enable_var,
                                  bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                  font=("Segoe UI", 12, "bold"))
        enable_cb.pack(anchor="w")
        
        # Threshold settings
        threshold_frame = tk.LabelFrame(config_window, text="📊 Detection Thresholds", 
                                       bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                       padx=20, pady=20)
        threshold_frame.pack(fill="x", padx=30, pady=20)
        
        # Mass rename threshold
        rename_frame = tk.Frame(threshold_frame, bg=t["bg"])
        rename_frame.pack(fill="x", pady=10)
        
        tk.Label(rename_frame, text="Mass rename threshold:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=25, anchor="w").pack(side="left")
        
        self.mass_rename_var = tk.IntVar(value=self.app.ransomware_detector.mass_rename_threshold)
        rename_scale = tk.Scale(rename_frame, from_=5, to=50, orient="horizontal",
                               variable=self.mass_rename_var,
                               bg=t["entry_bg"], fg=t["fg"], length=200)
        rename_scale.pack(side="left", padx=10)
        
        tk.Label(rename_frame, text=f"({self.mass_rename_var.get()} files)", 
                fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10)).pack(side="left", padx=10)
        
        # Mass delete threshold
        delete_frame = tk.Frame(threshold_frame, bg=t["bg"])
        delete_frame.pack(fill="x", pady=10)
        
        tk.Label(delete_frame, text="Mass delete threshold:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=25, anchor="w").pack(side="left")
        
        self.mass_delete_var = tk.IntVar(value=self.app.ransomware_detector.mass_delete_threshold)
        delete_scale = tk.Scale(delete_frame, from_=5, to=50, orient="horizontal",
                               variable=self.mass_delete_var,
                               bg=t["entry_bg"], fg=t["fg"], length=200)
        delete_scale.pack(side="left", padx=10)
        
        tk.Label(delete_frame, text=f"({self.mass_delete_var.get()} files)", 
                fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10)).pack(side="left", padx=10)
        
        # Detection window
        window_frame = tk.Frame(threshold_frame, bg=t["bg"])
        window_frame.pack(fill="x", pady=10)
        
        tk.Label(window_frame, text="Detection window (seconds):", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=25, anchor="w").pack(side="left")
        
        self.detection_window_var = tk.IntVar(value=self.app.ransomware_detector.detection_window)
        window_scale = tk.Scale(window_frame, from_=30, to=300, orient="horizontal",
                               variable=self.detection_window_var,
                               bg=t["entry_bg"], fg=t["fg"], length=200)
        window_scale.pack(side="left", padx=10)
        
        tk.Label(window_frame, text=f"({self.detection_window_var.get()}s)", 
                fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10)).pack(side="left", padx=10)
        
        # Action buttons
        button_frame = tk.Frame(config_window, bg=t["bg"])
        button_frame.pack(pady=30)
        
        tk.Button(button_frame, text="💾 Save Settings", 
                 command=lambda: self.save_ransomware_settings(config_window),
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(side="left", padx=15)
        
        tk.Button(button_frame, text="❌ Cancel", 
                 command=config_window.destroy,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(side="left", padx=15)
    
    def save_ransomware_settings(self, window):
        """Save ransomware detection settings"""
        # Update config
        self.app.config["ransomware_detection"] = self.ransomware_enable_var.get()
        from config.settings import save_config
        save_config(self.app.config)
        
        # Update detector settings
        self.app.ransomware_detector.mass_rename_threshold = self.mass_rename_var.get()
        self.app.ransomware_detector.mass_delete_threshold = self.mass_delete_var.get()
        self.app.ransomware_detector.detection_window = self.detection_window_var.get()
        
        # Enable/disable detection
        if self.ransomware_enable_var.get():
            self.app.ransomware_detector.enable_detection()
        else:
            self.app.ransomware_detector.disable_detection()
        
        messagebox.showinfo("Settings Saved", "Ransomware detection settings saved!")
        window.destroy()
    
    def view_ransomware_history(self):
        """View detailed ransomware alert history"""
        history_window = tk.Toplevel(self.frame)
        history_window.title("Ransomware Alert History")
        history_window.geometry("800x600")
        history_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        history_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(history_window, text="📜 Ransomware Alert History", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # History list with scrollbar
        main_frame = tk.Frame(history_window, bg=t["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        scrollbar = tk.Scrollbar(main_frame, bg=t["bg"])
        scrollbar.pack(side="right", fill="y")
        
        history_text = tk.Text(main_frame, bg=t["text_bg"], fg=t["text_fg"],
                              font=("Segoe UI", 10), wrap="word",
                              yscrollcommand=scrollbar.set)
        history_text.pack(fill="both", expand=True)
        
        scrollbar.config(command=history_text.yview)
        
        # Populate history
        alerts = self.app.ransomware_detector.get_alerts(limit=50)
        
        if alerts:
            for alert in reversed(alerts):
                timestamp = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                pattern = alert['data'].get('pattern', 'Unknown')
                
                history_text.insert("end", f"🕐 {timestamp}\n")
                history_text.insert("end", f"🚨 Pattern: {pattern}\n")
                
                for key, value in alert['data'].items():
                    if key != 'pattern':
                        history_text.insert("end", f"   • {key}: {value}\n")
                
                history_text.insert("end", "-" * 60 + "\n\n")
        else:
            history_text.insert("end", "✅ No ransomware alerts detected yet.\n\n")
        
        history_text.configure(state="disabled")
        
        # Close button
        tk.Button(history_window, text="Close", command=history_window.destroy,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(pady=20)
    
    def clear_ransomware_history(self):
        """Clear ransomware alert history"""
        if messagebox.askyesno("Clear History", 
                              "Clear all ransomware alert history?\n\n"
                              "This action cannot be undone."):
            self.app.ransomware_detector.clear_alerts()
            self.update_ransomware_history()
            messagebox.showinfo("Cleared", "Ransomware alert history cleared.")
    
    def update_ransomware_history(self):
        """Update ransomware history display"""
        if not hasattr(self, 'ransomware_history'):
            return
        
        self.ransomware_history.configure(state="normal")
        self.ransomware_history.delete("1.0", "end")
        
        # Get recent alerts
        alerts = self.app.ransomware_detector.get_alerts(limit=10)
        
        if alerts:
            self.ransomware_history.insert("end", f"📋 Last {len(alerts)} alerts:\n\n")
            
            for alert in alerts:
                timestamp = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')
                pattern = alert['data'].get('pattern', 'Unknown')
                
                self.ransomware_history.insert("end", f"[{timestamp}] {pattern}\n")
        else:
            self.ransomware_history.insert("end", "✅ No ransomware alerts detected.\n\n"
                                              "System is clean and monitoring actively.")
        
        self.ransomware_history.configure(state="disabled")