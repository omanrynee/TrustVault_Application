"""
Monitor tab for TrustVault - Complete with All Features
Web Dashboard Integration Added
"""

import sys
import os

# Add the project root to Python's path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))  # Go up twice: gui/tabs → gui → project_root
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
from datetime import datetime
import json

from config import constants

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    MONITORING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import watchdog: {e}")
    MONITORING_AVAILABLE = False


class FastFileHandler(FileSystemEventHandler):
    """Optimized file handler with dashboard, anomaly, and ransomware features"""
    
    def __init__(self, log_callback, monitored_path, config, app=None):
        super().__init__()
        self.log_callback = log_callback
        self.monitored_path = monitored_path
        self.config = config
        self.app = app
        self.event_count = 0
# File type emojis
        self.type_map = {
            '.txt': '📄', '.doc': '📝', '.docx': '📝', '.pdf': '📕',
            '.xls': '📊', '.xlsx': '📊', '.ppt': '📊', '.pptx': '📊',
            '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
            '.mp3': '🎵', '.wav': '🎵', '.mp4': '🎬', '.avi': '🎬',
            '.zip': '📦', '.rar': '📦', '.7z': '📦',
            '.py': '🐍', '.js': '📜', '.html': '🌐', '.css': '🎨',
            '.json': '📋', '.xml': '📋', '.exe': '⚙️', '.dll': '⚙️',
            '.log': '📝', '.tmp': '🗑️', '.temp': '🗑️',
        }
        
        # Ransomware detection patterns
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
            '.cerber', '.locky', '.zepto', '.odin', '.shit', '.fuck'
        ]
        
        print("[FastFileHandler] Initialized with all features")
    
    def get_icon(self, path, is_directory):
        """Get emoji icon for file/folder"""
        if is_directory:
            return "📁"
        ext = os.path.splitext(path)[1].lower()
        return self.type_map.get(ext, '📄')
    
    def get_relative_path(self, path):
        """Get clean relative path"""
        try:
            rel = os.path.relpath(path, self.monitored_path)
            if rel == '.':
                return os.path.basename(path)
            return rel
        except:
            return os.path.basename(path)
    
    def check_ransomware(self, path):
        """Check for ransomware indicators"""
        if not self.config.get("ransomware_detection", True):
            return False
        
        filename = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()
        
        # Check suspicious extensions
        if ext in self.ransomware_extensions:
            return True
        
        # Check for ransom note patterns
        ransom_keywords = ['readme', 'decrypt', 'recover', 'ransom', 'payment']
        if any(keyword in filename for keyword in ransom_keywords):
            if ext in ['.txt', '.html', '.htm']:
                return True
        
        return False

    
    def send_ransomware_alert(self, path):
        """Send critical ransomware alert"""
        if self.config.get("alert_popup", True):
            try:
                import tkinter.messagebox as mb
                mb.showwarning(
                    "Ransomware Alert",
                    f"Suspicious file detected:\n\n{path}\n\nThis may be ransomware activity!"
                )
            except:
                pass
    
    def send_to_web_dashboard(self, event_type, path, is_directory=False, dest_path=None):
        """Send event to web dashboard if enabled"""
        try:
            # Check if web dashboard exists and is running
            if hasattr(self.app, 'web_dashboard') and self.app.web_dashboard and self.app.web_dashboard.is_running:
                
                # Create event for web dashboard
                icon = self.get_icon(path, is_directory)
                rel_path = self.get_relative_path(path)
                
                # Determine severity
                severity = "info"
                if "RANSOMWARE" in event_type:
                    severity = "critical"
                elif event_type == "DELETED":
                    severity = "critical"
                elif event_type == "MODIFIED":
                    severity = "warning"
                
                # Create event object
                web_event = {
                    "event_type": event_type,
                    "severity": severity,
                    "message": f"{icon} {rel_path}",
                    "file": path,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Add destination for moved events
                if dest_path:
                    web_event["destination"] = dest_path
                    web_event["message"] = f"{icon} {rel_path} → {self.get_relative_path(dest_path)}"
                
                # Send to web dashboard
                self.app.web_dashboard.add_event(web_event)
                
                # Debug log
                if self.config.get("debug_mode", False):
                    print(f"[WebDashboard] Event sent: {event_type} - {rel_path}")
                    
        except Exception as e:
            print(f"[WebDashboard] Error sending event: {e}")
    
    def send_to_anomaly_detector(self, event_type, path):
        """Send event to anomaly detector"""
        try:
            if hasattr(self.app, 'anomaly_detector') and self.app.anomaly_detector:
                # Record event in anomaly detector
                anomaly, rate, status = self.app.anomaly_detector.record_event(event_type, path)
                
                # If anomaly detected, send to web dashboard
                if anomaly and hasattr(self.app, 'web_dashboard') and self.app.web_dashboard:
                    anomaly_event = {
                        "event_type": "ANOMALY_DETECTED",
                        "severity": "critical",
                        "message": f"🚨 Anomaly detected! Rate: {rate:.1f} events/min",
                        "file": path,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.app.web_dashboard.add_event(anomaly_event)
                    
        except Exception as e:
            print(f"[AnomalyDetector] Error: {e}")
    
    def log_event(self, event_type, path, is_directory=False, dest_path=None):
        """Log event with all features"""
        try:
            self.event_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S')
            icon = self.get_icon(path, is_directory)
            rel_path = self.get_relative_path(path)
            
            # Send to web dashboard FIRST (before any UI updates)
            self.send_to_web_dashboard(event_type, path, is_directory, dest_path)
            
            # Send to anomaly detector
            self.send_to_anomaly_detector(event_type, path)
            
            # Check for ransomware
            is_ransomware = False
            if event_type == 'CREATED':
                is_ransomware = self.check_ransomware(path)
                if is_ransomware:
                    # Send ransomware alert to dashboard
                    if hasattr(self.app, 'web_dashboard') and self.app.web_dashboard:
                        ransom_event = {
                            "event_type": "RANSOMWARE_DETECTED",
                            "severity": "critical",
                            "message": f"🚨 Ransomware detected: {rel_path}",
                            "file": path,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        self.app.web_dashboard.add_event(ransom_event)
                    self.send_ransomware_alert(path)
            
            # Format log message
            if dest_path:
                dest_rel = self.get_relative_path(dest_path)
                message = f"[{timestamp}] 📦 MOVED {icon} '{rel_path}' → '{dest_rel}'"
            else:
                type_names = {
                    'CREATED': '✅ CREATED',
                    'MODIFIED': '✏️ MODIFIED',
                    'DELETED': '🗑️ DELETED'
                }
                type_str = type_names.get(event_type, event_type)
                
                if is_ransomware:
                    message = f"[{timestamp}] 🚨 RANSOMWARE DETECTED {icon} '{rel_path}'"
                else:
                    message = f"[{timestamp}] {type_str} {icon} '{rel_path}'"
            
            # Send to UI log
            if self.log_callback:
                self.log_callback(message)
            
            # Console log
            print(f"[EVENT #{self.event_count}] {message}")
            
        except Exception as e:
            print(f"[ERROR] Failed to log event: {e}")
    
    def on_created(self, event):
        print(f"[WATCHDOG] Created: {event.src_path}")
        self.log_event('CREATED', event.src_path, event.is_directory)
    
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[WATCHDOG] Modified: {event.src_path}")
            self.log_event('MODIFIED', event.src_path, event.is_directory)
    
    def on_deleted(self, event):
        print(f"[WATCHDOG] Deleted: {event.src_path}")
        self.log_event('DELETED', event.src_path, event.is_directory)
    
    def on_moved(self, event):
        print(f"[WATCHDOG] Moved: {event.src_path} → {event.dest_path}")
        self.log_event('MOVED', event.src_path, event.is_directory, event.dest_path)


class MonitorTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.observer = None
        self.handler = None
        self.monitoring = False
        self.monitored_path = None
        self.build_ui()
    
    def build_ui(self):
        """Build complete monitoring UI"""
        t = constants.THEMES[self.app.config["theme"]]
        main_frame = tk.Frame(self.frame, bg=t["bg"])
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Control frame
        control_frame = tk.LabelFrame(main_frame, text="📁 Real-Time Folder Monitoring", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                     padx=20, pady=20)
        control_frame.pack(fill="x", pady=(0, 20))
        
        # Folder selection
        folder_row = tk.Frame(control_frame, bg=t["bg"])
        folder_row.pack(fill="x", pady=10)
        tk.Label(folder_row, text="Monitor Folder:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=15, anchor="w").pack(side="left")
        self.folder_path = tk.Entry(folder_row, width=60, font=("Segoe UI", 12), 
                                   bg=t["entry_bg"], fg=t["fg"])
        self.folder_path.pack(side="left", padx=10, fill="x", expand=True)
        tk.Button(folder_row, text="📁 Browse", command=self.browse_monitor_folder, 
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"),
                 cursor="hand2").pack(side="left", padx=5)
        
        # Start/Stop button
        button_row = tk.Frame(control_frame, bg=t["bg"])
        button_row.pack(fill="x", pady=15)
        self.monitor_button = tk.Button(button_row, text="▶️ Start Monitoring", 
                                       command=self.toggle_monitoring,
                                       bg="#27ae60", fg="white", 
                                       font=("Segoe UI", 12, "bold"),
                                       padx=30, pady=10, cursor="hand2")
        self.monitor_button.pack(side="left", padx=5)
        self.status_label = tk.Label(button_row, text="● Stopped", 
                                    fg="#e74c3c", bg=t["bg"],
                                    font=("Segoe UI", 12, "bold"))
        self.status_label.pack(side="left", padx=20)
        
        # Options frame
        options_frame = tk.LabelFrame(control_frame, text="⚙️ Monitoring Options",
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 12, "bold"),
                                     padx=15, pady=15)
        options_frame.pack(fill="x", pady=10)
        options_grid = tk.Frame(options_frame, bg=t["bg"])
        options_grid.pack()
        
        # Row 1: Recursive
        row1 = tk.Frame(options_grid, bg=t["bg"])
        row1.pack(fill="x", pady=5)
        self.recursive_var = tk.BooleanVar(value=self.app.config.get("monitor_recursive", True))
        tk.Checkbutton(row1, text="📂 Monitor Subfolders", variable=self.recursive_var,
                      command=lambda: self.update_setting("monitor_recursive", self.recursive_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        
        # Row 2: Email and Popup
        row2 = tk.Frame(options_grid, bg=t["bg"])
        row2.pack(fill="x", pady=5)
        self.email_var = tk.BooleanVar(value=self.app.config.get("email_alerts", False))
        tk.Checkbutton(row2, text="📧 Email Alerts", variable=self.email_var,
                      command=lambda: self.update_setting("email_alerts", self.email_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        self.popup_var = tk.BooleanVar(value=self.app.config.get("alert_popup", True))
        tk.Checkbutton(row2, text="💬 Popup Alerts", variable=self.popup_var,
                      command=lambda: self.update_setting("alert_popup", self.popup_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        
        # Row 3: Ransomware and Anomaly
        row3 = tk.Frame(options_grid, bg=t["bg"])
        row3.pack(fill="x", pady=5)
        self.ransomware_var = tk.BooleanVar(value=self.app.config.get("ransomware_detection", True))
        tk.Checkbutton(row3, text="🚨 Ransomware Detection", variable=self.ransomware_var,
                      command=lambda: self.update_setting("ransomware_detection", self.ransomware_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        self.anomaly_var = tk.BooleanVar(value=self.app.config.get("anomaly_detection", True))
        tk.Checkbutton(row3, text="🔍 Anomaly Detection", variable=self.anomaly_var,
                      command=lambda: self.update_setting("anomaly_detection", self.anomaly_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        
        # Web Dashboard option
        row4 = tk.Frame(options_grid, bg=t["bg"])
        row4.pack(fill="x", pady=5)
        self.web_dashboard_var = tk.BooleanVar(value=self.app.config.get("web_dashboard", False))
        tk.Checkbutton(row4, text="🌐 Web Dashboard", variable=self.web_dashboard_var,
                      command=self.toggle_web_dashboard,
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                      font=("Segoe UI", 11)).pack(side="left", padx=20)
        
        # Log display
        log_frame = tk.LabelFrame(main_frame, text="📝 Live Event Log", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                 padx=10, pady=10)
        log_frame.pack(fill="both", expand=True)
        log_scroll = tk.Scrollbar(log_frame)
        log_scroll.pack(side="right", fill="y")
        self.log_output = tk.Text(log_frame, height=20, bg=t["text_bg"], fg=t["text_fg"], 
                                 font=("Segoe UI", 10), wrap="word",
                                 yscrollcommand=log_scroll.set, state="disabled")
        self.log_output.pack(fill="both", expand=True, padx=5, pady=5)
        log_scroll.config(command=self.log_output.yview)
        
        # Log controls
        log_controls = tk.Frame(log_frame, bg=t["bg"])
        log_controls.pack(fill="x", pady=5)
        tk.Button(log_controls, text="🗑️ Clear Log", command=self.clear_log,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"),
                 cursor="hand2").pack(side="left", padx=5)
        tk.Button(log_controls, text="💾 Save Log", command=self.save_logs_csv,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"),
                 cursor="hand2").pack(side="left", padx=5)
        
        # Test buttons for web dashboard
        test_frame = tk.Frame(log_frame, bg=t["bg"])
        test_frame.pack(fill="x", pady=5)
        tk.Button(test_frame, text="📊 Test Web Dashboard", command=self.test_web_dashboard,
                 bg="#9b59b6", fg="white", font=("Segoe UI", 10, "bold"),
                 cursor="hand2").pack(side="left", padx=5)
        tk.Button(test_frame, text="🌐 Open Dashboard", command=self.open_web_dashboard,
                 bg="#3498db", fg="white", font=("Segoe UI", 10, "bold"),
                 cursor="hand2").pack(side="left", padx=5)
        
        # Status bar
        status_bar = tk.Frame(main_frame, bg=t["bg"], height=25)
        status_bar.pack(fill="x", pady=(10, 0))
        self.status_text = tk.Label(status_bar, text="Ready to monitor", 
                                   fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10))
        self.status_text.pack(side="left", padx=10)
        self.stats_text = tk.Label(status_bar, text="Events: 0", 
                                  fg="#3498db", bg=t["bg"], font=("Segoe UI", 10, "bold"))
        self.stats_text.pack(side="right", padx=10)
        self.update_stats()
    
    def update_setting(self, key, value):
        self.app.config[key] = value
        if self.app.config.get("auto_save", True):
            try:
                from config.settings import save_config
                save_config(self.app.config)
            except: pass

    
    def toggle_web_dashboard(self):
        enabled = self.web_dashboard_var.get()
        self.update_setting("web_dashboard", enabled)
        
        if enabled:
            # Start web dashboard
            self.start_web_dashboard()
        else:
            # Stop web dashboard
            self.stop_web_dashboard()
    
    def start_web_dashboard(self):
        """Start web dashboard server"""
        try:
            from gui.webdashboard_server import WebDashboardServer
            
            if not hasattr(self.app, 'web_dashboard') or not self.app.web_dashboard:
                port = self.app.config.get("dashboard_port", 5000)
                self.app.web_dashboard = WebDashboardServer(port=port, debug=True)
            
            success, url = self.app.web_dashboard.start()
            if success:
                messagebox.showinfo("Web Dashboard", f"✅ Web dashboard started at:\n\n{url}")
                self.log_message("✅ Web dashboard started")
            else:
                messagebox.showerror("Web Dashboard", f"Failed to start web dashboard:\n{url}")
                self.web_dashboard_var.set(False)
                
        except ImportError as e:
            messagebox.showerror("Web Dashboard", f"Flask not installed:\n\npip install flask flask-socketio")
            self.web_dashboard_var.set(False)
        except Exception as e:
            messagebox.showerror("Web Dashboard", f"Error starting web dashboard:\n{str(e)}")
            self.web_dashboard_var.set(False)
    
    def stop_web_dashboard(self):
        """Stop web dashboard server"""
        try:
            if hasattr(self.app, 'web_dashboard') and self.app.web_dashboard:
                success, message = self.app.web_dashboard.stop()
                if success:
                    self.log_message("🛑 Web dashboard stopped")
                else:
                    self.log_message(f"⚠️ Failed to stop web dashboard: {message}")
        except Exception as e:
            print(f"Error stopping web dashboard: {e}")
    
    def test_web_dashboard(self):
        """Send test event to web dashboard"""
        try:
            if hasattr(self.app, 'web_dashboard') and self.app.web_dashboard and self.app.web_dashboard.is_running:
                # Send test event
                self.app.web_dashboard.add_event({
                    "event_type": "TEST_EVENT",
                    "severity": "info",
                    "message": "Test event from Monitor Tab",
                    "file": "/test/path.txt",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                messagebox.showinfo("Test Successful", "✅ Test event sent to web dashboard!")
                self.log_message("✅ Web dashboard test event sent")
            else:
                messagebox.showwarning("Dashboard Not Running", "Web dashboard is not running. Enable it in settings.")
        except Exception as e:
            messagebox.showerror("Test Failed", f"Error testing web dashboard:\n{str(e)}")
    
    def open_web_dashboard(self):
        """Open web dashboard in browser"""
        try:
            if hasattr(self.app, 'web_dashboard') and self.app.web_dashboard and self.app.web_dashboard.is_running:
                import webbrowser
                url = self.app.web_dashboard.get_url()
                webbrowser.open(url)
                self.log_message(f"🌐 Opening dashboard: {url}")
            else:
                messagebox.showwarning("Dashboard Not Running", "Web dashboard is not running. Enable it in settings.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open dashboard:\n{str(e)}")

    
    def browse_monitor_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Monitor")
        if folder:
            self.folder_path.delete(0, tk.END)
            self.folder_path.insert(0, folder)
    
    def toggle_monitoring(self):
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def log_message(self, message):
        try:
            def update_log():
                self.log_output.configure(state="normal")
                self.log_output.insert("end", f"{message}\n")
                self.log_output.see("end")
                self.log_output.configure(state="disabled")
            self.frame.after(0, update_log)
        except Exception as e:
            print(f"[ERROR] Failed to log message: {e}")
    
    def start_monitoring(self):
        path = self.folder_path.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a folder to monitor!")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", f"Folder does not exist:\n{path}")
            return
        if not os.path.isdir(path):
            messagebox.showerror("Error", f"Path is not a directory:\n{path}")
            return
        if not MONITORING_AVAILABLE:
            messagebox.showerror("Error", "Watchdog not installed!\n\nInstall with: pip install watchdog")
            return
        try:
            self.app.config["send_email_alerts"] = self.email_var.get()
            self.app.config["alert_popup"] = self.popup_var.get()
            self.app.config["ransomware_detection"] = self.ransomware_var.get()
            self.app.config["anomaly_detection"] = self.anomaly_var.get()
            
            print(f"\n{'='*60}\nSTARTING MONITORING\nPath: {path}\n{'='*60}\n")
            
            # Create handler with app reference for web dashboard access
            self.handler = FastFileHandler(log_callback=self.log_message, monitored_path=path,
                                          config=self.app.config, app=self.app)
            self.observer = Observer()
            self.observer.schedule(self.handler, path, recursive=self.recursive_var.get())
            self.observer.start()
            
            self.monitoring = True
            self.monitored_path = path
            self.app.monitoring = True
            self.app.monitor = self
            
            self.monitor_button.config(text="⏹️ Stop Monitoring", bg="#e74c3c")
            self.status_label.config(text="● ACTIVE", fg="#27ae60")
            self.status_text.config(text=f"Monitoring: {os.path.basename(path)}")
            
            self.log_message("=" * 80)
            self.log_message(f"🚀 MONITORING STARTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.log_message(f"📁 Path: {path}")
            self.log_message(f"📂 Recursive: {'Yes' if self.recursive_var.get() else 'No'}")
            if self.email_var.get():
                self.log_message("📧 Email Alerts: ENABLED ✅")
            if self.ransomware_var.get():
                self.log_message("🚨 Ransomware Detection: ENABLED ✅")
            if self.anomaly_var.get():
                self.log_message("🔍 Anomaly Detection: ENABLED ✅")
            if self.popup_var.get():
                self.log_message("💬 Popup Alerts: ENABLED ✅")
            if self.web_dashboard_var.get():
                self.log_message("🌐 Web Dashboard: ENABLED ✅")
            self.log_message("=" * 80)
            self.log_message("⚡ Real-time monitoring active\n")
            
            messagebox.showinfo("Monitoring Active", 
                f"✅ Real-time monitoring started!\n\n📁 Folder: {path}\n\n💡 All file changes will appear instantly!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start monitoring:\n\n{str(e)}")
            import traceback
            traceback.print_exc()
            if self.observer:
                try: self.observer.stop()
                except: pass
            self.observer = None
            self.handler = None
            self.monitoring = False
    
    def stop_monitoring(self):
        if not self.monitoring:
            return
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=2)
            self.monitoring = False
            self.monitored_path = None
            self.app.monitoring = False
            self.app.monitor = None
            self.observer = None
            self.handler = None
            self.monitor_button.config(text="▶️ Start Monitoring", bg="#27ae60")
            self.status_label.config(text="● Stopped", fg="#e74c3c")
            self.status_text.config(text="Ready to monitor")
            self.log_message(f"\n{'=' * 80}\n⏹️ MONITORING STOPPED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'=' * 80}")
        except Exception as e:
            messagebox.showerror("Error", f"Error stopping monitoring:\n\n{str(e)}")
    
    def clear_log(self):
        self.log_output.configure(state="normal")
        self.log_output.delete("1.0", "end")
        self.log_output.insert("end", f"✨ Log cleared - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        self.log_output.configure(state="disabled")
    
    def save_logs_csv(self):
        """Save logs to CSV file - FIXED to use project's CSV_logs folder"""
        try:
            import csv
            import os
            
            content = self.log_output.get("1.0", "end-1c")
            if not content.strip():
                messagebox.showinfo("Empty Log", "No logs to save.")
                return
            
            # ===== FIXED PATH CALCULATION =====
            # Calculate project root based on current file location
            # Assuming structure: SecureFIM-Pro/CSV_logs/
            # and this file is in: SecureFIM-Pro/gui/tabs/monitor_tab.py
            
            # Get the directory of this file
            current_file_path = os.path.abspath(__file__)  # Full path to monitor_tab.py
            current_dir = os.path.dirname(current_file_path)  # gui/tabs/
            
            # Navigate up: gui/tabs → gui → project_root
            gui_dir = os.path.dirname(current_dir)          # gui/
            project_root = os.path.dirname(gui_dir)         # project_root/
            
            # Target CSV_logs folder
            logs_dir = os.path.join(project_root, "CSV_logs")
            
            print(f"[DEBUG] Current file: {current_file_path}")
            print(f"[DEBUG] Project root: {project_root}")
            print(f"[DEBUG] CSV logs folder: {logs_dir}")
            # =================================
            
            # Create logs directory if it doesn't exist
            os.makedirs(logs_dir, exist_ok=True)
            
            # Create filename with timestamp
            filename = f"monitor_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            full_path = os.path.join(logs_dir, filename)
            
            lines = content.split('\n')
            with open(full_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Event Type', 'Details'])
                
                for line in lines:
                    if line.strip() and not line.startswith('='):
                        if '[' in line and ']' in line:
                            parts = line.split(']', 1)
                            timestamp = parts[0].replace('[', '').strip()
                            rest = parts[1].strip() if len(parts) > 1 else ''
                            
                            event_type = 'Info'
                            if '✅' in rest or 'CREATED' in rest: 
                                event_type = 'Created'
                            elif '✏️' in rest or 'MODIFIED' in rest: 
                                event_type = 'Modified'
                            elif '🗑️' in rest or 'DELETED' in rest: 
                                event_type = 'Deleted'
                            elif '📦' in rest or 'MOVED' in rest: 
                                event_type = 'Moved'
                            elif '⚠️' in rest or 'WARNING' in rest: 
                                event_type = 'Warning'
                            elif '❌' in rest or 'ERROR' in rest: 
                                event_type = 'Error'
                            elif '🚨' in rest or 'RANSOMWARE' in rest:
                                event_type = 'Ransomware Alert'
                            
                            writer.writerow([timestamp, event_type, rest])
                        else:
                            writer.writerow([datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Info', line])
            
            messagebox.showinfo("Logs Saved", f"Logs saved successfully to:\n{full_path}")
            
            # Open folder - FIXED to use the correct path
            if messagebox.askyesno("Open Folder", "Would you like to open the logs folder?"):
                import subprocess
                import platform
                
                folder_path = os.path.abspath(logs_dir)
                print(f"[DEBUG] Opening folder: {folder_path}")
                
                if platform.system() == 'Windows':
                    os.startfile(folder_path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.run(['open', folder_path])
                else:  # Linux
                    subprocess.run(['xdg-open', folder_path])
                    
        except Exception as e:
            messagebox.showerror("Save Error", f"Error saving logs:\n\n{str(e)}")
            import traceback
            traceback.print_exc()
    
    def update_stats(self):
        """Update monitoring statistics"""
        try:
            if self.monitoring and self.handler:
                event_count = self.handler.event_count
                self.stats_text.config(text=f"Events: {event_count}")
            else:
                self.stats_text.config(text="Events: 0")
        except:
            pass
        
        # Schedule next update
        self.frame.after(1000, self.update_stats)

    def get_status(self):
        """Get monitoring status for external access"""
        return {
            "is_running": self.monitoring,
            "path": self.monitored_path,
            "event_count": self.handler.event_count if self.handler else 0,
            "features": {
                "ransomware_detection": self.ransomware_var.get(),
                "anomaly_detection": self.anomaly_var.get(),
                "recursive": self.recursive_var.get(),
                "web_dashboard": self.web_dashboard_var.get()
            }
        }
    
    def cleanup(self):
        """Cleanup resources when tab is closed"""
        if self.monitoring:
            self.stop_monitoring()
        return True
