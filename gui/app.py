"""
Main application class for TrustVault
"""

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox
import threading
import time
import os
import sys
from datetime import datetime
import socket
from typing import Dict, Optional

from config import settings, constants
from gui.login_window import show_login
from security.anomaly_detector import AnomalyDetector
from security.hash_verifier import FileHashVerifier
from security.ransomware_detector import RansomwareDetector
from alerts.notifier import AlertNotifier

# Try to import monitoring modules (they might not exist yet)
try:
    from monitoring.observer import FileMonitor
    from monitoring.handler import EnhancedRealtimeHandler
    MONITORING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Monitoring modules not available: {e}")
    print("Install required packages: pip install watchdog requests")
    MONITORING_AVAILABLE = False
    FileMonitor = None
    EnhancedRealtimeHandler = None

class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System")
        self._configure_default_fonts()
        
        # Load configuration
        self.config = settings.load_config()
        
        # Ensure config has monitoring-related settings
        self._initialize_config_defaults()
        
        # Initialize monitoring state
        self.monitoring = False
        self.monitor = None
        self.monitored_path = None
        self.start_time = None
        
        # Initialize components
        self._initialize_components()
        
        # Combined log storage
        self.combined_logs = []
        
        # Show login screen
        if not self.show_login():
            self.root.destroy()
            return
        
        # Setup main application
        self.setup_ui()
        self.apply_theme()
        self.setup_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Start background tasks
        self.update_status_bar()
        
        # Check if web dashboard should auto-start
        if self.config.get("web_dashboard", False):
            self.root.after(2000, self.auto_start_web_dashboard)
    
    def _configure_default_fonts(self):
        """Set the application font for Tk and ttk widgets."""
        default_family = constants.THEME_FONT
        named_fonts = (
            "TkDefaultFont",
            "TkTextFont",
            "TkFixedFont",
            "TkMenuFont",
            "TkHeadingFont",
            "TkCaptionFont",
            "TkSmallCaptionFont",
            "TkIconFont",
            "TkTooltipFont",
        )
        for font_name in named_fonts:
            try:
                tkfont.nametofont(font_name).configure(family=default_family)
            except tk.TclError:
                pass
    def _initialize_config_defaults(self):
        """Initialize default configuration values for monitoring"""
        defaults = {
            "theme": constants.DEFAULT_THEME,
            "window_size": "1400x800",
            "auto_save": True,
            "send_email_alerts": False,
            "ransomware_detection": True,
            "anomaly_detection": True,
            "hash_verification": False,
            "web_dashboard": False,
            "monitor_recursive": True,
            "alert_sound": True,
            "alert_popup": True,
            "last_user": "Administrator",
            "debug_mode": True
        }
        
        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value

        if self.config.get("theme") not in constants.THEMES:
            self.config["theme"] = constants.DEFAULT_THEME
    
    def _initialize_components(self):
        """Initialize all application components"""
        try:
            self.alert_notifier = AlertNotifier(config=self.config)
            
            self.anomaly_detector = None
            try:
                self.anomaly_detector = AnomalyDetector(
                    window_size=60, 
                    threshold=2.5,
                    alert_callback=self._alert_callback
                )
                print("[OK] Anomaly detector initialized")
                        
            except Exception as e:
                print(f"[WARN] Anomaly detector error: {e}")
                self.anomaly_detector = None
            
            self.hash_verifier = None
            try:
                self.hash_verifier = FileHashVerifier(
                    alert_callback=self._alert_callback
                )
                print("[OK] Hash verifier initialized")
            except Exception as e:
                print(f"[WARN] Hash verifier error: {e}")
                self.hash_verifier = None
            
            self.ransomware_detector = None
            try:
                self.ransomware_detector = RansomwareDetector(
                    alert_callback=self._alert_callback
                )
                print("[OK] Ransomware detector initialized")
            except Exception as e:
                print(f"[WARN] Ransomware detector error: {e}")
                self.ransomware_detector = None
            
            self.web_dashboard = None
            self.email_system = None
            
            self.certificate_manager = None
            try:
                from security.key_certificate import CertificateManager
                self.certificate_manager = CertificateManager()
                print("[OK] Certificate manager initialized for digital signatures")
            except ImportError as e:
                print(f"[WARN] Certificate manager not available: {e}")
            except Exception as e:
                print(f"[WARN] Error initializing certificate manager: {e}")
            
            print("[OK] All components initialized")
            
        except Exception as e:
            print(f"[ERROR] Error initializing components: {e}")
            import traceback
            traceback.print_exc()
    
    def _alert_callback(self, alert_type: str, title: str, message: str, 
                       details: Dict = None, file_path: str = None, channel: str = None):
        """Callback function for all alerts from detectors"""
        try:
            if hasattr(self, 'alert_notifier') and self.alert_notifier:
                return self.alert_notifier.notify(
                    alert_type=alert_type,
                    title=title,
                    message=message,
                    details=details,
                    file_path=file_path,
                    channel=channel
                )
            else:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[ALERT] {timestamp} [{alert_type}] {title}: {message}")
                return False
        except Exception as e:
            print(f"Error in alert callback: {e}")
            return False
    
    def show_login(self):
        """Show login screen"""
        return show_login(self.root, self.config)
    
    def setup_ui(self):
        """Setup the main user interface"""
        self.root.geometry(self.config["window_size"])
        
        t = constants.THEMES[self.config["theme"]]
        panel_bg = t.get("panel", t["bg"])
        top_bar = tk.Frame(self.root, bg=panel_bg, height=58, highlightthickness=1,
                           highlightbackground=t.get("border", panel_bg))
        top_bar.pack(fill="x", padx=14, pady=(12, 6))
        top_bar.pack_propagate(False)
        
        left_frame = tk.Frame(top_bar, bg=panel_bg)
        left_frame.pack(side="left", padx=20)
        
        tk.Button(left_frame, text="📅 Calendar", command=self.show_calendar,
                 bg=t["btn"], fg=t["btn_fg"], activebackground=t.get("accent_hover", t["btn"]),
                 activeforeground=t["btn_fg"], font=(constants.THEME_FONT, 11, "bold"),
                 relief="flat", bd=0, cursor="hand2", padx=15, pady=6).pack(side="left", padx=5)
        self.monitor_status = tk.Label(left_frame, text="⏹️ Stopped", 
                                      bg="#e74c3c", fg="white",
                                      font=(constants.THEME_FONT, 10, "bold"), padx=10, pady=4,
                                      relief="flat")
        self.monitor_status.pack(side="left", padx=10)
        
        self.alert_counter = tk.Label(left_frame, text="🚨 0 Alerts", 
                                     bg="#3498db", fg="white",
                                     font=(constants.THEME_FONT, 10, "bold"), padx=10, pady=4,
                                     relief="flat")
        self.alert_counter.pack(side="left", padx=10)
        
        right_frame = tk.Frame(top_bar, bg=panel_bg)
        right_frame.pack(side="right", padx=20)
        
        tk.Label(right_frame, text=f"👤 {self.config.get('last_user', 'User')}", 
                fg=t["fg"], bg=panel_bg, font=(constants.THEME_FONT, 11)).pack(side="right", padx=10)
        
        self.notebook = ttk.Notebook(self.root, style="Main.Vertical.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=14, pady=8)
        
        try:
            from gui.tabs.home_tab import HomeTab
            from gui.tabs.monitor_tab import MonitorTab
            from gui.tabs.anomaly_tab import AnomalyTab
            from gui.tabs.web_dashboard_tab import WebDashboardTab
            from gui.tabs.hash_verification_tab import HashVerificationTab
            from gui.tabs.ransomware_tab import RansomwareTab
            from gui.tabs.logs_tab import LogsTab
            from gui.tabs.users_tab import UsersTab
            from gui.tabs.settings_tab import SettingsTab
            from gui.tabs.crypto_ops_tab import CryptoOpsTab
            
            self.home_tab = HomeTab(self.notebook, self)
            self.monitor_tab = MonitorTab(self.notebook, self)
            self.anomaly_tab = AnomalyTab(self.notebook, self)
            self.web_dashboard_tab = WebDashboardTab(self.notebook, self)
            self.hash_tab = HashVerificationTab(self.notebook, self)
            self.ransomware_tab = RansomwareTab(self.notebook, self)
            self.logs_tab = LogsTab(self.notebook, self)
            self.users_tab = UsersTab(self.notebook, self)
            self.crypto_ops_tab = CryptoOpsTab(self.notebook, self)
            self.settings_tab = SettingsTab(self.notebook, self)
            
            self.monitor_tab = self.monitor_tab
            
            print("[OK] All tabs loaded successfully")
        except Exception as e:
            print(f"[ERROR] Error loading tabs: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Tab Error", f"Failed to load tabs:\n\n{str(e)}")
            return
        
        self.notebook.add(self.home_tab.frame, text="🏠 Home")
        self.notebook.add(self.monitor_tab.frame, text="🖥️ Monitor")
        self.notebook.add(self.anomaly_tab.frame, text="🔍 Anomaly")
        self.notebook.add(self.web_dashboard_tab.frame, text="🌐 Web Dashboard")
        self.notebook.add(self.hash_tab.frame, text="🔐 Hash Verify")
        self.notebook.add(self.ransomware_tab.frame, text="🚨 Ransomware")
        self.notebook.add(self.logs_tab.frame, text="📄 Logs")
        self.notebook.add(self.users_tab.frame, text="👤 Users")
        self.notebook.add(self.crypto_ops_tab.frame, text="🔏 Crypto Ops")
        self.notebook.add(self.settings_tab.frame, text="⚙️ Settings")
        
        self.status_bar = tk.Label(self.root, text="Ready", 
                                  bg=t.get("panel", t["bg"]), fg=t.get("muted", t["fg"]),
                                  font=(constants.THEME_FONT, 10),
                                  anchor="w", padx=20)
        self.status_bar.pack(side="bottom", fill="x", padx=14, pady=(6, 12))
        self.update_alert_counter()
    
    def log_event(self, event_data):
        """Log event to combined logs"""
        try:
            self.combined_logs.append(event_data)
            if len(self.combined_logs) > 1000:
                self.combined_logs = self.combined_logs[-1000:]
        except Exception as e:
            print(f"Error logging event: {e}")
    def update_alert_counter(self):
        """Update alert counter display"""
        if hasattr(self, 'alert_counter'):
            alert_count = 0
            if hasattr(self, 'alert_notifier') and self.alert_notifier:
                recent_alerts = self.alert_notifier.get_recent_alerts(limit=100)
                alert_count = len(recent_alerts)
                critical_alerts = [a for a in recent_alerts if a.get('type') in ['RANSOMWARE', 'CRITICAL', 'TAMPER']]
                
                if critical_alerts:
                    self.alert_counter.config(
                        text=f"🚨 {len(critical_alerts)} Alerts",
                        bg="#e74c3c"
                    )
                else:
                    self.alert_counter.config(
                        text=f"✅ {alert_count} Events",
                        bg="#3498db"
                    )
            else:
                self.alert_counter.config(
                    text=f"📊 {alert_count} Events",
                    bg="#3498db"
                )
            
            self.root.after(5000, self.update_alert_counter)
    
    def apply_theme(self):
        """Apply selected theme to all widgets"""
        t = constants.THEMES[self.config["theme"]]
        self.root.configure(bg=t["bg"])
        
        style = ttk.Style()
        style.theme_use('clam')
        app_font = (constants.THEME_FONT, 10)
        bold_font = (constants.THEME_FONT, 10, "bold")
        
        panel_bg = t.get("panel", t["bg"])
        panel_alt = t.get("panel_alt", panel_bg)
        border = t.get("border", panel_bg)
        muted = t.get("muted", t["fg"])
        accent_hover = t.get("accent_hover", t["btn"])

        style.configure(".", background=t["bg"], foreground=t["fg"], font=app_font)
        style.configure("TNotebook", background=t["bg"], borderwidth=0)
        style.configure("Main.Vertical.TNotebook", background=t["bg"], borderwidth=0, tabposition="wn")
        style.configure("TFrame", background=t["bg"], font=app_font)
        style.configure("TLabelframe", background=t["bg"], bordercolor=border, relief="solid", font=app_font)
        style.configure("TLabelframe.Label", background=t["bg"], foreground=t["btn"], font=bold_font)
        style.configure("TLabel", background=t["bg"], foreground=t["fg"], font=app_font)
        style.configure("TCheckbutton", background=t["bg"], foreground=t["fg"], font=app_font)
        style.configure("TRadiobutton", background=t["bg"], foreground=t["fg"], font=app_font)
        style.configure("TEntry", fieldbackground=t["entry_bg"], foreground=t["fg"],
                        bordercolor=border, lightcolor=border, darkcolor=border,
                        insertcolor=t["btn"], padding=5, font=app_font)
        style.configure("TCombobox", fieldbackground=t["entry_bg"], foreground=t["fg"],
                        background=panel_bg, arrowcolor=t["btn"], bordercolor=border,
                        padding=5, font=app_font)
        style.configure("TButton", background=t["btn"], foreground=t["btn_fg"],
                        borderwidth=0, focusthickness=2, focuscolor=t["btn"],
                        padding=(12, 7), font=bold_font)
        style.configure(
            "Treeview",
            background=t["text_bg"],
            fieldbackground=t["text_bg"],
            foreground=t["text_fg"],
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
            rowheight=28,
            font=app_font
        )
        style.configure(
            "Treeview.Heading",
            background=panel_alt,
            foreground=t["btn"],
            relief="flat",
            font=bold_font
        )
        style.configure("TNotebook.Tab", 
                       background=panel_bg,
                       foreground=t["fg"],
                       padding=[20, 10],
                       font=(constants.THEME_FONT, 10, "bold"))
        style.configure("Main.Vertical.TNotebook.Tab",
                       background=panel_bg,
                       foreground=t["fg"],
                       padding=[18, 13],
                       width=20,
                       anchor="w",
                       font=(constants.THEME_FONT, 10, "bold"))
        style.map("TButton",
                  background=[("active", accent_hover), ("pressed", t["select"])],
                  foreground=[("active", t["btn_fg"]), ("pressed", t["btn_fg"])])
        style.map("TEntry",
                  bordercolor=[("focus", t["btn"])],
                  lightcolor=[("focus", t["btn"])],
                  darkcolor=[("focus", t["btn"])])
        style.map("TCombobox",
                  bordercolor=[("focus", t["btn"])],
                  fieldbackground=[("readonly", t["entry_bg"])],
                  foreground=[("readonly", t["fg"])])
        style.map("Treeview",
                  background=[("selected", "#063b5a")],
                  foreground=[("selected", t["fg"])])
        style.map("TNotebook.Tab", 
                 background=[("selected", t["select"]), ("active", panel_alt)],
                 foreground=[("selected", t["btn_fg"]), ("active", t["fg"])])
        style.map("Main.Vertical.TNotebook.Tab",
                 background=[("selected", t["select"]), ("active", panel_alt)],
                 foreground=[("selected", t["btn_fg"]), ("active", t["fg"])])
    
    def change_theme(self):
        """Change application theme"""
        self.config["theme"] = constants.DEFAULT_THEME
        settings.save_config(self.config)
        self.apply_theme()
    
    def show_calendar(self):
        """Show a calendar popup window"""
        try:
            from tkcalendar import Calendar
            
            cal_win = tk.Toplevel(self.root)
            cal_win.title("Calendar")
            cal_win.geometry("400x450")
            t = constants.THEMES[self.config["theme"]]
            cal_win.configure(bg=t["bg"])
            cal_win.resizable(False, False)
            
            cal_win.update_idletasks()
            width = cal_win.winfo_width()
            height = cal_win.winfo_height()
            x = (cal_win.winfo_screenwidth() // 2) - (width // 2)
            y = (cal_win.winfo_screenheight() // 2) - (height // 2)
            cal_win.geometry(f'{width}x{height}+{x}+{y}')
            
            tk.Label(cal_win, text="📅 Calendar", font=("Segoe UI", 18, "bold"), 
                    fg=t["fg"], bg=t["bg"]).pack(pady=15)
            
            cal = Calendar(cal_win, selectmode='day', 
                          year=datetime.now().year, 
                          month=datetime.now().month,
                          day=datetime.now().day, 
                          background=t["btn"],
                          foreground=t["btn_fg"], 
                          selectbackground=t["select"],
                          selectforeground="white", 
                          borderwidth=2,
                          font=("Segoe UI", 12))
            cal.pack(pady=20, padx=20)
            
            selected_date_label = tk.Label(cal_win, text="", font=("Segoe UI", 12), 
                                          fg=t["fg"], bg=t["bg"])
            selected_date_label.pack(pady=10)
            
            def show_selected():
                date = cal.get_date()
                selected_date_label.config(text=f"Selected: {date}")
            
            btn_frame = tk.Frame(cal_win, bg=t["bg"])
            btn_frame.pack(pady=10)
            
            tk.Button(btn_frame, text="Show Selected", command=show_selected, 
                     bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"), 
                     width=15).pack(side="left", padx=5)
            
            tk.Button(btn_frame, text="Close", command=cal_win.destroy, 
                     bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"), 
                     width=15).pack(side="left", padx=5)
            
        except ImportError:
            messagebox.showinfo("Calendar", "Install tkcalendar: pip install tkcalendar")
    
    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-q>', lambda e: self.on_close())
        self.root.bind('<Control-s>', lambda e: self.save_logs())
        self.root.bind('<Control-r>', lambda e: self.refresh_all())
        self.root.bind('<Control-m>', lambda e: self.toggle_monitoring_shortcut())
        self.root.bind('<Control-a>', lambda e: self.show_recent_alerts())
    
    def save_logs(self):
        """Save logs from monitor tab"""
        if hasattr(self, 'monitor_tab') and hasattr(self.monitor_tab, 'save_logs_csv'):
            self.monitor_tab.save_logs_csv()
    
    def refresh_all(self):
        """Refresh all UI components"""
        if hasattr(self, 'home_tab') and hasattr(self.home_tab, 'update_home_stats'):
            self.home_tab.update_home_stats()
        if hasattr(self, 'anomaly_tab') and hasattr(self.anomaly_tab, 'refresh_anomaly_stats'):
            self.anomaly_tab.refresh_anomaly_stats()
        if hasattr(self, 'hash_tab') and hasattr(self.hash_tab, 'refresh_hash_database'):
            self.hash_tab.refresh_hash_database()
        if hasattr(self, 'status_bar'):
            self.status_bar.config(text="🔄 Refreshed at " + datetime.now().strftime("%H:%M:%S"))
        self.update_alert_counter()
    
    def toggle_monitoring_shortcut(self):
        """Toggle monitoring with keyboard shortcut"""
        if hasattr(self, 'monitor_tab') and hasattr(self.monitor_tab, 'toggle_monitoring'):
            self.monitor_tab.toggle_monitoring()
    def show_recent_alerts(self):
        """Show recent alerts dialog"""
        try:
            if not hasattr(self, 'alert_notifier') or not self.alert_notifier:
                messagebox.showinfo("No Alerts", "Alert system not available.")
                return
            
            recent_alerts = self.alert_notifier.get_recent_alerts(limit=20)
            
            alert_win = tk.Toplevel(self.root)
            alert_win.title("Recent Alerts")
            alert_win.geometry("800x500")
            t = constants.THEMES[self.config["theme"]]
            alert_win.configure(bg=t["bg"])
            
            tk.Label(alert_win, text="📋 Recent Alerts", font=("Segoe UI", 16, "bold"),
                    fg=t["fg"], bg=t["bg"]).pack(pady=(20, 10))
            
            tree_frame = tk.Frame(alert_win, bg=t["bg"])
            tree_frame.pack(fill="both", expand=True, padx=20, pady=10)
            
            columns = ("Time", "Type", "Title")
            tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
            
            tree.heading("Time", text="Time")
            tree.heading("Type", text="Type")
            tree.heading("Title", text="Title")
            
            tree.column("Time", width=150)
            tree.column("Type", width=100)
            tree.column("Title", width=500)
            
            scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            for alert in reversed(recent_alerts):
                time_str = alert.get('timestamp', '')
                if isinstance(time_str, str) and 'T' in time_str:
                    try:
                        time_str = datetime.fromisoformat(time_str.replace('Z', '+00:00')).strftime("%H:%M:%S")
                    except:
                        pass
                alert_type = alert.get('type', 'UNKNOWN')
                title = alert.get('title', 'No title')
                
                tree.insert("", "end", values=(
                    time_str,
                    alert_type,
                    title[:50] + ("..." if len(title) > 50 else "")
                ))
            
            tk.Button(alert_win, text="Close", command=alert_win.destroy,
                     bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"),
                     padx=20, pady=5).pack(pady=(0, 20))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show alerts: {e}")
    
    def update_status_bar(self):
        """Update status bar with current information"""
        if not hasattr(self, 'status_bar'):
            return
        
        status_parts = []
        
        if hasattr(self, 'monitor_tab') and hasattr(self.monitor_tab, 'monitoring'):
            if self.monitor_tab.monitoring:
                status_parts.append("▶️ Monitoring")
                if hasattr(self.monitor_tab, 'folder_path') and self.monitor_tab.folder_path.get():
                    path = self.monitor_tab.folder_path.get()
                    folder_name = os.path.basename(path) if os.path.isdir(path) else path
                    if len(folder_name) > 20:
                        folder_name = folder_name[:17] + "..."
                    status_parts.append(f"📁 {folder_name}")
            else:
                status_parts.append("⏹️ Stopped")
        elif self.monitoring:
            status_parts.append("▶️ Monitoring")
        else:
            status_parts.append("⏹️ Stopped")
        
        if hasattr(self, 'alert_notifier') and self.alert_notifier:
            recent_alerts = self.alert_notifier.get_recent_alerts(limit=10)
            critical_alerts = [a for a in recent_alerts if a.get('type') in ['RANSOMWARE', 'CRITICAL']]
            if critical_alerts:
                status_parts.append(f"🚨 {len(critical_alerts)} Critical")
        
        if hasattr(self, 'web_dashboard') and self.web_dashboard:
            if getattr(self.web_dashboard, 'is_running', False):
                status_parts.append("🌐 Dashboard Active")
        
        status_parts.append(datetime.now().strftime("%H:%M:%S"))
        
        status_text = " | ".join(status_parts)
        self.status_bar.config(text=status_text)
        
        if hasattr(self, 'monitor_status'):
            if self.monitoring:
                self.monitor_status.config(text="▶️ Monitoring", bg="#27ae60")
            else:
                self.monitor_status.config(text="⏹️ Stopped", bg="#e74c3c")
        
        self.root.after(1000, self.update_status_bar)
    
    def auto_start_web_dashboard(self):
        """Auto-start web dashboard if configured"""
        if self.config.get("web_dashboard", False):
            if hasattr(self, 'web_dashboard_tab') and hasattr(self.web_dashboard_tab, 'start_web_server'):
                response = messagebox.askyesno("Auto-start Web Dashboard", 
                                              "Web dashboard is configured to auto-start.\n\nStart it now?")
                if response:
                    self.web_dashboard_tab.start_web_server()
    
    def on_close(self):
        """Handle application shutdown"""
        if messagebox.askyesno("Exit TrustVault", 
                              "Are you sure you want to exit?\n\n"
                              "Monitoring will stop and all unsaved data may be lost."):
            
            if hasattr(self, 'monitor_tab') and hasattr(self.monitor_tab, 'monitoring'):
                if self.monitor_tab.monitoring and hasattr(self.monitor_tab, 'stop_monitoring'):
                    self.monitor_tab.stop_monitoring()
            
            if hasattr(self, 'web_dashboard') and self.web_dashboard:
                if getattr(self.web_dashboard, 'is_running', False):
                    try:
                        self.web_dashboard.stop()
                    except:
                        pass
            
            try:
                self.config["window_size"] = f"{self.root.winfo_width()}x{self.root.winfo_height()}"
                settings.save_config(self.config)
                
                if hasattr(self, 'hash_verifier') and self.hash_verifier:
                    if hasattr(self.hash_verifier, 'save_hash_database'):
                        self.hash_verifier.save_hash_database()
                if hasattr(self, 'alert_notifier') and self.alert_notifier:
                    alert_history = self.alert_notifier.get_recent_alerts(limit=1000)
                    os.makedirs("data", exist_ok=True)
                    with open("data/alert_history.json", "w") as f:
                        import json
                        json.dump(alert_history, f, indent=2, default=str)
                        
            except Exception as e:
                print(f"Error saving on exit: {e}")
            
            self.root.destroy()
    
    def start_monitoring(self, path, recursive=True):
        """Start monitoring a folder"""
        try:
            if self.monitoring:
                return False, "Already monitoring"
            
            self.monitor = FileMonitor(
                path=path,
                recursive=recursive,
                app=self,
                config=self.config
            )
            
            success, message = self.monitor.start()
            
            if success:
                self.monitoring = True
                self.monitored_path = path
                self.start_time = datetime.now()
                return True, message
            else:
                self.monitor = None
                return False, message
                
        except Exception as e:
            return False, f"Failed to start monitoring: {str(e)}"
    
    def stop_monitoring(self):
        """Stop monitoring"""
        try:
            if not self.monitoring or not self.monitor:
                return False, "No monitoring to stop"
            
            success, message = self.monitor.stop()
            if success:
                self.monitoring = False
                self.monitored_path = None
                self.monitor = None
            return success, message
        except Exception as e:
            return False, f"Error stopping monitoring: {str(e)}"


def main():
    """Main application entry point"""
    try:
        root = tk.Tk()
        app = FIMApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        messagebox.showerror("Fatal Error", f"Application failed to start:\n\n{str(e)}")

if __name__ == "__main__":
    main()
