"""
Application settings tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import shutil
import platform
from datetime import datetime
from config import constants
from config.settings import save_config
# jhhj
class SettingsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.build_ui()
    
    def build_ui(self):
        """Build the settings tab UI"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Main frame with scrollbar
        main_frame = tk.Frame(self.frame, bg=t["bg"])
        main_frame.pack(fill="both", expand=True)
        
        # Canvas for scrolling
        canvas = tk.Canvas(main_frame, bg=t["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=t["bg"])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
        # Title
        tk.Label(scrollable_frame, text="⚙️ Application Settings", 
                font=("Segoe UI", 24, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Alert settings
        alert_frame = tk.LabelFrame(scrollable_frame, text="🔔 Alert Settings", 
                                   bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                   padx=30, pady=25)
        alert_frame.pack(fill="x", pady=20, padx=10)
        
        self.sound_var = tk.BooleanVar(value=self.app.config.get("alert_sound", True))
        sound_cb = tk.Checkbutton(alert_frame, text="🔊 Enable sound alerts", 
                                 variable=self.sound_var,
                                 command=lambda: self.update_setting("alert_sound", self.sound_var.get()),
                                 bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                 font=("Segoe UI", 12))
        sound_cb.pack(anchor="w", pady=8)
        
        self.popup_var = tk.BooleanVar(value=self.app.config.get("alert_popup", True))
        popup_cb = tk.Checkbutton(alert_frame, text="💬 Enable popup alerts for critical events", 
                                 variable=self.popup_var,
                                 command=lambda: self.update_setting("alert_popup", self.popup_var.get()),
                                 bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                 font=("Segoe UI", 12))
        popup_cb.pack(anchor="w", pady=8)
        
        self.normal_popup_var = tk.BooleanVar(value=self.app.config.get("alert_popup_normal", False))
        normal_popup_cb = tk.Checkbutton(alert_frame, text="📝 Show popups for normal events", 
                                        variable=self.normal_popup_var,
                                        command=lambda: self.update_setting("alert_popup_normal", self.normal_popup_var.get()),
                                        bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                        font=("Segoe UI", 12))
        normal_popup_cb.pack(anchor="w", pady=8)
        
        # Detection settings
        detect_frame = tk.LabelFrame(scrollable_frame, text="🛡️ Detection Settings", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                    padx=30, pady=25)
        detect_frame.pack(fill="x", pady=20, padx=10)
        
        self.anomaly_var = tk.BooleanVar(value=self.app.config.get("anomaly_detection", True))
        anomaly_cb = tk.Checkbutton(detect_frame, text="🔍 Enable anomaly detection", 
                                   variable=self.anomaly_var,
                                   command=lambda: self.update_setting("anomaly_detection", self.anomaly_var.get()),
                                   bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                   font=("Segoe UI", 12))
        anomaly_cb.pack(anchor="w", pady=8)
        
        self.hash_var = tk.BooleanVar(value=self.app.config.get("hash_verification", False))
        hash_cb = tk.Checkbutton(detect_frame, text="🔐 Enable hash verification", 
                                variable=self.hash_var,
                                command=lambda: self.update_setting("hash_verification", self.hash_var.get()),
                                bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                font=("Segoe UI", 12))
        hash_cb.pack(anchor="w", pady=8)
        
        self.ransomware_var = tk.BooleanVar(value=self.app.config.get("ransomware_detection", True))
        ransomware_cb = tk.Checkbutton(detect_frame, text="🚨 Enable ransomware detection", 
                                      variable=self.ransomware_var,
                                      command=lambda: self.update_setting("ransomware_detection", self.ransomware_var.get()),
                                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                      font=("Segoe UI", 12))
        ransomware_cb.pack(anchor="w", pady=8)
        
        self.email_var = tk.BooleanVar(value=self.app.config.get("email_alerts", False))
        email_cb = tk.Checkbutton(detect_frame, text="📧 Enable email alerts", 
                                 variable=self.email_var,
                                 command=lambda: self.update_setting("email_alerts", self.email_var.get()),
                                 bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                 font=("Segoe UI", 12))
        email_cb.pack(anchor="w", pady=8)
        
        # Monitoring settings
        monitor_frame = tk.LabelFrame(scrollable_frame, text="📁 Monitoring Settings", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                     padx=30, pady=25)
        monitor_frame.pack(fill="x", pady=20, padx=10)
        
        self.recursive_var = tk.BooleanVar(value=self.app.config.get("monitor_recursive", True))
        recursive_cb = tk.Checkbutton(monitor_frame, text="📂 Monitor subfolders recursively", 
                                     variable=self.recursive_var,
                                     command=lambda: self.update_setting("monitor_recursive", self.recursive_var.get()),
                                     bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                     font=("Segoe UI", 12))
        recursive_cb.pack(anchor="w", pady=8)
        
        # Log settings
        log_frame = tk.LabelFrame(scrollable_frame, text="📝 Log Settings", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                 padx=30, pady=25)
        log_frame.pack(fill="x", pady=20, padx=10)
        
        # Log verbosity
        verbosity_frame = tk.Frame(log_frame, bg=t["bg"])
        verbosity_frame.pack(fill="x", pady=10)
        
        tk.Label(verbosity_frame, text="Log Verbosity:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=20, anchor="w").pack(side="left")
        
        self.log_verbosity_combo = ttk.Combobox(verbosity_frame, 
                                               values=["MINIMAL", "NORMAL", "VERBOSE"],
                                               state="readonly", width=15)
        self.log_verbosity_combo.set(self.app.config.get("log_verbosity", "NORMAL"))
        self.log_verbosity_combo.pack(side="left", padx=10)
        
        tk.Button(verbosity_frame, text="Apply", 
                 command=self.update_log_verbosity_setting,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        
        # Auto-clean logs
        self.auto_clean_var = tk.BooleanVar(value=self.app.config.get("auto_clean_logs", True))
        auto_clean_cb = tk.Checkbutton(log_frame, text="🧹 Automatically clean old logs (keep last 1000 entries)", 
                                      variable=self.auto_clean_var,
                                      command=lambda: self.update_setting("auto_clean_logs", self.auto_clean_var.get()),
                                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                      font=("Segoe UI", 12))
        auto_clean_cb.pack(anchor="w", pady=10)
        
        # Web dashboard settings
        web_frame = tk.LabelFrame(scrollable_frame, text="🌐 Web Dashboard", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                 padx=30, pady=25)
        web_frame.pack(fill="x", pady=20, padx=10)
        
        # Port configuration
        port_frame = tk.Frame(web_frame, bg=t["bg"])
        port_frame.pack(fill="x", pady=10)
        
        tk.Label(port_frame, text="Dashboard Port:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=20, anchor="w").pack(side="left")
        
        self.settings_port_entry = tk.Entry(port_frame, width=10, 
                                           bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 12))
        self.settings_port_entry.insert(0, str(self.app.config.get("dashboard_port", 5000)))
        self.settings_port_entry.pack(side="left", padx=10)
        
        tk.Button(port_frame, text="Update", 
                 command=self.update_dashboard_port_setting,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        
        # Auto-start
        self.web_auto_var = tk.BooleanVar(value=self.app.config.get("web_dashboard", False))
        web_auto_cb = tk.Checkbutton(web_frame, text="▶️ Auto-start web dashboard on application launch", 
                                    variable=self.web_auto_var,
                                    command=lambda: self.update_setting("web_dashboard", self.web_auto_var.get()),
                                    bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                    font=("Segoe UI", 12))
        web_auto_cb.pack(anchor="w", pady=10)
        
        # Application settings
        app_frame = tk.LabelFrame(scrollable_frame, text="📱 Application", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                 padx=30, pady=25)
        app_frame.pack(fill="x", pady=20, padx=10)
        
        # Auto-save
        self.auto_save_var = tk.BooleanVar(value=self.app.config.get("auto_save", True))
        auto_save_cb = tk.Checkbutton(app_frame, text="💾 Auto-save configuration changes", 
                                     variable=self.auto_save_var,
                                     command=lambda: self.update_setting("auto_save", self.auto_save_var.get()),
                                     bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                     font=("Segoe UI", 12))
        auto_save_cb.pack(anchor="w", pady=8)
        
        # Check for updates
        self.update_check_var = tk.BooleanVar(value=self.app.config.get("check_updates", True))
        update_cb = tk.Checkbutton(app_frame, text="🔄 Check for updates on startup", 
                                  variable=self.update_check_var,
                                  command=lambda: self.update_setting("check_updates", self.update_check_var.get()),
                                  bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                  font=("Segoe UI", 12))
        update_cb.pack(anchor="w", pady=8)
        
        # Window size
        size_frame = tk.Frame(app_frame, bg=t["bg"])
        size_frame.pack(fill="x", pady=10)
        
        tk.Label(size_frame, text="Window Size:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=20, anchor="w").pack(side="left")
        
        self.window_size_entry = tk.Entry(size_frame, width=15, 
                                         bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 12))
        self.window_size_entry.insert(0, self.app.config.get("window_size", "1400x900"))
        self.window_size_entry.pack(side="left", padx=10)
        
        tk.Button(size_frame, text="Apply", 
                 command=self.update_window_size_setting,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        
        # Maintenance buttons
        button_frame = tk.Frame(scrollable_frame, bg=t["bg"])
        button_frame.pack(pady=30)
        
        tk.Button(button_frame, text="🔄 Reset All Settings", 
                 command=self.reset_all_settings,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=15)
        
        tk.Button(button_frame, text="💾 Backup Configuration", 
                 command=self.backup_configuration,
                 bg="#3498db", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=15)
        
        tk.Button(button_frame, text="📊 System Info", 
                 command=self.show_system_info,
                 bg="#9b59b6", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=15)
        
        tk.Button(button_frame, text="🧹 Cleanup System", 
                 command=self.cleanup_system,
                 bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=15)
        
        # About section
        about_frame = tk.LabelFrame(scrollable_frame, text="ℹ️ About TrustVault", 
                                   bg=t["bg"], fg=t["fg"], font=("Segoe UI", 16, "bold"), 
                                   padx=30, pady=25)
        about_frame.pack(fill="x", pady=20, padx=10)
        
        about_text = f"""
TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System
Advanced File Integrity Monitoring System

Developed by: Oman Ryne
Version: 2.0.0
Release Date: 2025-2026

Features:
• Real-time file monitoring
• ML-based anomaly detection
• Hash verification
• Real-time alerts
• Ransomware detection
• Web dashboard
• Certificate management

License: MIT
Copyright © 2026 Oman Ryne. All Rights Reserved.
"""
        
        about_label = tk.Label(about_frame, text=about_text, 
                              fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10),
                              justify="left")
        about_label.pack()
    
    def update_setting(self, key, value):
        """Update a setting and save configuration"""
        self.app.config[key] = value
        if self.app.config.get("auto_save", True):
            save_config(self.app.config)
    
    def update_log_verbosity_setting(self):
        """Update log verbosity setting"""
        verbosity = self.log_verbosity_combo.get()
        self.app.config["log_verbosity"] = verbosity
        save_config(self.app.config)
        messagebox.showinfo("Setting Updated", f"Log verbosity set to: {verbosity}")
    
    def update_dashboard_port_setting(self):
        """Update dashboard port setting"""
        try:
            port = int(self.settings_port_entry.get())
            if 1024 <= port <= 65535:
                old_port = self.app.config.get("dashboard_port", 5000)
                self.app.config["dashboard_port"] = port
                save_config(self.app.config)
                
                # If web server is running, ask to restart
                if self.app.web_dashboard and self.app.web_dashboard.is_running:
                    response = messagebox.askyesno("Port Changed", 
                                                  f"Port changed from {old_port} to {port}.\n\n"
                                                  "Web dashboard needs to be restarted for changes to take effect.\n\n"
                                                  "Restart web dashboard now?")
                    if response:
                        # Stop and restart web dashboard
                        if hasattr(self.app, 'web_dashboard_tab'):
                            self.app.web_dashboard_tab.stop_web_server()
                            import time
                            time.sleep(1)
                            self.app.web_dashboard_tab.start_web_server()
                
                messagebox.showinfo("Port Updated", f"Dashboard port set to {port}")
            else:
                messagebox.showerror("Invalid Port", "Port must be between 1024-65535")
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid port number")
    
    def update_window_size_setting(self):
        """Update window size setting"""
        size = self.window_size_entry.get().strip()
        
        # Validate format
        if 'x' not in size:
            messagebox.showerror("Invalid Format", "Window size must be in format: WIDTHxHEIGHT")
            return
        
        try:
            width, height = map(int, size.split('x'))
            if width < 800 or height < 600:
                messagebox.showwarning("Small Size", "Minimum window size is 800x600")
                return
            
            self.app.config["window_size"] = size
            save_config(self.app.config)
            
            response = messagebox.askyesno("Restart Required", 
                                          f"Window size set to {size}.\n\n"
                                          "This change will take effect after restarting the application.\n\n"
                                          "Restart now?")
            if response:
                self.app.on_close()
        except ValueError:
            messagebox.showerror("Invalid Size", "Please enter valid numbers for width and height")
    
    def reset_all_settings(self):
        """Reset all settings to defaults"""
        if messagebox.askyesno("Reset Settings", 
                              "Reset ALL settings to defaults?\n\n"
                              "This will:\n"
                              "• Reset all configuration options\n"
                              "• Clear monitoring preferences\n"
                              "• Reset detection settings\n"
                              "• Keep your data (logs, certificates, hashes)\n\n"
                              "This action cannot be undone!"):
            
            # Reset config to defaults
            default_config = {
                "theme": constants.DEFAULT_THEME, 
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
                "last_user": self.app.config.get("last_user", "admin"),
                "alert_popup_normal": False,
                "auto_save": True,
                "check_updates": True,
                "auto_clean_logs": True
            }
            
            # Update current config
            for key, value in default_config.items():
                self.app.config[key] = value
            
            save_config(self.app.config)
            
            # Update UI checkboxes
            self.sound_var.set(self.app.config["alert_sound"])
            self.popup_var.set(self.app.config["alert_popup"])
            self.normal_popup_var.set(self.app.config["alert_popup_normal"])
            self.anomaly_var.set(self.app.config["anomaly_detection"])
            self.hash_var.set(self.app.config["hash_verification"])
            self.ransomware_var.set(self.app.config["ransomware_detection"])
            self.email_var.set(self.app.config["email_alerts"])
            self.recursive_var.set(self.app.config["monitor_recursive"])
            self.log_verbosity_combo.set(self.app.config["log_verbosity"])
            self.web_auto_var.set(self.app.config["web_dashboard"])
            self.settings_port_entry.delete(0, tk.END)
            self.settings_port_entry.insert(0, str(self.app.config["dashboard_port"]))
            self.window_size_entry.delete(0, tk.END)
            self.window_size_entry.insert(0, self.app.config["window_size"])
            self.auto_save_var.set(self.app.config["auto_save"])
            self.update_check_var.set(self.app.config["check_updates"])
            self.auto_clean_var.set(self.app.config["auto_clean_logs"])
            
            messagebox.showinfo("Settings Reset", 
                              "All settings have been reset to defaults.\n\n"
                              "Some changes may require application restart.")
    
    def backup_configuration(self):
        """Backup all configuration files"""
        backup_dir = filedialog.askdirectory(title="Select Backup Directory")
        if not backup_dir:
            return
        
        try:
            files_to_backup = [
                "config.json",
                "email_config.json",
                "file_hashes.json",
                "data/revoked_certs.json"
            ]
            
            backup_files = []
            for filepath in files_to_backup:
                if os.path.exists(filepath):
                    dest = os.path.join(backup_dir, os.path.basename(filepath))
                    shutil.copy2(filepath, dest)
                    backup_files.append(os.path.basename(filepath))
            
            if backup_files:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                info_file = os.path.join(backup_dir, f"backup_info_{timestamp}.txt")
                
                with open(info_file, 'w') as f:
                    f.write(f"TrustVault Backup\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"User: {self.app.config.get('last_user', 'Unknown')}\n")
                    f.write(f"Version: 2.0 Enhanced\n\n")
                    f.write(f"Backed up files:\n")
                    for file in backup_files:
                        f.write(f"- {file}\n")
                
                messagebox.showinfo("Backup Complete", 
                                  f"Configuration backed up to:\n{backup_dir}\n\n"
                                  f"Files backed up:\n" + "\n".join([f"• {f}" for f in backup_files]))
            else:
                messagebox.showinfo("No Config", "No configuration files found to backup.")
                
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Error during backup:\n\n{e}")
    
    def show_system_info(self):
        """Show system information"""
        import platform
        import socket
        
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "Unknown"
        
        info = f"""
SYSTEM INFORMATION:

Application: TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System
Python: {platform.python_version()}
Operating System: {platform.system()} {platform.release()}
Architecture: {platform.machine()}
Processor: {platform.processor()}
Hostname: {socket.gethostname()}
IP Address: {local_ip}

CONFIGURATION PATHS:

Configuration: {os.path.abspath('config.json')}
Certificates: {os.path.abspath('certs')}
Hash Database: {os.path.abspath('file_hashes.json')}
Logs Directory: {os.path.abspath('logs')}
Data Directory: {os.path.abspath('data')}

APPLICATION STATUS:

Monitoring: {'Active' if self.app.monitoring else 'Inactive'}
Web Dashboard: {'Running' if self.app.web_dashboard and self.app.web_dashboard.is_running else 'Stopped'}
Email Alerts: {'Enabled' if self.app.email_system.enabled else 'Disabled'}
Hash Verification: {'Enabled' if self.app.config.get('hash_verification') else 'Disabled'}
Anomaly Detection: {'Enabled' if self.app.config.get('anomaly_detection') else 'Disabled'}
Ransomware Detection: {'Enabled' if self.app.config.get('ransomware_detection') else 'Disabled'}
        """
        
        info_window = tk.Toplevel(self.app.root)
        info_window.title("System Information")
        info_window.geometry("600x500")
        info_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        info_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(info_window, text="📊 System Information", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Text widget with info
        text_frame = tk.Frame(info_window, bg=t["bg"])
        text_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        scrollbar = tk.Scrollbar(text_frame, bg=t["bg"])
        scrollbar.pack(side="right", fill="y")
        
        info_text = tk.Text(text_frame, bg=t["text_bg"], fg=t["text_fg"],
                           font=("Segoe UI", 10), wrap="word",
                           yscrollcommand=scrollbar.set)
        info_text.pack(fill="both", expand=True)
        
        scrollbar.config(command=info_text.yview)
        
        info_text.insert("1.0", info)
        info_text.configure(state="disabled")
        
        # Copy button
        copy_frame = tk.Frame(info_window, bg=t["bg"])
        copy_frame.pack(pady=10)
        
        tk.Button(copy_frame, text="📋 Copy to Clipboard", 
                 command=lambda: self.copy_to_clipboard(info),
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold"),
                 padx=20, pady=5).pack(side="left", padx=5)
        
        # Close button
        tk.Button(info_window, text="Close", command=info_window.destroy,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(pady=20)
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        messagebox.showinfo("Copied", "System information copied to clipboard!")
    
    def cleanup_system(self):
        """Cleanup system files"""
        cleanup_window = tk.Toplevel(self.app.root)
        cleanup_window.title("System Cleanup")
        cleanup_window.geometry("500x400")
        cleanup_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        cleanup_window.resizable(False, False)
        cleanup_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        tk.Label(cleanup_window, text="🧹 System Cleanup", 
                font=("Segoe UI", 16, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Options frame
        options_frame = tk.LabelFrame(cleanup_window, text="Select cleanup options", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 12, "bold"),
                                     padx=20, pady=20)
        options_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Cleanup options
        self.clean_logs_var = tk.BooleanVar(value=True)
        logs_cb = tk.Checkbutton(options_frame, text="Clean old log files (keep last 7 days)", 
                                variable=self.clean_logs_var,
                                bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                font=("Segoe UI", 11))
        logs_cb.pack(anchor="w", pady=8)
        
        self.clean_csv_var = tk.BooleanVar(value=True)
        csv_cb = tk.Checkbutton(options_frame, text="Clean old CSV export files", 
                               variable=self.clean_csv_var,
                               bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                               font=("Segoe UI", 11))
        csv_cb.pack(anchor="w", pady=8)
        
        self.clean_temp_var = tk.BooleanVar(value=True)
        temp_cb = tk.Checkbutton(options_frame, text="Clean temporary files", 
                                variable=self.clean_temp_var,
                                bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                font=("Segoe UI", 11))
        temp_cb.pack(anchor="w", pady=8)
        
        self.backup_first_var = tk.BooleanVar(value=True)
        backup_cb = tk.Checkbutton(options_frame, text="Create backup before cleanup", 
                                  variable=self.backup_first_var,
                                  bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                  font=("Segoe UI", 11))
        backup_cb.pack(anchor="w", pady=8)
        
        # Results label
        result_label = tk.Label(cleanup_window, text="", fg=t["fg"], bg=t["bg"])
        result_label.pack(pady=10)
        
        def perform_cleanup():
            result_text = "Cleanup started...\n\n"
            
            try:
                import time
                from datetime import datetime, timedelta
                
                files_deleted = 0
                total_size = 0
                
                # Clean logs
                if self.clean_logs_var.get():
                    logs_dir = "logs"
                    if os.path.exists(logs_dir):
                        cutoff_time = time.time() - (7 * 24 * 3600)  # 7 days ago
                        for filename in os.listdir(logs_dir):
                            filepath = os.path.join(logs_dir, filename)
                            if os.path.isfile(filepath):
                                if os.path.getmtime(filepath) < cutoff_time:
                                    size = os.path.getsize(filepath)
                                    os.remove(filepath)
                                    files_deleted += 1
                                    total_size += size
                                    result_text += f"Deleted: {filename}\n"
                
                # Clean CSV files
                if self.clean_csv_var.get():
                    csv_dir = "CSV_logs"
                    if os.path.exists(csv_dir):
                        cutoff_time = time.time() - (30 * 24 * 3600)  # 30 days ago
                        for filename in os.listdir(csv_dir):
                            filepath = os.path.join(csv_dir, filename)
                            if os.path.isfile(filepath) and filename.endswith('.csv'):
                                if os.path.getmtime(filepath) < cutoff_time:
                                    size = os.path.getsize(filepath)
                                    os.remove(filepath)
                                    files_deleted += 1
                                    total_size += size
                                    result_text += f"Deleted: {filename}\n"
                
                # Format size
                size_mb = total_size / (1024 * 1024)
                
                result_text += f"\n✅ Cleanup completed!\n"
                result_text += f"Files deleted: {files_deleted}\n"
                result_text += f"Space freed: {size_mb:.2f} MB\n"
                
                result_label.config(text=result_text, fg="#27ae60")
                
                # Schedule window close
                cleanup_window.after(3000, cleanup_window.destroy)
                messagebox.showinfo("Cleanup Complete", 
                                  f"System cleanup completed successfully!\n\n"
                                  f"Files deleted: {files_deleted}\n"
                                  f"Space freed: {size_mb:.2f} MB")
                
            except Exception as e:
                result_label.config(text=f"❌ Cleanup failed: {str(e)}", fg="#e74c3c")
        
        # Action buttons
        button_frame = tk.Frame(cleanup_window, bg=t["bg"])
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="🧹 Start Cleanup", 
                 command=perform_cleanup,
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="❌ Cancel", 
                 command=cleanup_window.destroy,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(side="left", padx=10)
