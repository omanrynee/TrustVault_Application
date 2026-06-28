"""
Email alerts tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from datetime import datetime
from config import constants

class EmailAlertsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        # Main notebook for sub-tabs
        self.main_notebook = ttk.Notebook(self.frame)
        self.main_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create sub-tabs
        self.config_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.test_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.alert_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        self.main_notebook.add(self.config_tab, text="⚙️ Configuration")
        self.main_notebook.add(self.test_tab, text="🔧 Testing")
        self.main_notebook.add(self.alert_tab, text="📨 Alert Settings")
        
        self.build_config_tab()
        self.build_test_tab()
        self.build_alert_tab()
        self.update_email_status()
    
    def build_config_tab(self):
        """Build email configuration sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.config_tab, text="📧 Email Alert Configuration", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Configuration form
        form_frame = tk.LabelFrame(self.config_tab, text="📝 SMTP Settings", 
                                  bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                  padx=30, pady=25)
        form_frame.pack(fill="x", padx=30, pady=20)
        
        # Server settings
        server_frame = tk.Frame(form_frame, bg=t["bg"])
        server_frame.pack(fill="x", pady=10)
        
        tk.Label(server_frame, text="SMTP Server:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.smtp_server_entry = tk.Entry(server_frame, width=40, 
                                         bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11))
        self.smtp_server_entry.insert(0, self.app.email_system.config.get('smtp_server', 'smtp.gmail.com'))
        self.smtp_server_entry.pack(side="left", padx=10)
        
        # Port settings
        port_frame = tk.Frame(form_frame, bg=t["bg"])
        port_frame.pack(fill="x", pady=10)
        
        tk.Label(port_frame, text="SMTP Port:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.smtp_port_entry = tk.Entry(port_frame, width=10, 
                                       bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11))
        self.smtp_port_entry.insert(0, str(self.app.email_system.config.get('smtp_port', 587)))
        self.smtp_port_entry.pack(side="left", padx=10)
        
        # Common ports quick buttons
        port_buttons = tk.Frame(port_frame, bg=t["bg"])
        port_buttons.pack(side="left", padx=20)
        
        for port in [587, 465, 25]:
            tk.Button(port_buttons, text=str(port), 
                     command=lambda p=port: self.smtp_port_entry.delete(0, tk.END) or 
                     self.smtp_port_entry.insert(0, str(p)),
                     bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 9, "bold"),
                     width=4).pack(side="left", padx=2)
        
        # Email address
        email_frame = tk.Frame(form_frame, bg=t["bg"])
        email_frame.pack(fill="x", pady=10)
        
        tk.Label(email_frame, text="Sender Email:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.sender_email_entry = tk.Entry(email_frame, width=40, 
                                          bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11))
        self.sender_email_entry.insert(0, self.app.email_system.config.get('sender_email', ''))
        self.sender_email_entry.pack(side="left", padx=10)
        
        # Password/App Password
        pass_frame = tk.Frame(form_frame, bg=t["bg"])
        pass_frame.pack(fill="x", pady=10)
        
        tk.Label(pass_frame, text="App Password:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.sender_pass_entry = tk.Entry(pass_frame, width=40, 
                                         bg=t["entry_bg"], fg=t["fg"], 
                                         font=("Segoe UI", 11), show="●")
        self.sender_pass_entry.insert(0, self.app.email_system.config.get('sender_password', ''))
        self.sender_pass_entry.pack(side="left", padx=10)
        
        # Show password checkbox
        self.show_pass_var = tk.BooleanVar(value=False)
        show_pass_cb = tk.Checkbutton(pass_frame, text="Show", 
                                     variable=self.show_pass_var,
                                     command=self.toggle_password_visibility,
                                     bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                     font=("Segoe UI", 9))
        show_pass_cb.pack(side="left", padx=5)
        
        # Recipients
        recip_frame = tk.Frame(form_frame, bg=t["bg"])
        recip_frame.pack(fill="x", pady=10)
        
        tk.Label(recip_frame, text="Recipients:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.recipients_entry = tk.Entry(recip_frame, width=40, 
                                        bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11))
        recipients_str = ', '.join(self.app.email_system.config.get('recipients', [])) if self.app.email_system else ""
        self.recipients_entry.insert(0, recipients_str)
        self.recipients_entry.pack(side="left", padx=10)
        
        # Enable Alerts Checkbutton
        enable_frame = tk.Frame(form_frame, bg=t["bg"])
        enable_frame.pack(fill="x", pady=10)
        
        tk.Label(enable_frame, text="Email Alerts Status:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
        
        self.config_enable_var = tk.BooleanVar(value=self.app.email_system.enabled if self.app.email_system else False)
        self.config_enable_cb = tk.Checkbutton(
            enable_frame, text="Enable Email Alerts System", variable=self.config_enable_var,
            bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=("Segoe UI", 11)
        )
        self.config_enable_cb.pack(side="left", padx=10)
        
        # Save button
        save_frame = tk.Frame(form_frame, bg=t["bg"])
        save_frame.pack(pady=20)
        
        tk.Button(save_frame, text="💾 Save Configuration", 
                 command=self.save_email_config,
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack()
    
    def build_test_tab(self):
        """Build email testing sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.test_tab, text="🔧 Test Email Configuration", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Status frame
        status_frame = tk.LabelFrame(self.test_tab, text="📊 Email Status", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                    padx=20, pady=20)
        status_frame.pack(fill="x", padx=30, pady=20)
        
        # Status indicators
        self.email_status_label = tk.Label(status_frame, text="❌ Not Configured", 
                                          fg="#e74c3c", bg=t["bg"],
                                          font=("Segoe UI", 12, "bold"))
        self.email_status_label.pack(pady=10)
        
        self.last_test_label = tk.Label(status_frame, text="Last test: Never", 
                                       fg=t["fg"], bg=t["bg"], font=("Segoe UI", 10))
        self.last_test_label.pack(pady=5)
        
        # Test buttons
        test_frame = tk.Frame(self.test_tab, bg=t["bg"])
        test_frame.pack(pady=30)
        
        tk.Button(test_frame, text="🔗 Test Connection", 
                 command=self.test_email_connection,
                 bg="#3498db", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=25, pady=12).pack(side="left", padx=15)
        
        tk.Button(test_frame, text="✉️ Send Test Email", 
                 command=self.test_email_send,
                 bg="#9b59b6", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=25, pady=12).pack(side="left", padx=15)
        
        # Test mode checkbox
        mode_frame = tk.Frame(self.test_tab, bg=t["bg"])
        mode_frame.pack(pady=20)
        
        self.test_mode_var = tk.BooleanVar(value=self.app.email_system.config.get('test_mode', False))
        test_cb = tk.Checkbutton(mode_frame, text="Test Mode (Save emails to file instead of sending)", 
                                variable=self.test_mode_var,
                                command=lambda: self.app.email_system.config.update({'test_mode': self.test_mode_var.get()}),
                                bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                                font=("Segoe UI", 10))
        test_cb.pack()
        
        # Test results
        results_frame = tk.LabelFrame(self.test_tab, text="📋 Test Results", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                     padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Results text with scrollbar
        results_scroll = tk.Scrollbar(results_frame, bg=t["bg"])
        results_scroll.pack(side="right", fill="y")
        
        self.email_test_results = tk.Text(results_frame, height=10, 
                                         bg=t["text_bg"], fg=t["text_fg"],
                                         font=("Segoe UI", 10), wrap="word",
                                         yscrollcommand=results_scroll.set)
        self.email_test_results.pack(fill="both", expand=True, padx=5, pady=5)
        
        results_scroll.config(command=self.email_test_results.yview)
        
        # Results controls
        results_controls = tk.Frame(results_frame, bg=t["bg"])
        results_controls.pack(fill="x", pady=5)
        
        tk.Button(results_controls, text="🗑️ Clear Results", 
                 command=self.clear_email_results,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(results_controls, text="📋 Copy Results", 
                 command=self.copy_email_results,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
    
    def build_alert_tab(self):
        """Build email alert settings sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.alert_tab, text="📨 Alert Settings & Triggers", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Alert levels frame
        levels_frame = tk.LabelFrame(self.alert_tab, text="🚨 Alert Levels", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                    padx=20, pady=20)
        levels_frame.pack(fill="x", padx=30, pady=20)
        
        # Alert level checkboxes
        self.alert_level_vars = {}
        
        level_configs = [
            ("CRITICAL", "🔴 Critical alerts (Ransomware, Tampering)", True),
            ("WARNING", "🟡 Warning alerts (Anomalies, Suspicious activity)", True),
            ("INFO", "🔵 Information alerts (Normal file changes)", False)
        ]
        
        for level, description, default in level_configs:
            frame = tk.Frame(levels_frame, bg=t["bg"])
            frame.pack(fill="x", pady=8)
            
            var = tk.BooleanVar(value=self.app.email_system.config.get('alert_levels', {}).get(level, default))
            self.alert_level_vars[level] = var
            
            cb = tk.Checkbutton(frame, text=description, variable=var,
                               command=lambda l=level, v=var: self.update_alert_level(l, v.get()),
                               bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], 
                               font=("Segoe UI", 11))
            cb.pack(anchor="w")
        
        # Save all settings button
        save_frame = tk.Frame(self.alert_tab, bg=t["bg"])
        save_frame.pack(pady=20)
        
        tk.Button(save_frame, text="💾 Save All Alert Settings", 
                 command=self.save_alert_settings,
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_pass_var.get():
            self.sender_pass_entry.config(show="")
        else:
            self.sender_pass_entry.config(show="●")
    
    def update_email_status(self):
        """Update email status display"""
        if self.app.email_system.enabled:
            self.email_status_label.config(text="✅ Configured", fg="#27ae60")
        else:
            self.email_status_label.config(text="❌ Not Configured", fg="#e74c3c")
    
    def save_email_config(self):
        """Save email configuration"""
        smtp_server = self.smtp_server_entry.get().strip()
        smtp_port = self.smtp_port_entry.get().strip()
        sender_email = self.sender_email_entry.get().strip()
        sender_pass = self.sender_pass_entry.get()
        recipients = [r.strip() for r in self.recipients_entry.get().split(',') if r.strip()]
        
        # Validation
        if not all([smtp_server, smtp_port, sender_email, sender_pass]):
            messagebox.showwarning("Missing Information", 
                                 "Please fill all required fields!")
            return
        
        if not recipients:
            messagebox.showwarning("No Recipients", 
                                 "Please enter at least one recipient email!")
            return
        
        try:
            port = int(smtp_port)
            if port not in [25, 465, 587, 2525]:
                response = messagebox.askyesno("Unusual Port", 
                                              f"Port {port} is unusual for SMTP.\n"
                                              f"Common ports are 587 (TLS) or 465 (SSL).\n\n"
                                              f"Continue anyway?")
                if not response:
                    return
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number!")
            return
        
        # Warn if using Gmail and the password does not look like a 16-character App Password
        is_gmail = "gmail" in sender_email.lower() or "gmail" in smtp_server.lower()
        if is_gmail:
            clean_pass = sender_pass.replace(" ", "").replace("-", "")
            if len(clean_pass) != 16 or not clean_pass.isalpha():
                response = messagebox.askyesno(
                    "Gmail Security Warning",
                    "The password you entered does not appear to be a standard 16-character Gmail App Password.\n\n"
                    "Gmail requires a Google App Password (not your regular account password) to connect via SMTP.\n\n"
                    "Do you want to save this password anyway?"
                )
                if not response:
                    return

        # Save configuration
        test_mode = self.test_mode_var.get() if hasattr(self, 'test_mode_var') else False
        success, message = self.app.email_system.configure(
            smtp_server, smtp_port, sender_email, sender_pass, recipients, test_mode
        )
        
        if success:
            # Update enable status
            enabled = self.config_enable_var.get()
            self.app.email_system.enabled = enabled
            self.app.email_system.config['enabled'] = enabled
            self.app.email_system.save_config()
            
            messagebox.showinfo("Success", message)
            self.update_email_status()
            self.app.config["email_alerts"] = enabled
            from config.settings import save_config
            save_config(self.app.config)
            
            # Log the configuration
            self.email_test_results.configure(state="normal")
            self.email_test_results.insert("end", 
                f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Configuration saved\n"
                f"    Server: {smtp_server}:{smtp_port}\n"
                f"    Sender: {sender_email}\n"
                f"    Recipients: {', '.join(recipients)}\n\n")
            self.email_test_results.see("end")
            self.email_test_results.configure(state="disabled")
        else:
            messagebox.showerror("Error", message)
    
    def test_email_connection(self):
        """Test email connection"""
        if not self.app.email_system.enabled:
            messagebox.showwarning("Not Configured", 
                                 "Please save configuration first!")
            return
        
        # Show testing window
        test_window = tk.Toplevel(self.frame)
        test_window.title("Testing Connection...")
        test_window.geometry("400x150")
        test_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        test_window.resizable(False, False)
        test_window.grab_set()
        
        tk.Label(test_window, text="🔗 Testing SMTP Connection...", 
                font=("Segoe UI", 14, "bold"), 
                fg=constants.THEMES[self.app.config["theme"]]["fg"],
                bg=constants.THEMES[self.app.config["theme"]]["bg"]).pack(pady=30)
        
        status_label = tk.Label(test_window, text="Connecting to server...",
                               fg=constants.THEMES[self.app.config["theme"]]["fg"],
                               bg=constants.THEMES[self.app.config["theme"]]["bg"])
        status_label.pack(pady=10)
        
        test_window.update()
        
        # Run test in background
        def run_test():
            success, message = self.app.email_system.test_connection()
            
            def update_ui():
                try:
                    test_window.destroy()
                except Exception:
                    pass
                
                self.email_test_results.configure(state="normal")
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if success:
                    self.email_test_results.insert("end", 
                        f"[{timestamp}] ✅ Connection test successful!\n"
                        f"    {message}\n\n")
                    self.last_test_label.config(text=f"Last test: {timestamp} - Success")
                else:
                    self.email_test_results.insert("end", 
                        f"[{timestamp}] ❌ Connection test failed!\n"
                        f"    {message}\n\n")
                    self.last_test_label.config(text=f"Last test: {timestamp} - Failed")
                
                self.email_test_results.see("end")
                self.email_test_results.configure(state="disabled")
                
                # Show message box
                if success:
                    messagebox.showinfo("Connection Test", 
                                      f"✅ Connection successful!\n\n{message}")
                else:
                    messagebox.showerror("Connection Test", 
                                       f"❌ Connection failed!\n\n{message}")
            
            self.frame.after(0, update_ui)
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def test_email_send(self):
        """Send test email in background thread to avoid UI freezing"""
        if not self.app.email_system.enabled:
            messagebox.showwarning("Not Configured", 
                                 "Please save configuration first!")
            return
        
        # Show status window
        status_win = tk.Toplevel(self.frame)
        status_win.title("Sending Test Email...")
        status_win.geometry("400x150")
        status_win.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        status_win.resizable(False, False)
        status_win.grab_set()
        
        tk.Label(status_win, text="✉️ Dispatching Test Email...", 
                font=("Segoe UI", 14, "bold"), 
                fg=constants.THEMES[self.app.config["theme"]]["fg"],
                bg=constants.THEMES[self.app.config["theme"]]["bg"]).pack(pady=30)
        
        status_label = tk.Label(status_win, text="Please wait while SMTP delivers the alert...",
                               fg=constants.THEMES[self.app.config["theme"]]["fg"],
                               bg=constants.THEMES[self.app.config["theme"]]["bg"])
        status_label.pack(pady=10)
        status_win.update()

        def run_send():
            # Test connection first
            success_conn, message_conn = self.app.email_system.test_connection()
            
            def handle_conn_result():
                try:
                    status_win.destroy()
                except Exception:
                    pass
                
                if not success_conn:
                    response = messagebox.askyesno("Connection Failed", 
                                                  f"Connection test failed:\n\n{message_conn}\n\n"
                                                  "Try sending test email anyway?")
                    if response:
                        self._execute_test_send()
                else:
                    self._execute_test_send()
            
            self.frame.after(0, handle_conn_result)

        threading.Thread(target=run_send, daemon=True).start()
 
    def _execute_test_send(self):
        progress_win = tk.Toplevel(self.frame)
        progress_win.title("Sending...")
        progress_win.geometry("400x150")
        progress_win.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        progress_win.resizable(False, False)
        progress_win.grab_set()
        
        tk.Label(progress_win, text="✉️ Sending...", 
                font=("Segoe UI", 14, "bold"), 
                fg=constants.THEMES[self.app.config["theme"]]["fg"],
                bg=constants.THEMES[self.app.config["theme"]]["bg"]).pack(pady=30)
        progress_win.update()

        def run_actual_send():
            success, message = self.app.email_system.send_test_email()
            
            def show_results():
                try:
                    progress_win.destroy()
                except Exception:
                    pass
                
                self.email_test_results.configure(state="normal")
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                from alerts.alert_manager import AlertManager
                if success:
                    self.email_test_results.insert("end", 
                        f"[{timestamp}] ✅ Test email sent!\n"
                        f"    {message}\n\n")
                    AlertManager.show_success("Email Sent Successfully", "Test email sent successfully!")
                    
                    if self.app.email_system.config.get('test_mode', False):
                        messagebox.showinfo("Test Email", 
                                          f"✅ Test email saved to file (Test Mode).\n\n"
                                          f"Check the logs folder for the email file.")
                    else:
                        messagebox.showinfo("Test Email", 
                                          f"✅ Test email sent successfully!\n\n"
                                          f"Check your inbox (and spam folder).")
                else:
                    self.email_test_results.insert("end", 
                        f"[{timestamp}] ❌ Failed to send test email!\n"
                        f"    {message}\n\n")
                    AlertManager.show_error("Email Delivery Failed", f"SMTP Error: {message}")
                    messagebox.showerror("Test Email", 
                                       f"❌ Failed to send test email:\n\n{message}")
                
                self.email_test_results.see("end")
                self.email_test_results.configure(state="disabled")
            
            self.frame.after(0, show_results)

        threading.Thread(target=run_actual_send, daemon=True).start()
    
    def clear_email_results(self):
        """Clear email test results"""
        self.email_test_results.configure(state="normal")
        self.email_test_results.delete("1.0", "end")
        self.email_test_results.insert("end", f"Results cleared at {datetime.now().strftime('%H:%M:%S')}\n\n")
        self.email_test_results.configure(state="disabled")
    
    def copy_email_results(self):
        """Copy email test results to clipboard"""
        content = self.email_test_results.get("1.0", "end-1c")
        if content.strip():
            self.frame.clipboard_clear()
            self.frame.clipboard_append(content)
            messagebox.showinfo("Copied", "Results copied to clipboard!")
        else:
            messagebox.showinfo("Empty", "No results to copy.")
    
    def update_alert_level(self, level, enabled):
        """Update alert level setting"""
        if 'alert_levels' not in self.app.email_system.config:
            self.app.email_system.config['alert_levels'] = {}
        
        self.app.email_system.config['alert_levels'][level] = enabled
        self.app.email_system.save_config()
    
    def save_alert_settings(self):
        """Save all alert settings"""
        # Save alert levels
        for level, var in self.alert_level_vars.items():
            self.update_alert_level(level, var.get())
        
        self.app.email_system.save_config()
        messagebox.showinfo("Settings Saved", "Alert settings saved successfully!")