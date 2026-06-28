"""
Logs tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from config import constants
import re

class LogsTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.build_ui()
    
    def build_ui(self):
        """Build the logs tab UI"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Main frame
        main_frame = tk.Frame(self.frame, bg=t["bg"])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(main_frame, text="📄 Combined System Logs", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Control buttons
        ctrl_frame = tk.Frame(main_frame, bg=t["bg"])
        ctrl_frame.pack(pady=20)
        
        tk.Button(ctrl_frame, text="🔄 Refresh Logs", command=self.refresh_combined_logs,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(ctrl_frame, text="🗑️ Clear All Logs", command=self.clear_combined_logs,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(ctrl_frame, text="💾 Export All Logs", command=self.export_all_logs,
                 bg="#3498db", fg="white", font=("Segoe UI", 12, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        # Log display area
        log_frame = tk.LabelFrame(main_frame, text="📝 Combined Log Display", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                 padx=10, pady=10)
        log_frame.pack(fill="both", expand=True, pady=20)
        
        # Add scrollbar
        log_scroll = tk.Scrollbar(log_frame, bg=t["bg"])
        log_scroll.pack(side="right", fill="y")
        
        # Log text widget
        self.combined_log_display = tk.Text(log_frame, height=25, bg=t["text_bg"], fg=t["text_fg"], 
                                           font=("Segoe UI", 10), wrap="word",
                                           yscrollcommand=log_scroll.set)
        self.combined_log_display.pack(fill="both", expand=True, padx=5, pady=5)
        
        log_scroll.config(command=self.combined_log_display.yview)
        
        # Initialize with current log content
        self.refresh_combined_logs()
    
    def format_log_with_timestamps(self, content, section_name):
        """Format log content with timestamps at the beginning of each line"""
        if not content.strip():
            return ""
        
        formatted_lines = []
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        lines = content.split('\n')
        for line in lines:
            if not line.strip():
                continue
            
            # Extract existing timestamp if present (e.g., [12:58:50])
            timestamp_match = re.search(r'\[(\d{2}:\d{2}:\d{2})\]', line)
            if timestamp_match:
                # Use existing timestamp with today's date
                time_part = timestamp_match.group(1)
                timestamp = f"{datetime.now().strftime('%Y-%m-%d')} {time_part}"
                # Remove the original timestamp from the line
                line = re.sub(r'\[\d{2}:\d{2}:\d{2}\]\s*', '', line)
            else:
                timestamp = current_time
            
            # Remove decorative elements like === and 🚀
            clean_line = line.strip()
            clean_line = re.sub(r'^=+\s*', '', clean_line)
            clean_line = re.sub(r'\s*=+$', '', clean_line)
            
            # Skip empty lines after cleaning
            if not clean_line:
                continue
            
            formatted_lines.append(f"{timestamp} {clean_line}")
        
        return '\n'.join(formatted_lines)
    
    def refresh_combined_logs(self):
        """Refresh combined logs display from all sources"""
        if not hasattr(self, 'combined_log_display'):
            return
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        combined_content = f"{current_time} Generated TRUSTVAULT COMBINED LOGS\n\n"
        
        # Get monitoring logs
        if hasattr(self.app, 'monitor_tab') and hasattr(self.app.monitor_tab, 'log_output'):
            monitoring_log = self.app.monitor_tab.log_output.get("1.0", "end-1c")
            if monitoring_log.strip():
                combined_content += f"{current_time} === MONITORING LOGS ===\n"
                formatted = self.format_log_with_timestamps(monitoring_log, "MONITORING")
                if formatted:
                    combined_content += formatted + "\n\n"
        
        # Get hash verification logs
        if hasattr(self.app, 'hash_tab') and hasattr(self.app.hash_tab, 'verify_results_text'):
            verify_log = self.app.hash_tab.verify_results_text.get("1.0", "end-1c")
            if verify_log.strip():
                combined_content += f"{current_time} === HASH VERIFICATION LOGS ===\n"
                formatted = self.format_log_with_timestamps(verify_log, "HASH")
                if formatted:
                    combined_content += formatted + "\n\n"
        
        # Get anomaly logs
        if hasattr(self.app, 'anomaly_tab') and hasattr(self.app.anomaly_tab, 'anomaly_history_text'):
            anomaly_log = self.app.anomaly_tab.anomaly_history_text.get("1.0", "end-1c")
            if anomaly_log.strip():
                combined_content += f"{current_time} === ANOMALY DETECTION LOGS ===\n"
                formatted = self.format_log_with_timestamps(anomaly_log, "ANOMALY")
                if formatted:
                    combined_content += formatted + "\n\n"
        
        # Get ransomware logs
        if hasattr(self.app, 'ransomware_tab') and hasattr(self.app.ransomware_tab, 'ransomware_history'):
            ransomware_log = self.app.ransomware_tab.ransomware_history.get("1.0", "end-1c")
            if ransomware_log.strip():
                combined_content += f"{current_time} === RANSOMWARE DETECTION LOGS ===\n"
                formatted = self.format_log_with_timestamps(ransomware_log, "RANSOMWARE")
                if formatted:
                    combined_content += formatted + "\n\n"
        
        # Get email logs
        if hasattr(self.app, 'email_tab') and hasattr(self.app.email_tab, 'email_test_results'):
            email_log = self.app.email_tab.email_test_results.get("1.0", "end-1c")
            if email_log.strip():
                combined_content += f"{current_time} === EMAIL ALERT LOGS ===\n"
                formatted = self.format_log_with_timestamps(email_log, "EMAIL")
                if formatted:
                    combined_content += formatted + "\n\n"
        
        # Display combined content
        self.combined_log_display.configure(state="normal")
        self.combined_log_display.delete("1.0", "end")
        self.combined_log_display.insert("1.0", combined_content)
        self.combined_log_display.configure(state="disabled")
        self.combined_log_display.see("end")
    
    def clear_combined_logs(self):
        """Clear all logs from the combined display"""
        if messagebox.askyesno("Clear All Logs", "Clear combined log display?\n\nNote: This only clears the display, not the actual logs."):
            self.combined_log_display.configure(state="normal")
            self.combined_log_display.delete("1.0", "end")
            self.combined_log_display.insert("end", f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Logs cleared\n\n")
            self.combined_log_display.configure(state="disabled")
    
    def export_all_logs(self):
        """Export all logs to a file"""
        content = self.combined_log_display.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("Empty", "No logs to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"fim_all_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Export Complete", f"All logs exported to:\n{filename}")