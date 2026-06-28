"""
Hash verification tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from datetime import datetime
import threading
import time
import csv
import shutil

from config import constants

class HashVerificationTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        # Main notebook for sub-tabs
        self.main_notebook = ttk.Notebook(self.frame)
        self.main_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create sub-tabs
        self.register_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.verify_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.db_tab = tk.Frame(self.main_notebook, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        self.main_notebook.add(self.register_tab, text="📝 Register Files")
        self.main_notebook.add(self.verify_tab, text="🔍 Verify Files")
        self.main_notebook.add(self.db_tab, text="🗃️ Database")
        
        self.build_register_tab()
        self.build_verify_tab()
        self.build_db_tab()
    
    def build_register_tab(self):
        """Build file registration sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.register_tab, text="🔐 Register Files for Integrity Monitoring", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # File selection frame
        select_frame = tk.LabelFrame(self.register_tab, text="📁 Select File or Folder", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                    padx=20, pady=20)
        select_frame.pack(fill="x", padx=30, pady=20)
        
        # Single file selection
        file_row = tk.Frame(select_frame, bg=t["bg"])
        file_row.pack(fill="x", pady=10)
        
        tk.Label(file_row, text="Single File:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=15).pack(side="left")
        
        self.hash_file_entry = tk.Entry(file_row, width=50, bg=t["entry_bg"], 
                                       fg=t["fg"], font=("Segoe UI", 11))
        self.hash_file_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        tk.Button(file_row, text="📁 Browse File", command=self.browse_hash_file,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        # Folder selection
        folder_row = tk.Frame(select_frame, bg=t["bg"])
        folder_row.pack(fill="x", pady=10)
        
        tk.Label(folder_row, text="Entire Folder:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=15).pack(side="left")
        
        self.hash_folder_entry = tk.Entry(folder_row, width=50, bg=t["entry_bg"], 
                                         fg=t["fg"], font=("Segoe UI", 11))
        self.hash_folder_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        tk.Button(folder_row, text="📂 Browse Folder", command=self.browse_hash_folder,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        # Registration options
        options_frame = tk.LabelFrame(select_frame, text="⚙️ Registration Options", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 12, "bold"),
                                     padx=15, pady=15)
        options_frame.pack(fill="x", pady=15)
        
        self.recursive_hash_var = tk.BooleanVar(value=True)
        recursive_cb = tk.Checkbutton(options_frame, text="Include subfolders", 
                                     variable=self.recursive_hash_var,
                                     bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=("Segoe UI", 11))
        recursive_cb.pack(anchor="w", pady=5)
        
        self.overwrite_hash_var = tk.BooleanVar(value=False)
        overwrite_cb = tk.Checkbutton(options_frame, text="Overwrite existing entries", 
                                      variable=self.overwrite_hash_var,
                                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=("Segoe UI", 11))
        overwrite_cb.pack(anchor="w", pady=5)
        
        # Action buttons
        action_frame = tk.Frame(select_frame, bg=t["bg"])
        action_frame.pack(pady=20)
        
        tk.Button(action_frame, text="✅ Register Selected File", 
                 command=self.register_file_hash,
                 bg="#27ae60", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(action_frame, text="📂 Register Entire Folder", 
                 command=self.register_folder_hash,
                 bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
    
    def build_verify_tab(self):
        """Build file verification sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.verify_tab, text="🔍 Verify File Integrity", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Verification controls
        ctrl_frame = tk.LabelFrame(self.verify_tab, text="🛠️ Verification Controls", 
                                  bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                  padx=20, pady=20)
        ctrl_frame.pack(fill="x", padx=30, pady=20)
        
        # File selection for verification
        verify_row = tk.Frame(ctrl_frame, bg=t["bg"])
        verify_row.pack(fill="x", pady=10)
        
        tk.Label(verify_row, text="File to Verify:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 12), width=15).pack(side="left")
        
        self.verify_file_entry = tk.Entry(verify_row, width=50, bg=t["entry_bg"], 
                                         fg=t["fg"], font=("Segoe UI", 11))
        self.verify_file_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        tk.Button(verify_row, text="📁 Browse", command=self.browse_verify_file,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        # Action buttons
        action_frame = tk.Frame(ctrl_frame, bg=t["bg"])
        action_frame.pack(pady=20)
        
        tk.Button(action_frame, text="🔍 Verify Single File", 
                 command=self.verify_file_hash,
                 bg="#3498db", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(action_frame, text="📋 Verify All Files", 
                 command=self.verify_all_hashes,
                 bg="#9b59b6", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        tk.Button(action_frame, text="❌ Unregister File", 
                 command=self.unregister_file_hash,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=20, pady=10).pack(side="left", padx=10)
        
        # Results display
        results_frame = tk.LabelFrame(self.verify_tab, text="📊 Verification Results", 
                                     bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                     padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Results text widget with scrollbar
        results_scroll = tk.Scrollbar(results_frame, bg=t["bg"])
        results_scroll.pack(side="right", fill="y")
        
        self.verify_results_text = tk.Text(results_frame, height=15, 
                                          bg=t["text_bg"], fg=t["text_fg"],
                                          font=("Segoe UI", 10), wrap="word",
                                          yscrollcommand=results_scroll.set)
        self.verify_results_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        results_scroll.config(command=self.verify_results_text.yview)
        
        # Results controls
        results_controls = tk.Frame(results_frame, bg=t["bg"])
        results_controls.pack(fill="x", pady=5)
        
        tk.Button(results_controls, text="🗑️ Clear Results", 
                 command=self.clear_verify_results,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(results_controls, text="💾 Save Report", 
                 command=self.save_verify_report,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
    
    def build_db_tab(self):
        """Build hash database management sub-tab"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(self.db_tab, text="🗃️ Hash Database Management", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Database stats
        stats_frame = tk.LabelFrame(self.db_tab, text="📈 Database Statistics", 
                                   bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                   padx=20, pady=20)
        stats_frame.pack(fill="x", padx=30, pady=20)
        
        # Stats grid
        self.hash_stats_labels = {}
        stats_grid = tk.Frame(stats_frame, bg=t["bg"])
        stats_grid.pack()
        
        stat_items = [
            ("Total Files", "total_files"),
            ("Verified Files", "verified_files"),
            ("Tampered Files", "tampered_files"),
            ("Missing Files", "missing_files")
        ]
        
        for i, (label, key) in enumerate(stat_items):
            cell = tk.Frame(stats_grid, bg=t["bg"], padx=20)
            cell.grid(row=0, column=i, padx=10)
            
            tk.Label(cell, text=label, fg=t["fg"], bg=t["bg"], 
                    font=("Segoe UI", 11)).pack()
            
            value_label = tk.Label(cell, text="0", fg=t["select"], 
                                  bg=t["bg"], font=("Segoe UI", 16, "bold"))
            value_label.pack()
            
            self.hash_stats_labels[key] = value_label
        
        # Database actions
        action_frame = tk.LabelFrame(self.db_tab, text="🛠️ Database Actions", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                    padx=20, pady=20)
        action_frame.pack(fill="x", padx=30, pady=20)
        
        action_grid = tk.Frame(action_frame, bg=t["bg"])
        action_grid.pack()
        
        actions = [
            ("🔄 Refresh Database", self.refresh_hash_database, "#3498db"),
            ("🧹 Cleanup Missing", self.cleanup_missing_hashes, "#f39c12"),
            ("💾 Backup Database", self.backup_hash_database, "#27ae60"),
            ("🗑️ Clear Database", self.clear_hash_database, "#e74c3c")
        ]
        
        for i, (text, command, color) in enumerate(actions):
            btn = tk.Button(action_grid, text=text, command=command,
                           bg=color, fg="white", font=("Segoe UI", 11, "bold"),
                           padx=15, pady=8)
            btn.grid(row=i//2, column=i%2, padx=10, pady=10)
        
        # Registered files list
        list_frame = tk.LabelFrame(self.db_tab, text="📋 Registered Files", 
                                  bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                  padx=20, pady=20)
        list_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Listbox with scrollbar
        list_scroll = tk.Scrollbar(list_frame, bg=t["bg"])
        list_scroll.pack(side="right", fill="y")
        
        self.hash_listbox = tk.Listbox(list_frame, height=15, 
                                      bg=t["text_bg"], fg=t["text_fg"],
                                      font=("Segoe UI", 10),
                                      yscrollcommand=list_scroll.set,
                                      selectbackground=t["select"],
                                      selectforeground="white")
        self.hash_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        list_scroll.config(command=self.hash_listbox.yview)
        
        # List controls
        list_controls = tk.Frame(list_frame, bg=t["bg"])
        list_controls.pack(fill="x", pady=5)
        
        tk.Button(list_controls, text="🔄 Refresh List", 
                 command=self.refresh_hash_list,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(list_controls, text="📋 Copy Selected", 
                 command=self.copy_selected_hash,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(list_controls, text="🗑️ Remove Selected", 
                 command=self.remove_selected_hash,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        # Initialize
        self.refresh_hash_database()
    
    def browse_hash_file(self):
        """Browse for file to hash"""
        file = filedialog.askopenfilename(title="Select File to Register")
        if file:
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, file)
            
            # Also update verify entry
            if hasattr(self, 'verify_file_entry'):
                self.verify_file_entry.delete(0, tk.END)
                self.verify_file_entry.insert(0, file)
    
    def browse_hash_folder(self):
        """Browse for folder to hash"""
        folder = filedialog.askdirectory(title="Select Folder to Register")
        if folder:
            self.hash_folder_entry.delete(0, tk.END)
            self.hash_folder_entry.insert(0, folder)
    
    def browse_verify_file(self):
        """Browse for file to verify"""
        file = filedialog.askopenfilename(title="Select File to Verify")
        if file:
            self.verify_file_entry.delete(0, tk.END)
            self.verify_file_entry.insert(0, file)
    
    def register_file_hash(self):
        """Register a single file for hash verification"""
        filepath = self.hash_file_entry.get().strip()
        if not filepath:
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        if not os.path.exists(filepath):
            messagebox.showerror("File Not Found", "The selected file does not exist!")
            return
        
        # Check if already registered
        if self.app.hash_verifier.is_registered(filepath) and not self.overwrite_hash_var.get():
            response = messagebox.askyesno("Already Registered", 
                                          f"File is already registered.\n\n"
                                          f"Overwrite existing registration?")
            if not response:
                return
        
        # Register the file
        success, message = self.app.hash_verifier.register_file(filepath)
        
        if success:
            messagebox.showinfo("Success", message)
            if hasattr(self.app, 'monitor_tab') and hasattr(self.app.monitor_tab, 'log_output'):
                self.app.monitor_tab.log_output.configure(state="normal")
                self.app.monitor_tab.log_output.insert("end", f"🔐 {message}\n")
                self.app.monitor_tab.log_output.configure(state="disabled")
            
            # Update database view
            self.refresh_hash_database()
        else:
            messagebox.showerror("Error", message)
    
    def register_folder_hash(self):
        """Register all files in a folder"""
        folder = self.hash_folder_entry.get().strip()
        if not folder:
            messagebox.showwarning("No Folder", "Please select a folder first!")
            return
        
        if not os.path.exists(folder):
            messagebox.showerror("Folder Not Found", "The selected folder does not exist!")
            return
        
        # Confirm large folder registration
        file_count = sum([len(files) for _, _, files in os.walk(folder)])
        if file_count > 100:
            response = messagebox.askyesno("Large Folder", 
                                          f"Folder contains {file_count} files.\n\n"
                                          f"This may take a while. Continue?")
            if not response:
                return
        
        # Register folder
        success, message = self.app.hash_verifier.register_folder(
            folder, 
            recursive=self.recursive_hash_var.get()
        )
        
        messagebox.showinfo("Registration Complete", message)
        if hasattr(self.app, 'monitor_tab') and hasattr(self.app.monitor_tab, 'log_output'):
            self.app.monitor_tab.log_output.configure(state="normal")
            self.app.monitor_tab.log_output.insert("end", f"📂 {message}\n")
            self.app.monitor_tab.log_output.configure(state="disabled")
        
        # Update database view
        self.refresh_hash_database()
    
    def verify_file_hash(self):
        """Verify a single file's integrity"""
        filepath = self.verify_file_entry.get().strip()
        if not filepath:
            messagebox.showwarning("No File", "Please select a file to verify!")
            return
        
        status, message, tamper_info = self.app.hash_verifier.verify_file(filepath)
        
        # Display results
        self.verify_results_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if status == "VERIFIED":
            self.verify_results_text.insert("end", 
                f"[{timestamp}] ✅ VERIFIED: {os.path.basename(filepath)}\n"
                f"    {message}\n\n")
        elif status == "TAMPERED":
            self.verify_results_text.insert("end", 
                f"[{timestamp}] 🚨 TAMPERED: {os.path.basename(filepath)}\n"
                f"    {message}\n"
                f"    Original Hash: {tamper_info['original_hash'][:32]}...\n"
                f"    Current Hash:  {tamper_info['current_hash'][:32]}...\n\n")
            
            # Show alert
            messagebox.showerror("File Tampered!", 
                               f"File integrity violation detected!\n\n"
                               f"File: {os.path.basename(filepath)}\n"
                               f"Location: {os.path.dirname(filepath)}\n\n"
                               f"File has been modified without authorization!")
        elif status == "MISSING":
            self.verify_results_text.insert("end", 
                f"[{timestamp}] ❌ MISSING: {os.path.basename(filepath)}\n"
                f"    {message}\n\n")
        elif status == "NOT_REGISTERED":
            self.verify_results_text.insert("end", 
                f"[{timestamp}] ⚠️ NOT REGISTERED: {os.path.basename(filepath)}\n"
                f"    {message}\n\n")
        else:
            self.verify_results_text.insert("end", 
                f"[{timestamp}] ❓ ERROR: {os.path.basename(filepath)}\n"
                f"    {message}\n\n")
        
        self.verify_results_text.see("end")
        self.verify_results_text.configure(state="disabled")
        
        # Update database stats
        self.refresh_hash_database()
    
    def verify_all_hashes(self):
        """Verify all registered files"""
        if not self.app.hash_verifier.hash_database:
            messagebox.showinfo("Empty Database", "No files registered for verification.")
            return
        
        response = messagebox.askyesno("Verify All Files", 
                                      f"Verify all {len(self.app.hash_verifier.hash_database)} registered files?\n\n"
                                      "This may take a while depending on file sizes.")
        if not response:
            return
        
        # Show progress
        progress_window = tk.Toplevel(self.frame)
        progress_window.title("Verification Progress")
        progress_window.geometry("400x150")
        progress_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        progress_window.resizable(False, False)
        progress_window.grab_set()
        
        tk.Label(progress_window, text="🔍 Verifying Files...", 
                font=("Segoe UI", 14, "bold"), 
                fg=constants.THEMES[self.app.config["theme"]]["fg"],
                bg=constants.THEMES[self.app.config["theme"]]["bg"]).pack(pady=20)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_window, variable=progress_var, 
                                      maximum=100, length=300)
        progress_bar.pack(pady=10)
        
        status_label = tk.Label(progress_window, text="Starting...",
                               fg=constants.THEMES[self.app.config["theme"]]["fg"],
                               bg=constants.THEMES[self.app.config["theme"]]["bg"])
        status_label.pack(pady=10)
        
        progress_window.update()
        
        # Run verification in background
        def run_verification():
            results = self.app.hash_verifier.verify_all_files()
            
            progress_window.destroy()
            
            # Show summary
            summary = f"""📊 Verification Complete!

✅ Verified: {len(results['verified'])}
🚨 Tampered: {len(results['tampered'])}
❌ Missing: {len(results['missing'])}
⚠️ Errors: {len(results['errors'])}
📊 Total: {results['total']}

"""
            
            if results['tampered']:
                summary += "\n🚨 TAMPERED FILES:\n"
                for item in results['tampered'][:10]:
                    summary += f"• {item['filename']}\n"
                if len(results['tampered']) > 10:
                    summary += f"... and {len(results['tampered']) - 10} more\n"
            
            # Update results text
            self.verify_results_text.configure(state="normal")
            self.verify_results_text.insert("end", 
                f"\n{'='*60}\n"
                f"BATCH VERIFICATION COMPLETE\n"
                f"Time: {datetime.now().strftime('%H:%M:%S')}\n"
                f"{summary}\n"
                f"{'='*60}\n\n")
            self.verify_results_text.see("end")
            self.verify_results_text.configure(state="disabled")
            
            # Show message box
            messagebox.showinfo("Verification Results", summary)
            
            # Update database stats
            self.refresh_hash_database()
        
        # Start verification thread
        threading.Thread(target=run_verification, daemon=True).start()
        
        # Update progress bar (simulated)
        def update_progress():
            for i in range(101):
                progress_var.set(i)
                status_label.config(text=f"Processing... {i}%")
                progress_window.update()
                time.sleep(0.05)
        
        threading.Thread(target=update_progress, daemon=True).start()
    
    def unregister_file_hash(self):
        """Unregister a file from hash verification"""
        filepath = self.verify_file_entry.get().strip()
        if not filepath:
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        success, message = self.app.hash_verifier.unregister_file(filepath)
        
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_hash_database()
        else:
            messagebox.showwarning("Not Found", message)
    
    def clear_verify_results(self):
        """Clear verification results"""
        self.verify_results_text.configure(state="normal")
        self.verify_results_text.delete("1.0", "end")
        self.verify_results_text.insert("end", f"Results cleared at {datetime.now().strftime('%H:%M:%S')}\n\n")
        self.verify_results_text.configure(state="disabled")
    
    def save_verify_report(self):
        """Save verification report to file"""
        content = self.verify_results_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("Empty", "No results to save.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"hash_verify_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Report saved to:\n{filename}")
    
    def refresh_hash_database(self):
        """Refresh hash database statistics and list"""
        # Update statistics
        total = len(self.app.hash_verifier.hash_database)
        
        # Count verification statuses
        verified = 0
        tampered = 0
        missing = 0
        
        for filepath in self.app.hash_verifier.hash_database:
            if not os.path.exists(filepath):
                missing += 1
            else:
                # Quick check if file might be tampered
                current_size = os.path.getsize(filepath)
                stored_size = self.app.hash_verifier.hash_database[filepath].get('size', 0)
                if current_size != stored_size:
                    tampered += 1
                else:
                    verified += 1
        
        # Update stats labels
        if hasattr(self, 'hash_stats_labels'):
            self.hash_stats_labels['total_files'].config(text=str(total))
            self.hash_stats_labels['verified_files'].config(text=str(verified))
            self.hash_stats_labels['tampered_files'].config(text=str(tampered))
            self.hash_stats_labels['missing_files'].config(text=str(missing))
        
        # Update listbox
        self.refresh_hash_list()
    
    def refresh_hash_list(self):
        """Refresh the hash listbox"""
        if not hasattr(self, 'hash_listbox'):
            return
        
        self.hash_listbox.delete(0, tk.END)
        
        registered = self.app.hash_verifier.get_registered_files()
        registered.sort()
        
        for filepath in registered:
            filename = os.path.basename(filepath)
            exists = "✅" if os.path.exists(filepath) else "❌"
            self.hash_listbox.insert(tk.END, f"{exists} {filename}")
    
    def cleanup_missing_hashes(self):
        """Remove missing files from hash database"""
        missing = self.app.hash_verifier.cleanup_missing_files()
        
        if missing:
            messagebox.showinfo("Cleanup Complete", 
                              f"Removed {len(missing)} missing files from database.")
        else:
            messagebox.showinfo("No Missing Files", "No missing files found in database.")
        
        self.refresh_hash_database()
    
    def backup_hash_database(self):
        """Backup hash database"""
        backup_file = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"hash_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if backup_file:
            try:
                shutil.copy2("data/file_hashes.json", backup_file)
                messagebox.showinfo("Backup Complete", 
                                  f"Hash database backed up to:\n{backup_file}")
            except Exception as e:
                messagebox.showerror("Backup Failed", f"Error: {e}")
    
    def clear_hash_database(self):
        """Clear entire hash database"""
        if not self.app.hash_verifier.hash_database:
            messagebox.showinfo("Empty", "Database is already empty.")
            return
        
        response = messagebox.askyesno("Clear Database", 
                                      f"Clear entire hash database?\n\n"
                                      f"This will remove {len(self.app.hash_verifier.hash_database)} entries.\n"
                                      f"This action cannot be undone!")
        
        if response:
            self.app.hash_verifier.hash_database.clear()
            self.app.hash_verifier.save_hash_database()
            self.refresh_hash_database()
            messagebox.showinfo("Cleared", "Hash database cleared.")
    
    def copy_selected_hash(self):
        """Copy selected hash entry to clipboard"""
        selection = self.hash_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an item first.")
            return
        
        index = selection[0]
        registered_files = self.app.hash_verifier.get_registered_files()
        registered_files.sort()
        
        if index < len(registered_files):
            filepath = registered_files[index]
            info = self.app.hash_verifier.get_file_info(filepath)
            
            if info:
                clipboard_text = f"File: {os.path.basename(filepath)}\n"
                clipboard_text += f"Path: {filepath}\n"
                clipboard_text += f"Hash: {info.get('hash', 'N/A')[:64]}\n"
                clipboard_text += f"Registered: {info.get('registered', 'N/A')}\n"
                clipboard_text += f"Size: {info.get('size', 0)} bytes"
                
                self.frame.clipboard_clear()
                self.frame.clipboard_append(clipboard_text)
                messagebox.showinfo("Copied", "File information copied to clipboard.")
    
    def remove_selected_hash(self):
        """Remove selected hash entry"""
        selection = self.hash_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an item first.")
            return
        
        index = selection[0]
        registered_files = self.app.hash_verifier.get_registered_files()
        registered_files.sort()
        
        if index < len(registered_files):
            filepath = registered_files[index]
            filename = os.path.basename(filepath)
            
            response = messagebox.askyesno("Remove Entry", 
                                          f"Remove '{filename}' from hash database?")
            
            if response:
                self.app.hash_verifier.unregister_file(filepath)
                self.refresh_hash_database()
                messagebox.showinfo("Removed", f"Removed '{filename}' from database.")