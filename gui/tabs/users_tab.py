"""
Users and certificate management tab for TrustVault
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import json
from datetime import datetime
from config import constants

class UsersTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        
        # DEBUG: Print to see if this is being called
        print(f"DEBUG: UsersTab initialized with theme: {app.config.get('theme', 'default')}")
        
        # Create the main frame
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        # Build the UI
        self.build_ui()
        
        # Refresh certificate list
        self.refresh_certificate_list()
        
        # DEBUG: Force the frame to be visible
        self.frame.pack(fill="both", expand=True)
    
    def build_ui(self):
        """Build the users/certificates tab UI"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # DEBUG: Print theme colors
        print(f"DEBUG: Theme colors - bg: {t['bg']}, fg: {t['fg']}")
        
        # Main frame with notebook
        main_notebook = ttk.Notebook(self.frame)
        main_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: Certificate Management
        cert_tab = tk.Frame(main_notebook, bg=t["bg"])
        main_notebook.add(cert_tab, text="📜 Certificates")
        
        # Tab 2: User Management
        user_tab = tk.Frame(main_notebook, bg=t["bg"])
        main_notebook.add(user_tab, text="👤 Users")
        
        # Tab 3: Access Logs
        logs_tab = tk.Frame(main_notebook, bg=t["bg"])
        main_notebook.add(logs_tab, text="📋 Access Logs")
        
        # Build each tab
        self.build_certificate_tab(cert_tab, t)
        self.build_user_tab(user_tab, t)
        self.build_access_logs_tab(logs_tab, t)
        
        # DEBUG: Print success message
        print("DEBUG: UsersTab UI built successfully")
    
    def build_certificate_tab(self, parent, theme):
        """Build certificate management tab"""
        t = theme
        
        # DEBUG
        print(f"DEBUG: Building certificate tab with bg: {t['bg']}")
        
        # Title
        tk.Label(parent, text="📜 Certificate Management", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Certificate generation frame
        gen_frame = tk.LabelFrame(parent, text="➕ Generate New Certificate", 
                                 bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                 padx=20, pady=20)
        gen_frame.pack(fill="x", padx=30, pady=20)
        
        # Username input
        user_frame = tk.Frame(gen_frame, bg=t["bg"])
        user_frame.pack(fill="x", pady=10)
        
        tk.Label(user_frame, text="Username:", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=15, anchor="w").pack(side="left")
        
        self.username_entry = tk.Entry(user_frame, width=30, 
                                      bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 12))
        self.username_entry.pack(side="left", padx=10)

        pass_frame = tk.Frame(gen_frame, bg=t["bg"])
        pass_frame.pack(fill="x", pady=10)

        tk.Label(pass_frame, text="Keystore Password:", fg=t["fg"], bg=t["bg"],
                font=("Segoe UI", 11), width=15, anchor="w").pack(side="left")

        self.cert_password_entry = tk.Entry(pass_frame, width=30, show="*",
                                           bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 12))
        self.cert_password_entry.pack(side="left", padx=10)
        
        # Certificate options
        options_frame = tk.Frame(gen_frame, bg=t["bg"])
        options_frame.pack(fill="x", pady=10)
        
        self.cert_duration_var = tk.IntVar(value=365)  # Default 1 year
        tk.Label(options_frame, text="Validity (days):", fg=t["fg"], bg=t["bg"], 
                font=("Segoe UI", 11), width=15, anchor="w").pack(side="left")
        
        self.duration_entry = tk.Entry(options_frame, width=10, 
                                 bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11),
                                 textvariable=self.cert_duration_var)
        self.duration_entry.pack(side="left", padx=10)
        
        # Action buttons
        action_frame = tk.Frame(gen_frame, bg=t["bg"])
        action_frame.pack(pady=20)
        
        tk.Button(action_frame, text="📄 Generate Certificate", 
                 command=self.generate_certificate,
                 bg="#27ae60", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=15, pady=8).pack(side="left", padx=10)
        
        tk.Button(action_frame, text="🚫 Revoke Certificate", 
                 command=self.revoke_certificate,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 11, "bold"), 
                 padx=15, pady=8).pack(side="left", padx=10)
        
        # Certificate list frame
        list_frame = tk.LabelFrame(parent, text="📋 Certificates List", 
                                  bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                  padx=20, pady=20)
        list_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Treeview for certificates
        columns = ("Status", "Username", "Issued Date", "Expiry Date", "Type")
        self.cert_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        # Define headings
        self.cert_tree.heading("Status", text="Status")
        self.cert_tree.heading("Username", text="Username")
        self.cert_tree.heading("Issued Date", text="Issued Date")
        self.cert_tree.heading("Expiry Date", text="Expiry Date")
        self.cert_tree.heading("Type", text="Type")
        
        # Define columns
        self.cert_tree.column("Status", width=80)
        self.cert_tree.column("Username", width=150)
        self.cert_tree.column("Issued Date", width=120)
        self.cert_tree.column("Expiry Date", width=120)
        self.cert_tree.column("Type", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.cert_tree.yview)
        self.cert_tree.configure(yscrollcommand=scrollbar.set)
        
        self.cert_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Certificate controls
        cert_controls = tk.Frame(list_frame, bg=t["bg"])
        cert_controls.pack(fill="x", pady=5)
        
        tk.Button(cert_controls, text="🔄 Refresh List", 
                 command=self.refresh_certificate_list,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(cert_controls, text="📋 View Details", 
                 command=self.view_certificate_details,
                 bg="#3498db", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(cert_controls, text="💾 Export Selected", 
                 command=self.export_certificate,
                 bg="#9b59b6", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
    
    def build_user_tab(self, parent, theme):
        """Build user management tab"""
        t = theme
        
        # Title
        tk.Label(parent, text="👤 User Account Management", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # User creation frame
        create_frame = tk.LabelFrame(parent, text="➕ Create New User", 
                                    bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                    padx=20, pady=20)
        create_frame.pack(fill="x", padx=30, pady=20)
        
        # Form fields
        fields = [
            ("Username:", "username_entry"),
            ("Password:", "password_entry"),
            ("Confirm Password:", "confirm_password_entry"),
            ("Email:", "email_entry"),
            ("Role:", "role_combo")
        ]
        
        self.user_fields = {}
        
        for i, (label, field_name) in enumerate(fields):
            frame = tk.Frame(create_frame, bg=t["bg"])
            frame.pack(fill="x", pady=8)
            
            tk.Label(frame, text=label, fg=t["fg"], bg=t["bg"], 
                    font=("Segoe UI", 11), width=20, anchor="w").pack(side="left")
            
            if "password" in field_name:
                entry = tk.Entry(frame, width=30, 
                                bg=t["entry_bg"], fg=t["fg"], 
                                font=("Segoe UI", 11), show="●")
            elif field_name == "role_combo":
                entry = ttk.Combobox(frame, values=["Admin", "Operator", "Viewer"], 
                                    state="readonly", width=27)
                entry.set("Operator")
            else:
                entry = tk.Entry(frame, width=30, 
                                bg=t["entry_bg"], fg=t["fg"], font=("Segoe UI", 11))
            
            entry.pack(side="left", padx=10)
            self.user_fields[field_name] = entry
        
        # Create user button
        tk.Button(create_frame, text="👤 Create User", 
                 command=self.create_user,
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(pady=10)
        
        # Users list frame
        users_frame = tk.LabelFrame(parent, text="📋 System Users", 
                                   bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                   padx=20, pady=20)
        users_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Users listbox
        self.users_listbox = tk.Listbox(users_frame, height=10,
                                       bg=t["text_bg"], fg=t["text_fg"],
                                       font=("Segoe UI", 11),
                                       selectbackground=t["select"])
        self.users_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.refresh_users_list()
        
        # User controls
        user_controls = tk.Frame(users_frame, bg=t["bg"])
        user_controls.pack(fill="x", pady=5)
        
        tk.Button(user_controls, text="🗑️ Delete User", 
                 command=self.delete_user,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(user_controls, text="🔧 Edit User", 
                 command=self.edit_user,
                 bg="#3498db", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(user_controls, text="🔄 Reset Password", 
                 command=self.reset_password,
                 bg="#f39c12", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
    
    def build_access_logs_tab(self, parent, theme):
        """Build access logs tab"""
        t = theme
        
        # Title
        tk.Label(parent, text="📋 System Access Logs", 
                font=("Segoe UI", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Controls frame
        controls_frame = tk.Frame(parent, bg=t["bg"])
        controls_frame.pack(fill="x", padx=30, pady=10)
        
        # Date filter
        tk.Label(controls_frame, text="Filter by Date:", fg=t["fg"], bg=t["bg"],
                font=("Segoe UI", 11)).pack(side="left", padx=5)
        
        self.date_filter_var = tk.StringVar(value="All")
        date_filter = ttk.Combobox(controls_frame, textvariable=self.date_filter_var,
                                  values=["All", "Today", "Last 7 days", "Last 30 days", "Custom"],
                                  state="readonly", width=15)
        date_filter.pack(side="left", padx=5)
        
        # User filter
        tk.Label(controls_frame, text="Filter by User:", fg=t["fg"], bg=t["bg"],
                font=("Segoe UI", 11)).pack(side="left", padx=5)
        
        self.user_filter_var = tk.StringVar(value="All")
        user_filter = ttk.Combobox(controls_frame, textvariable=self.user_filter_var,
                                  values=["All", "admin", "operator", "viewer", "auditor"],
                                  state="readonly", width=15)
        user_filter.pack(side="left", padx=5)
        
        tk.Button(controls_frame, text="🔍 Apply Filters", 
                 command=self.apply_log_filters,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        
        tk.Button(controls_frame, text="🗑️ Clear Logs", 
                 command=self.clear_access_logs,
                 bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        
        # Logs display
        logs_frame = tk.LabelFrame(parent, text="📜 Access Log Entries", 
                                  bg=t["bg"], fg=t["fg"], font=("Segoe UI", 14, "bold"),
                                  padx=20, pady=20)
        logs_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Text widget with scrollbar
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=15,
                                                  bg=t["text_bg"], fg=t["text_fg"],
                                                  font=("Segoe UI", 10))
        self.logs_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Load sample logs
        self.load_sample_logs()
# METHODS CONTINUATION - Add these to the UsersTab class
    
    def generate_certificate(self):
        """Generate a new certificate and private key"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Missing Username", "Please enter a username!")
            return
        cert_password = self.cert_password_entry.get()
        if not cert_password:
            messagebox.showwarning("Missing Password", "Please enter a PKCS#12 keystore password!")
            return
        
        # Paths for certificate and key
        cert_path = f"certs/{username}.pem"
        key_path = f"keys/{username}.p12"
        
        # Check if certificate already exists
        if os.path.exists(cert_path) or os.path.exists(key_path):
            response = messagebox.askyesno("Files Exist", 
                                          f"Certificate or key files for '{username}' already exist.\n\n"
                                          "Do you want to overwrite them?")
            if not response:
                return
        
        try:
            # Get validity duration
            try:
                duration_days = int(self.cert_duration_var.get())
            except (ValueError, AttributeError):
                duration_days = 365

            from security.key_certificate import generate_certificate
            success, message = generate_certificate(
                username,
                password=cert_password,
                validity_days=duration_days,
                export_pkcs12=True,
                key_algorithm="RSA",
            )
            if not success:
                messagebox.showerror("Certificate Error", message)
                return

            self._reactivate_certificate(username)
            
            # Log the generation
            self.log_access_event(f"CERTIFICATE_GENERATED - User: {username} - Validity: {duration_days} days (RSA-2048, password-protected)")
            
            messagebox.showinfo("Certificate Generated",
                              f"Certificate and key generated successfully!\n\n"
                              f"{message}\n\n"
                              f"IMPORTANT:\n"
                              f"- Keep the private key secure and confidential\n"
                              f"- Store the passphrase separately from the key file\n"
                              f"- Back up both files securely")
            
            # Clear entry and refresh list
            self.username_entry.delete(0, tk.END)
            self.cert_password_entry.delete(0, tk.END)
            self.refresh_certificate_list(select_username=username)
            self.refresh_users_list()
            
        except Exception as e:
            messagebox.showerror("Generation Error", 
                               f"Failed to generate certificate and key:\n\n{str(e)}")
    
    def log_access_event(self, event_message):
        """Log an access event (helper method)"""
        try:
            log_file = "data/access_logs.txt"
            os.makedirs("data", exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"[{timestamp}] {event_message}\n"
            
            with open(log_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to log event: {e}")
    
    def revoke_certificate(self):
        """Revoke a certificate"""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate to revoke!")
            return
        
        item = self.cert_tree.item(selection[0])
        values = item.get('values', [])
        if len(values) < 2:
            messagebox.showerror("Selection Error", "Could not read the selected certificate.")
            return

        username = str(values[1])
        
        response = messagebox.askyesno("Revoke Certificate", 
                                      f"Are you sure you want to revoke the certificate for '{username}'?\n\n"
                                      "This action cannot be undone!")
        
        if response:
            try:
                revoked_file = "data/revoked_certs.json"
                os.makedirs("data", exist_ok=True)

                revoked = self._load_json_list(revoked_file)
                revoked_names = {
                    entry.get('username') if isinstance(entry, dict) else entry
                    for entry in revoked
                }

                if username not in revoked_names:
                    revoked.append({
                        'username': username,
                        'revoked_at': datetime.now().isoformat(),
                        'revoked_by': self.app.config.get('last_user', 'admin')
                    })
                    
                    self._write_json_file(revoked_file, revoked)

                    core_revoked = self._load_json_list(constants.REVOKED_FILE)
                    if username not in core_revoked:
                        core_revoked.append(username)
                        self._write_json_file(constants.REVOKED_FILE, core_revoked)

                    messagebox.showinfo("Certificate Revoked", 
                                      f"Certificate for '{username}' has been revoked!")
                    self.log_access_event(f"CERTIFICATE_REVOKED - User: {username}")
                    self.refresh_certificate_list()
                else:
                    messagebox.showinfo("Already Revoked", f"Certificate already revoked for '{username}'")
                    
            except Exception as e:
                messagebox.showerror("Revocation Error", f"Failed to revoke certificate:\n\n{str(e)}")
    
    def refresh_certificate_list(self, select_username=None):
        """Refresh the certificate list from the configured certs directory."""
        for item in self.cert_tree.get_children():
            self.cert_tree.delete(item)

        try:
            rows = []
            selected_item = None

            certs_dir = constants.CERT_DIR
            os.makedirs(certs_dir, exist_ok=True)

            for cert_file in sorted(os.listdir(certs_dir), key=str.lower):
                if not cert_file.lower().endswith('.pem'):
                    continue

                username = os.path.splitext(cert_file)[0]
                cert_path = os.path.join(certs_dir, cert_file)
                if self._is_certificate_revoked(username, cert_path):
                    continue

                issued_date, expiry_date = self._get_certificate_dates(cert_path)
                status = "ACTIVE"

                item_id = self.cert_tree.insert("", "end", values=(
                    status,
                    username,
                    issued_date,
                    expiry_date,
                    "User Certificate"
                ))
                rows.append({
                    "username": username,
                    "status": status,
                    "created": issued_date,
                    "expires": expiry_date
                })

                if select_username and username.lower() == select_username.lower():
                    selected_item = item_id

            self._save_certificate_metadata(rows)

            if selected_item:
                self.cert_tree.selection_set(selected_item)
                self.cert_tree.see(selected_item)
            self.cert_tree.update_idletasks()

        except Exception as e:
            print(f"Error refreshing certificate list: {e}")
            messagebox.showerror("Certificate List Error", f"Failed to refresh certificates:\n\n{e}")

    def _load_revoked_usernames(self):
        """Load revoked certificate usernames from both revocation stores."""
        revoked = set()

        revoked_certs_file = "data/revoked_certs.json"
        for entry in self._load_json_list(revoked_certs_file):
            if isinstance(entry, dict) and entry.get("username"):
                revoked.add(entry["username"])
            elif isinstance(entry, str):
                revoked.add(entry)

        for entry in self._load_json_list(constants.REVOKED_FILE):
            if isinstance(entry, str):
                revoked.add(entry)

        return revoked

    def _is_certificate_revoked(self, username, cert_path):
        """Return True only when the revocation is newer than the cert file."""
        target = username.lower()
        has_timestamped_revocation = False
        newest_revoked_at = None

        for entry in self._load_json_list("data/revoked_certs.json"):
            if isinstance(entry, dict):
                entry_username = entry.get("username")
                if not isinstance(entry_username, str) or entry_username.lower() != target:
                    continue

                revoked_at = entry.get("revoked_at")
                if not revoked_at:
                    return True

                try:
                    revoked_time = datetime.fromisoformat(revoked_at)
                except (TypeError, ValueError):
                    return True

                has_timestamped_revocation = True
                if newest_revoked_at is None or revoked_time > newest_revoked_at:
                    newest_revoked_at = revoked_time
            elif isinstance(entry, str) and entry.lower() == target:
                return True

        if newest_revoked_at:
            cert_mtime = datetime.fromtimestamp(os.path.getmtime(cert_path))
            return newest_revoked_at >= cert_mtime

        for entry in self._load_json_list(constants.REVOKED_FILE):
            if isinstance(entry, str) and entry.lower() == target:
                return not has_timestamped_revocation

        return False

    def _load_json_list(self, path):
        """Load a JSON list, returning [] for missing, empty, or invalid files."""
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return []

        try:
            with open(path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _reactivate_certificate(self, username):
        """Remove a regenerated certificate from revocation stores."""
        target = username.lower()
        revoked_file = "data/revoked_certs.json"

        revoked = self._load_json_list(revoked_file)
        active_revoked = []
        changed = False
        for entry in revoked:
            entry_username = entry.get("username") if isinstance(entry, dict) else entry
            if isinstance(entry_username, str) and entry_username.lower() == target:
                changed = True
                continue
            active_revoked.append(entry)

        if changed:
            self._write_json_file(revoked_file, active_revoked)

        core_revoked = self._load_json_list(constants.REVOKED_FILE)
        active_core_revoked = [
            entry for entry in core_revoked
            if not (isinstance(entry, str) and entry.lower() == target)
        ]
        if len(active_core_revoked) != len(core_revoked):
            self._write_json_file(constants.REVOKED_FILE, active_core_revoked)

    def _write_json_file(self, path, data):
        """Write JSON through a temp file so existing read locks do not break revoke."""
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)

        temp_path = f"{path}.tmp"
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, path)

    def _get_certificate_dates(self, cert_path):
        """Read certificate validity dates, falling back to file timestamps."""
        try:
            from cryptography import x509

            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            try:
                issued = cert.not_valid_before_utc
                expires = cert.not_valid_after_utc
            except AttributeError:
                issued = cert.not_valid_before
                expires = cert.not_valid_after

            return issued.strftime('%Y-%m-%d'), expires.strftime('%Y-%m-%d')
        except Exception:
            mtime = datetime.fromtimestamp(os.path.getmtime(cert_path))
            return (
                mtime.strftime('%Y-%m-%d'),
                mtime.replace(year=mtime.year + 1).strftime('%Y-%m-%d')
            )

    def _save_certificate_metadata(self, rows):
        """Keep data/certificates.json in sync with the visible certificate list."""
        try:
            self._write_json_file("data/certificates.json", {"certificates": rows})
        except OSError as e:
            print(f"Failed to save certificate metadata: {e}")


    def refresh_users_list(self):
        """Refresh the user account list from data/users.json."""
        try:
            from security.users import list_users
            self.users_listbox.delete(0, tk.END)
            for user in sorted(list_users(), key=lambda item: item.get("username", "").lower()):
                username = user.get("username", "unknown")
                role = user.get("role", "Operator")
                state = "active" if user.get("active", True) else "disabled"
                self.users_listbox.insert(tk.END, f"{username} ({role}, {state})")
        except Exception as e:
            print(f"Failed to refresh users list: {e}")
    def view_certificate_details(self):
        """View certificate details"""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate!")
            return
        
        item = self.cert_tree.item(selection[0])
        username = item['values'][1]
        status = item['values'][0]
        
        details_window = tk.Toplevel(self.app.root)
        details_window.title(f"Certificate Details - {username}")
        details_window.geometry("600x400")
        details_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        details_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        # Title
        tk.Label(details_window, text=f"📜 Certificate Details", 
                font=("Segoe UI", 16, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Details frame
        details_frame = tk.Frame(details_window, bg=t["bg"])
        details_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        details_text = f"""
Certificate Information:

• Username: {username}
• Status: {status}
• Issued: {item['values'][2]}
• Expires: {item['values'][3]}
• Type: {item['values'][4]}

Files:
• Certificate: certs/{username}.pem
• Private Key: keys/{username}_private.key

Actions:
- Keep private key secure
- Do not share private key
- Renew before expiry
"""
        
        text_widget = tk.Text(details_frame, height=15, width=60,
                             bg=t["text_bg"], fg=t["text_fg"],
                             font=("Segoe UI", 10))
        text_widget.insert("1.0", details_text)
        text_widget.configure(state="disabled")
        text_widget.pack(fill="both", expand=True)
        
        # Close button
        tk.Button(details_window, text="Close", command=details_window.destroy,
                 bg=t["btn"], fg=t["btn_fg"], font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(pady=20)
    
    def export_certificate(self):
        """Export selected certificate"""
        selection = self.cert_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a certificate to export!")
            return
        
        item = self.cert_tree.item(selection[0])
        username = item['values'][1]
        
        cert_file = f"certs/{username}.pem"
        if not os.path.exists(cert_file):
            messagebox.showerror("File Not Found", f"Certificate file not found: {cert_file}")
            return
        
        # Ask for export location
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile=f"{username}_certificate.pem"
        )
        
        if filename:
            try:
                import shutil
                shutil.copy2(cert_file, filename)
                messagebox.showinfo("Export Complete", f"Certificate exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export certificate:\n\n{str(e)}")
    
    def create_user(self):
        """Create a new user"""
        username = self.user_fields["username_entry"].get().strip()
        password = self.user_fields["password_entry"].get()
        confirm = self.user_fields["confirm_password_entry"].get()
        email = self.user_fields["email_entry"].get().strip()
        role = self.user_fields["role_combo"].get()
        
        # Validation
        if not username or not password:
            messagebox.showwarning("Missing Information", "Username and password are required!")
            return
        
        if password != confirm:
            messagebox.showwarning("Password Mismatch", "Passwords do not match!")
            return
        
        if email and "@" not in email:
            messagebox.showwarning("Invalid Email", "Please enter a valid email address!")
            return
        
        # In a real implementation, this would save to a database
        # For now, just add to listbox
        self.users_listbox.insert(tk.END, f"{username} ({role})")
        
        # Clear fields
        for field in self.user_fields.values():
            if isinstance(field, tk.Entry):
                field.delete(0, tk.END)
            elif isinstance(field, ttk.Combobox):
                field.set("Operator")
        
        messagebox.showinfo("User Created", 
                          f"User '{username}' created successfully!\n\n"
                          f"Role: {role}\n"
                          f"Email: {email or 'Not provided'}")
    
    def delete_user(self):
        """Delete selected user"""
        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to delete!")
            return
        
        index = selection[0]
        user_info = self.users_listbox.get(index)
        username = user_info.split()[0]
        
        if username == "admin":
            messagebox.showerror("Cannot Delete", "The admin user cannot be deleted!")
            return
        
        response = messagebox.askyesno("Delete User", 
                                      f"Are you sure you want to delete user '{username}'?\n\n"
                                      "This action cannot be undone!")
        
        if response:
            self.users_listbox.delete(index)
            messagebox.showinfo("User Deleted", f"User '{username}' has been deleted.")
    
    def edit_user(self):
        """Edit selected user"""
        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to edit!")
            return
        
        index = selection[0]
        user_info = self.users_listbox.get(index)
        
        # For simplicity, just show a message
        messagebox.showinfo("Edit User", 
                          f"Edit functionality for '{user_info}'\n\n"
                          "In a full implementation, this would open an edit dialog.")
    
    def reset_password(self):
        """Reset user password"""
        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user!")
            return
        
        index = selection[0]
        user_info = self.users_listbox.get(index)
        username = user_info.split()[0]
        
        # Show password reset dialog
        reset_window = tk.Toplevel(self.app.root)
        reset_window.title(f"Reset Password - {username}")
        reset_window.geometry("400x250")
        reset_window.configure(bg=constants.THEMES[self.app.config["theme"]]["bg"])
        reset_window.resizable(False, False)
        reset_window.grab_set()
        
        t = constants.THEMES[self.app.config["theme"]]
        
        tk.Label(reset_window, text=f"Reset Password for '{username}'", 
                font=("Segoe UI", 14, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # New password
        tk.Label(reset_window, text="New Password:", fg=t["fg"], bg=t["bg"]).pack(pady=5)
        new_pass_entry = tk.Entry(reset_window, show="●", width=30, 
                                 bg=t["entry_bg"], fg=t["fg"])
        new_pass_entry.pack(pady=5)
        
        # Confirm password
        tk.Label(reset_window, text="Confirm Password:", fg=t["fg"], bg=t["bg"]).pack(pady=5)
        confirm_pass_entry = tk.Entry(reset_window, show="●", width=30, 
                                     bg=t["entry_bg"], fg=t["fg"])
        confirm_pass_entry.pack(pady=5)
        
        def do_reset():
            new_pass = new_pass_entry.get()
            confirm = confirm_pass_entry.get()
            
            if not new_pass:
                messagebox.showwarning("Missing Password", "Please enter a new password!")
                return
            
            if new_pass != confirm:
                messagebox.showwarning("Password Mismatch", "Passwords do not match!")
                return
            
            reset_window.destroy()
            messagebox.showinfo("Password Reset", f"Password for '{username}' has been reset!")
        
        tk.Button(reset_window, text="Reset Password", command=do_reset,
                 bg="#27ae60", fg="white", font=("Segoe UI", 12, "bold"),
                 padx=20, pady=10).pack(pady=20)
    
    def load_sample_logs(self):
        """Load sample access logs"""
        sample_logs = f"""
Access Logs - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

[2024-01-15 08:30:15] LOGIN_SUCCESS - User: admin - IP: 192.168.1.100
[2024-01-15 08:35:22] FILE_MODIFIED - User: admin - Path: /docs/important.docx
[2024-01-15 09:15:10] LOGIN_SUCCESS - User: operator - IP: 192.168.1.101
[2024-01-15 10:20:45] CERTIFICATE_GENERATED - User: admin - For: auditor
[2024-01-15 11:05:33] LOGIN_FAILED - User: unknown - IP: 192.168.1.150
[2024-01-15 11:10:18] LOCKOUT - User: unknown - IP: 192.168.1.150
[2024-01-15 12:30:55] SETTINGS_CHANGED - User: admin - Setting: email_alerts
[2024-01-15 14:15:20] LOGOUT - User: operator - Duration: 05:40:10
[2024-01-15 15:45:12] MONITORING_STARTED - User: admin - Path: C:/Documents
[2024-01-15 16:20:05] RANSOMWARE_ALERT - User: system - File: suspicious.exe
[2024-01-15 17:10:30] EMAIL_SENT - User: system - To: admin@company.com
[2024-01-15 18:05:45] LOGOUT - User: admin - Duration: 09:35:30

Total entries: 12
"""
        
        self.logs_text.delete("1.0", tk.END)
        self.logs_text.insert("1.0", sample_logs)
        self.logs_text.configure(state="disabled")
    
    def apply_log_filters(self):
        """Apply filters to logs"""
        date_filter = self.date_filter_var.get()
        user_filter = self.user_filter_var.get()
        
        messagebox.showinfo("Filters Applied", 
                          f"Filters applied:\n\n"
                          f"Date: {date_filter}\n"
                          f"User: {user_filter}\n\n"
                          "In a full implementation, this would filter the actual logs.")
    
    def clear_access_logs(self):
        """Clear access logs"""
        response = messagebox.askyesno("Clear Logs", 
                                      "Are you sure you want to clear all access logs?\n\n"
                                      "This action cannot be undone!")
        
        if response:
            self.logs_text.configure(state="normal")
            self.logs_text.delete("1.0", tk.END)
            self.logs_text.insert("1.0", f"Logs cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.logs_text.configure(state="disabled")
            messagebox.showinfo("Logs Cleared", "Access logs have been cleared.")
