"""
Central Alert Manager for TrustVault.
Manages Toast Notifications and background email dispatch.
"""

import os
import ctypes
import threading
import tkinter as tk
from datetime import datetime
from typing import Dict, Optional

# Win32 rounding utility
def round_window(window, width, height, radius=16):
    if os.name == "nt":
        try:
            window.update_idletasks()
            hwnd = window.winfo_id()
            rgn = ctypes.windll.gdi32.CreateRoundRectRgn(0, 0, width, height, radius, radius)
            ctypes.windll.user32.SetWindowRgn(hwnd, rgn, True)
        except Exception as e:
            print(f"[AlertManager] Error rounding window: {e}")

class ToastNotification(tk.Toplevel):
    def __init__(self, parent, title: str, message: str, color_type: str = "info", duration_ms: int = 6000):
        super().__init__(parent)
        self.title_str = title
        self.message_str = message
        self.color_type = color_type.lower()
        self.duration_ms = duration_ms
        self.target_x = 0
        self.target_y = 0
        self.width = 340
        self.height = 75

        # Colors corresponding to severity levels
        # Blue: Info, Green: Success, Yellow: Warning, Red: Critical/Error
        colors = {
            "info": "#3b82f6",      # Blue
            "success": "#22c55e",   # Green
            "warning": "#f59e0b",   # Yellow
            "critical": "#ef4444",  # Red
            "error": "#ef4444",     # Red
            "danger": "#ef4444"
        }
        self.accent_color = colors.get(self.color_type, "#3b82f6")
        self.bg_color = "#0f172a"      # TrustVault UI panel bg
        self.text_color = "#e5f3ff"    # TrustVault UI text
        self.muted_color = "#8ea4b8"   # TrustVault UI muted text

        # Configure Tkinter window parameters
        self.overrideredirect(True)
        self.attributes("-alpha", 0.0)
        self.attributes("-topmost", True)
        self.configure(bg=self.bg_color)

        # Build card UI
        # Color bar on the left indicating severity
        self.accent_bar = tk.Frame(self, bg=self.accent_color, width=6)
        self.accent_bar.pack(side="left", fill="y")

        # Content area
        self.content_frame = tk.Frame(self, bg=self.bg_color, padx=12, pady=10)
        self.content_frame.pack(side="left", fill="both", expand=True)

        self.title_label = tk.Label(
            self.content_frame, text=self.title_str, fg=self.text_color, bg=self.bg_color,
            font=("Segoe UI", 10, "bold"), anchor="w", justify="left"
        )
        self.title_label.pack(fill="x", anchor="w")

        self.msg_label = tk.Label(
            self.content_frame, text=self.message_str, fg=self.muted_color, bg=self.bg_color,
            font=("Segoe UI", 9), anchor="w", justify="left", wrap=260
        )
        self.msg_label.pack(fill="x", anchor="w", pady=(2, 0))

        # Close button on the right
        self.close_btn = tk.Label(self, text="×", fg=self.muted_color, bg=self.bg_color,
                                  font=("Segoe UI", 16), cursor="hand2")
        self.close_btn.pack(side="right", fill="y", padx=(0, 12))
        self.close_btn.bind("<Button-1>", lambda e: self.fade_out())

        # Close button hover effects
        self.close_btn.bind("<Enter>", lambda e: self.close_btn.configure(fg=self.text_color))
        self.close_btn.bind("<Leave>", lambda e: self.close_btn.configure(fg=self.muted_color))

    def slide_to(self, target_x: int, target_y: int):
        self.target_x = target_x
        self.target_y = target_y
        self._animate_slide()

    def _animate_slide(self):
        try:
            geom = self.geometry()
            parts = geom.split('+')
            if len(parts) >= 3:
                curr_x = int(parts[1])
                curr_y = int(parts[2])
            else:
                curr_x, curr_y = self.target_x, self.target_y

            dx = self.target_x - curr_x
            dy = self.target_y - curr_y

            # Adjust Y coordinate dynamically for smooth transitions
            step_y = int(dy * 0.25)
            if abs(step_y) < 1 and dy != 0:
                step_y = 1 if dy > 0 else -1

            new_y = curr_y + step_y

            if abs(dy) <= 1:
                self.geometry(f"{self.width}x{self.height}+{self.target_x}+{self.target_y}")
                round_window(self, self.width, self.height)
            else:
                self.geometry(f"{self.width}x{self.height}+{self.target_x}+{new_y}")
                round_window(self, self.width, self.height)
                self.after(12, self._animate_slide)
        except Exception:
            try:
                self.geometry(f"{self.width}x{self.height}+{self.target_x}+{self.target_y}")
                round_window(self, self.width, self.height)
            except:
                pass

    def fade_in(self):
        self.geometry(f"{self.width}x{self.height}+{self.target_x}+{self.target_y + 20}")
        self._fade_step(0.0, 0.95, 0.08, True)

    def fade_out(self):
        self._fade_step(self.attributes("-alpha"), 0.0, -0.08, False)

    def _fade_step(self, current: float, target: float, step: float, is_in: bool):
        try:
            new_alpha = current + step
            if (is_in and new_alpha >= target) or (not is_in and new_alpha <= target):
                self.attributes("-alpha", target)
                if not is_in:
                    self.destroy()
            else:
                self.attributes("-alpha", new_alpha)
                if is_in:
                    # Move upwards slightly during fade in
                    geom = self.geometry()
                    parts = geom.split('+')
                    if len(parts) >= 3:
                        x = int(parts[1])
                        y = int(parts[2])
                        dy = self.target_y - y
                        new_y = y + int(dy * 0.25)
                        self.geometry(f"{self.width}x{self.height}+{x}+{new_y}")
                        round_window(self, self.width, self.height)
                self.after(16, lambda: self._fade_step(new_alpha, target, step, is_in))
        except:
            pass

class ToastNotificationManager:
    def __init__(self, root):
        self.root = root
        self.active_toasts = []
        self.spacing = 10
        self.margin_x = 20
        self.margin_y = 65
        self.toast_width = 340
        self.toast_height = 75

    def show_toast(self, title: str, message: str, color_type: str = "info"):
        try:
            self.root.after(0, lambda: self._create_toast(title, message, color_type))
        except Exception as e:
            print(f"[AlertManager] Error creating toast: {e}")

    def _create_toast(self, title: str, message: str, color_type: str):
        toast = ToastNotification(self.root, title, message, color_type)
        self.active_toasts.append(toast)

        # Place toast at target coordinates
        self.reposition_toasts()
        toast.fade_in()

        # Schedule auto close
        self.root.after(6000, lambda: self._fade_out_toast(toast))

    def _fade_out_toast(self, toast):
        if toast in self.active_toasts:
            toast.fade_out()
            self.root.after(300, lambda: self.remove_toast(toast))

    def remove_toast(self, toast):
        if toast in self.active_toasts:
            self.active_toasts.remove(toast)
            try:
                toast.destroy()
            except:
                pass
            self.reposition_toasts()

    def reposition_toasts(self):
        try:
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
        except:
            return

        for i, toast in enumerate(self.active_toasts):
            x = screen_width - self.toast_width - self.margin_x
            y = screen_height - self.margin_y - (i + 1) * (self.toast_height + self.spacing)
            toast.slide_to(x, y)

class AlertManager:
    _app = None
    _toast_manager = None

    @classmethod
    def register_app(cls, app):
        cls._app = app
        if app and hasattr(app, "root") and app.root:
            cls._toast_manager = ToastNotificationManager(app.root)

    @classmethod
    def show_info(cls, title: str, message: str = ""):
        print(f"[INFO ALERT] {title}: {message}")
        if cls._toast_manager:
            cls._toast_manager.show_toast(title, message, "info")

    @classmethod
    def show_success(cls, title: str, message: str = ""):
        print(f"[SUCCESS ALERT] {title}: {message}")
        if cls._toast_manager:
            cls._toast_manager.show_toast(title, message, "success")

    @classmethod
    def show_warning(cls, title: str, message: str = ""):
        print(f"[WARNING ALERT] {title}: {message}")
        if cls._toast_manager:
            cls._toast_manager.show_toast(title, message, "warning")

    @classmethod
    def show_error(cls, title: str, message: str = ""):
        print(f"[CRITICAL/ERROR ALERT] {title}: {message}")
        if cls._toast_manager:
            cls._toast_manager.show_toast(title, message, "error")

    @classmethod
    def send_email_alert(cls, subject: str, message: str, level: str = "INFO"):
        """Sends email alert in a background thread to prevent UI freezing"""
        threading.Thread(target=cls._async_send_email, args=(subject, message, level), daemon=True).start()

    @classmethod
    def _async_send_email(cls, subject: str, message: str, level: str):
        try:
            email_sys = None
            if cls._app and hasattr(cls._app, "email_system") and cls._app.email_system:
                email_sys = cls._app.email_system
            else:
                from communication.email_system import EmailAlertSystem
                email_sys = EmailAlertSystem()

            if email_sys and email_sys.enabled:
                success, err_msg = email_sys.send_alert(subject, message, level)
                if not success:
                    cls.show_error("Email Delivery Failed", f"Failed to send email alert: {err_msg}")
                else:
                    cls.show_success("Email Sent Successfully", f"Email alert sent: {subject}")
            else:
                # If disabled, do not attempt sending
                pass
        except Exception as e:
            cls.show_error("Email Delivery Failed", f"SMTP Exception: {str(e)}")
            # Log SMTP exceptions
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "smtp_exceptions.log"), "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} - Error: {str(e)}\n")

    # --- Standard Event Mappings ---

    @classmethod
    def file_created(cls, path: str):
        title = "File Created"
        msg = f"File created: {os.path.basename(path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"File Path: {path}", level="INFO")

    @classmethod
    def file_modified(cls, path: str):
        title = "File Modified"
        msg = f"File modified: {os.path.basename(path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"File Path: {path}", level="INFO")

    @classmethod
    def file_deleted(cls, path: str):
        title = "File Deleted"
        msg = f"File deleted: {os.path.basename(path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"File Path: {path}", level="INFO")

    @classmethod
    def file_renamed(cls, old_path: str, new_path: str):
        title = "File Renamed"
        msg = f"File renamed: {os.path.basename(old_path)} -> {os.path.basename(new_path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"Old Path: {old_path}\nNew Path: {new_path}", level="INFO")

    @classmethod
    def integrity_violation(cls, path: str, details: str = ""):
        title = "Hash Verification Failed"
        msg = f"Integrity violation: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"File Path: {path}\nDetails: {details}", level="CRITICAL")

    @classmethod
    def hash_mismatch(cls, path: str, original_hash: str, current_hash: str):
        title = "Hash Verification Failed"
        msg = f"File Modified: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"File Path: {path}\nExpected Hash: {original_hash}\nCurrent Hash: {current_hash}", level="CRITICAL")

    @classmethod
    def monitoring_started(cls, path: str):
        title = "Monitoring Started"
        msg = f"Continuous FIM active on: {os.path.basename(path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"Monitored Directory: {path}", level="INFO")

    @classmethod
    def monitoring_stopped(cls, path: str):
        title = "Monitoring Stopped"
        msg = f"FIM stopped on: {os.path.basename(path)}"
        cls.show_info(title, msg)
        cls.send_email_alert(title, f"Monitored Directory: {path}", level="INFO")

    @classmethod
    def ransomware_detected(cls, path: str, pattern: str = ""):
        title = "Ransomware Detected"
        msg = f"Suspicious ransomware pattern: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"Ransomware activity detected!\nAffected File: {path}\nPattern Details: {pattern}", level="CRITICAL")

    @classmethod
    def anomaly_detected(cls, path: str, details: str = ""):
        title = "Anomaly Detected"
        msg = f"Anomalous activity on: {os.path.basename(path)}"
        cls.show_warning(title, msg)
        cls.send_email_alert(title, f"Anomaly details: {details}\nTarget: {path}", level="WARNING")

    @classmethod
    def certificate_generated(cls, username: str, cert_path: str):
        title = "Certificate Generated"
        msg = f"X.509 cert generated for user: {username}"
        cls.show_success(title, msg)
        cls.send_email_alert(title, f"User: {username}\nCertificate Path: {cert_path}", level="INFO")

    @classmethod
    def certificate_revoked(cls, username: str):
        title = "Certificate Revoked"
        msg = f"Cert revoked for user: {username}"
        cls.show_warning(title, msg)
        cls.send_email_alert(title, f"User: {username} certificate has been revoked.", level="WARNING")

    @classmethod
    def login_failed(cls, username: str, reason: str = ""):
        title = "Login Failed"
        msg = f"Failed certificate login attempt: {username}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"User: {username}\nReason: {reason}", level="CRITICAL")

    @classmethod
    def login_successful(cls, username: str):
        title = "Login Successful"
        msg = f"Certificate authentication success: {username}"
        cls.show_success(title, msg)
        cls.send_email_alert(title, f"User: {username} successfully logged in using certificate.", level="INFO")

    @classmethod
    def signature_verification_failed(cls, path: str, reason: str = ""):
        title = "Signature Verification Failed"
        msg = f"Verification failed: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"File: {path}\nReason: {reason}", level="CRITICAL")

    @classmethod
    def encryption_failed(cls, path: str, reason: str = ""):
        title = "Encryption Failed"
        msg = f"Asymmetric encryption failed: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"File: {path}\nReason: {reason}", level="CRITICAL")

    @classmethod
    def decryption_failed(cls, path: str, reason: str = ""):
        title = "Decryption Failed"
        msg = f"Hybrid decryption failed: {os.path.basename(path)}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"File/Envelope: {path}\nReason: {reason}", level="CRITICAL")

    @classmethod
    def replay_attack_blocked(cls, context: str, reason: str = ""):
        title = "Replay Attack Blocked"
        msg = f"Nonce reuse or expired timestamp blocked!"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"Context: {context}\nReason: {reason}", level="CRITICAL")

    @classmethod
    def critical_error(cls, message: str, details: str = ""):
        title = "Critical Application Error"
        msg = f"System Error: {message}"
        cls.show_error(title, msg)
        cls.send_email_alert(title, f"Error: {message}\nDetails: {details}", level="CRITICAL")
