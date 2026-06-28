"""
Web dashboard tab for TrustVault
Location: V2/gui/tabs/web_dashboard_tab.py
"""

import sys
import os

# Add the project root to Python's path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))  # Go up twice: gui/tabs → gui → project_root
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import tkinter as tk
from tkinter import messagebox
import webbrowser

from config import constants
from gui.webdashboard_server import WebDashboardServer


class WebDashboardTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(
            parent,
            bg=constants.THEMES[app.config["theme"]]["bg"]
        )
        self.build_ui()
        self.update_dashboard_status()

    def build_ui(self):
        t = constants.THEMES[self.app.config["theme"]]

        main = tk.Frame(self.frame, bg=t["bg"])
        main.pack(fill="both", expand=True, padx=30, pady=20)

        tk.Label(
            main,
            text="🌐 Web Dashboard Server",
            font=("Segoe UI", 24, "bold"),
            fg=t["fg"],
            bg=t["bg"]
        ).pack(pady=30)

        status = tk.LabelFrame(
            main,
            text="Server Status",
            bg=t["bg"],
            fg=t["fg"],
            font=("Segoe UI", 16, "bold"),
            padx=25,
            pady=20
        )
        status.pack(fill="x", pady=20)

        self.status_label = tk.Label(
            status,
            text="⏹️ Stopped",
            fg="#e74c3c",
            bg=t["bg"],
            font=("Segoe UI", 12, "bold")
        )
        self.status_label.pack(anchor="w", pady=5)

        self.url_label = tk.Label(
            status,
            text="Not running",
            fg=t["fg"],
            bg=t["bg"],
            font=("Segoe UI", 11)
        )
        self.url_label.pack(anchor="w", pady=5)

        self.events_label = tk.Label(
            status,
            text="Events: 0",
            fg=t["select"],
            bg=t["bg"],
            font=("Segoe UI", 11, "bold")
        )
        self.events_label.pack(anchor="w", pady=5)

        controls = tk.Frame(main, bg=t["bg"])
        controls.pack(pady=30)

        self.start_btn = tk.Button(
            controls,
            text="▶️ Start",
            command=self.start_server,
            bg="#27ae60",
            fg="white",
            font=("Segoe UI", 13, "bold"),
            padx=30,
            pady=12
        )
        self.start_btn.pack(side="left", padx=10)

        self.open_btn = tk.Button(
            controls,
            text="🌐 Open",
            command=self.open_dashboard,
            bg="#3498db",
            fg="white",
            font=("Segoe UI", 13, "bold"),
            padx=30,
            pady=12,
            state="disabled"
        )
        self.open_btn.pack(side="left", padx=10)

        self.stop_btn = tk.Button(
            controls,
            text="⏹️ Stop",
            command=self.stop_server,
            bg="#e74c3c",
            fg="white",
            font=("Segoe UI", 13, "bold"),
            padx=30,
            pady=12,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=10)

    # -------------------------------------------------
    # SERVER CONTROL
    # -------------------------------------------------

    def start_server(self):
        base_port = int(self.app.config.get("dashboard_port", 5000))

        self.app.web_dashboard = WebDashboardServer(port=base_port)
        success, url = self.app.web_dashboard.start()

        if success:
            # 🔥 SYNC CONFIG WITH ACTUAL PORT
            self.app.config["dashboard_port"] = self.app.web_dashboard.port

            messagebox.showinfo(
                "Server Started",
                f"Dashboard running at:\n\n{url}\n\n"
                f"Port in use: {self.app.web_dashboard.port}"
            )
        else:
            messagebox.showerror("Server Error", url)

        self.update_dashboard_status()

    def stop_server(self):
        if not self.app.web_dashboard:
            return

        self.app.web_dashboard.stop()
        self.update_dashboard_status()

    def open_dashboard(self):
        if not self.app.web_dashboard or not self.app.web_dashboard.is_running:
            messagebox.showwarning("Not Running", "Server is not running.")
            return

        webbrowser.open(self.app.web_dashboard.get_url())

    # -------------------------------------------------
    # UI UPDATE LOOP
    # -------------------------------------------------

    def update_dashboard_status(self):
        if self.app.web_dashboard and self.app.web_dashboard.is_running:
            self.status_label.config(text="🟢 Running", fg="#27ae60")
            self.url_label.config(text=self.app.web_dashboard.get_url())
            self.events_label.config(
                text=f"Events: {self.app.web_dashboard.stats['total_events']}"
            )
            self.start_btn.config(state="disabled")
            self.open_btn.config(state="normal")
            self.stop_btn.config(state="normal")
        else:
            self.status_label.config(text="⏹️ Stopped", fg="#e74c3c")
            self.url_label.config(text="Not running")
            self.events_label.config(text="Events: 0")
            self.start_btn.config(state="normal")
            self.open_btn.config(state="disabled")
            self.stop_btn.config(state="disabled")

        self.frame.after(2000, self.update_dashboard_status)