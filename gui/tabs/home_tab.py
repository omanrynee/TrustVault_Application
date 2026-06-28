"""
Home tab for TrustVault - Clean design with scrolling text animation
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
import os
from config import constants

class HomeTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        self.build_ui()
        self.start_animations()
    
    def build_ui(self):
        """Build clean home tab UI with scrolling news-style animation"""
        t = constants.THEMES[self.app.config["theme"]]
        
        # Main container
        main_container = tk.Frame(self.frame, bg=t["bg"])
        main_container.pack(fill="both", expand=True)
        
        # ==================== TOP SECTION ====================
        top_section = tk.Frame(main_container, bg=t["bg"])
        top_section.pack(fill="x", pady=(40, 20))
        
        # Title with gradient effect
        tk.Label(top_section, text="TrustVault", 
                font=("Segoe UI", 38, "bold"), fg="#3498db", bg=t["bg"]).pack()
        
        tk.Label(top_section, text="A PKI-Based Real-Time Cryptographic Monitoring System", 
                font=("Segoe UI", 16), fg="#95a5a6", bg=t["bg"]).pack()
        
        # Subtitle
        tk.Label(top_section, text="Real-Time Cryptographic Monitoring",
                font=("Segoe UI", 12), fg="#7f8c8d", bg=t["bg"]).pack(pady=(5, 0))
        
        # ==================== CENTER SCROLLING TEXT SECTION ====================
        center_section = tk.Frame(main_container, bg=t["bg"])
        center_section.pack(fill="both", expand=True, pady=(60, 20))
        
        # Scrolling text container (news ticker style)
        ticker_container = tk.Frame(center_section, bg="#000000", height=80, 
                                   relief="flat", bd=2)
        ticker_container.pack(fill="x", padx=50)
        ticker_container.pack_propagate(False)
        
        # ==================== FEATURES CARDS ====================
        features_frame = tk.Frame(main_container, bg=t["bg"])
        features_frame.pack(fill="x", padx=50, pady=(30, 40))
        
        features = [
            ("🔒", "Real-time Monitoring", "24/7 file protection"),
            ("🔐", "PKI Encryption", "Military-grade security"),
            ("⚡", "Instant Alerts", "Immediate notifications"),
            ("📊", "Web Dashboard", "Monitor anywhere")
        ]
        
        for icon, title, desc in features:
            card = tk.Frame(features_frame, bg="#ecf0f1" if t["bg"] == "#ffffff" else "#34495e", 
                          relief="flat", bd=0)
            card.pack(side="left", fill="both", expand=True, padx=5)
            
            tk.Label(card, text=icon, font=("Segoe UI", 24), 
                    bg=card["bg"], fg=t["fg"]).pack(pady=(15, 5))
            
            tk.Label(card, text=title, font=("Segoe UI", 11, "bold"), 
                    bg=card["bg"], fg=t["fg"]).pack()
            
            tk.Label(card, text=desc, font=("Segoe UI", 9), 
                    bg=card["bg"], fg="#7f8c8d").pack(pady=(0, 15))
        
        # Animation canvas
        self.ticker_canvas = tk.Canvas(ticker_container, bg="#000000", 
                                      highlightthickness=0)
        self.ticker_canvas.pack(fill="both", expand=True)
        
        # Scrolling text
        self.ticker_text = "BUILT BY OMAN RYNE  -  TRUSTVAULT  -  A PKI-BASED REAL-TIME CRYPTOGRAPHIC MONITORING SYSTEM  -  REAL-TIME PROTECTION  -  PKI ENCRYPTION  -  ADVANCED CYBERSECURITY PLATFORM  -  "
        
        # Animation properties
        self.ticker_x = 0
        self.ticker_speed = 2
        self.animation_running = True
        
        # Create text object
        self.text_id = None
        
        # ==================== STATUS BAR ====================
        status_bar = tk.Frame(main_container, bg="#2c3e50", height=35)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        
        # Left: Monitoring status
        self.status_left = tk.Label(status_bar, 
                                   text="● System Ready",
                                   font=("Segoe UI", 10), 
                                   fg="#2ecc71", bg="#2c3e50")
        self.status_left.pack(side="left", padx=20)
        
        # Center: Stats
        self.status_center = tk.Label(status_bar, 
                                     text="",
                                     font=("Segoe UI", 10), 
                                     fg="#ecf0f1", bg="#2c3e50")
        self.status_center.pack(side="left", expand=True)
        
        # Right: Time
        self.time_label = tk.Label(status_bar, 
                                  text=datetime.now().strftime("%H:%M:%S"),
                                  font=("Segoe UI", 10, "bold"), 
                                  fg="#ecf0f1", bg="#2c3e50")
        self.time_label.pack(side="right", padx=20)
        
        # Start updates
        self.update_time()
        self.update_monitoring_status()
    
    def start_animations(self):
        """Start all animations"""
        self.frame.after(100, self.animate_ticker)
    
    def animate_ticker(self):
        """Animate scrolling text like news channel headline"""
        if not self.animation_running:
            return
        
        # Get canvas dimensions
        canvas_width = self.ticker_canvas.winfo_width()
        canvas_height = self.ticker_canvas.winfo_height()
        
        if canvas_width < 10:  # Canvas not ready
            self.frame.after(50, self.animate_ticker)
            return
        
        # Initialize text if needed
        if self.text_id is None:
            self.ticker_x = canvas_width
            center_y = canvas_height // 2
            self.text_id = self.ticker_canvas.create_text(
                self.ticker_x, center_y,
                text=self.ticker_text,
                font=("Segoe UI", 18, "bold"),
                fill="#00FF00",  # News channel green
                anchor="w"
            )
        
        # Move text to the left
        self.ticker_x -= self.ticker_speed
        
        # Update position
        center_y = canvas_height // 2
        self.ticker_canvas.coords(self.text_id, self.ticker_x, center_y)
        
        # Get text bounding box
        bbox = self.ticker_canvas.bbox(self.text_id)
        
        if bbox:
            text_width = bbox[2] - bbox[0]
            
            # If text has completely scrolled off the left side
            if self.ticker_x + text_width < 0:
                # Reset to right side for continuous loop
                self.ticker_x = canvas_width + 10
        
        # Schedule next frame (smooth 60fps-like animation)
        self.frame.after(20, self.animate_ticker)
    
    def update_time(self):
        """Update the time display"""
        current_time = datetime.now()
        self.time_label.config(text=current_time.strftime("%H:%M:%S"))
        self.frame.after(1000, self.update_time)
    
    def update_monitoring_status(self):
        """Update monitoring status display"""
        try:
            # Get system stats
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Left status (monitoring)
            if hasattr(self.app, 'monitoring') and self.app.monitoring:
                folder_name = "Active"
                if self.app.monitored_path:
                    folder_name = os.path.basename(self.app.monitored_path)
                    if len(folder_name) > 12:
                        folder_name = folder_name[:12] + "..."
                
                self.status_left.config(text=f"● Monitoring: {folder_name}", fg="#2ecc71")
            else:
                self.status_left.config(text="● System Ready", fg="#95a5a6")
            
            # Center status (system resources)
            cpu_color = "#2ecc71" if cpu_percent < 60 else "#f39c12" if cpu_percent < 80 else "#e74c3c"
            mem_color = "#2ecc71" if memory.percent < 60 else "#f39c12" if memory.percent < 80 else "#e74c3c"
            
            self.status_center.config(text=f"CPU: {cpu_percent:.1f}%  |  RAM: {memory.percent:.1f}%")
            
        except ImportError:
            # psutil not available
            if hasattr(self.app, 'monitoring') and self.app.monitoring:
                self.status_left.config(text="● Monitoring Active", fg="#2ecc71")
            else:
                self.status_left.config(text="● System Ready", fg="#95a5a6")
            
            self.status_center.config(text="")
        
        # Schedule next update
        self.frame.after(2000, self.update_monitoring_status)
    
    def update_home_stats(self):
        """Update home statistics (called from app refresh)"""
        self.update_monitoring_status()
    
    def stop_animations(self):
        """Stop all animations (call when tab is hidden)"""
        self.animation_running = False
    
    def resume_animations(self):
        """Resume animations (call when tab is shown)"""
        if not self.animation_running:
            self.animation_running = True
            self.animate_ticker()
