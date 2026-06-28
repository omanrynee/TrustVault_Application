# gui/tabs/dashboard_tab.py
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
import numpy as np
import psutil
import threading
import time
from datetime import datetime, timedelta
import json
import os

class DashboardTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.frame = self   # <-- Add this line
        self.chart_data = self.load_chart_data()
        self.setup_ui()
        self.start_updates()
    
    def load_chart_data(self):
        """Load saved chart data"""
        data_file = "data/dashboard_data.json"
        if os.path.exists(data_file):
            try:
                with open(data_file, 'r') as f:
                    return json.load(f)
            except:
                return self.default_chart_data()
        return self.default_chart_data()
    
    def default_chart_data(self):
        """Return default chart data"""
        return {
            "threat_level": "HIGH",
            "threat_value": 31000001,
            "ransomware_detected": 12,
            "tampering_detected": 29,
            "anomalies_detected": 18,
            "mass_changes": 41,
            "cpu_usage": [],
            "memory_usage": [],
            "network_activity": [],
            "alerts_today": 42
        }
    
    def setup_ui(self):
        """Setup the dashboard UI"""
        # Create main container with scrollbar
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas for scrolling
        canvas = tk.Canvas(main_container)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Header with refresh button
        header_frame = ttk.Frame(scrollable_frame)
        header_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(header_frame, text="Analytics Dashboard", 
                 font=("Segoe UI", 24, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Refresh Charts", 
                  command=self.refresh_charts,
                  style='Accent.TButton').pack(side=tk.RIGHT, padx=10)
        
        # Threat Level Display
        threat_frame = ttk.LabelFrame(scrollable_frame, text="Cyber Threat Level", padding=20)
        threat_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        threat_label = ttk.Label(threat_frame, 
                                text=f"CYBER: US${self.chart_data['threat_value']:,}",
                                font=("Segoe UI", 36, 'bold'),
                                foreground='#ff3333')
        threat_label.pack()
        
        # Charts Section
        charts_frame = ttk.Frame(scrollable_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Left charts (pie charts)
        left_charts = ttk.Frame(charts_frame)
        left_charts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Right charts (line graphs)
        right_charts = ttk.Frame(charts_frame)
        right_charts.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Create pie charts
        self.create_pie_charts(left_charts)
        
        # Create line graphs
        self.create_line_graphs(right_charts)
        
        # Security Alerts Section
        alerts_frame = ttk.LabelFrame(scrollable_frame, text="Security Alerts", padding=20)
        alerts_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Create alerts grid
        self.create_alerts_grid(alerts_frame)
        
        # System Metrics Section
        metrics_frame = ttk.LabelFrame(scrollable_frame, text="System Metrics", padding=20)
        metrics_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Create metrics display
        self.create_metrics_display(metrics_frame)
    
    def create_pie_charts(self, parent):
        """Create pie charts for security data"""
        # First pie chart - Security Incidents
        fig1, ax1 = plt.subplots(figsize=(5, 4))
        
        labels = ['Ransomware', 'Tampering', 'Anomaly', 'Mass Changes']
        sizes = [
            self.chart_data['ransomware_detected'],
            self.chart_data['tampering_detected'],
            self.chart_data['anomalies_detected'],
            self.chart_data['mass_changes']
        ]
        colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
        
        wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors,
                                          autopct='%1.1f%%', startangle=90)
        
        ax1.axis('equal')
        ax1.set_title('Security Incidents Distribution')
        
        # Embed in tkinter
        canvas1 = FigureCanvasTkAgg(fig1, parent)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Second pie chart - Anomaly Detection Rate
        fig2, ax2 = plt.subplots(figsize=(5, 4))
        
        detected = 85
        missed = 15
        
        ax2.pie([detected, missed], labels=['Detected', 'Missed'],
               colors=['#2ecc71', '#e74c3c'], autopct='%1.1f%%')
        
        ax2.axis('equal')
        ax2.set_title('Anomaly Detection Rate')
        
        canvas2 = FigureCanvasTkAgg(fig2, parent)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_line_graphs(self, parent):
        """Create line graphs for real-time data"""
        # Create figure with subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(8, 6))
        
        # Generate sample data
        time_points = list(range(24))
        cpu_data = [np.random.randint(20, 80) for _ in range(24)]
        memory_data = [np.random.randint(30, 90) for _ in range(24)]
        network_data = [np.random.randint(10, 100) for _ in range(24)]
        alert_data = [np.random.randint(0, 20) for _ in range(24)]
        
        # Plot CPU Usage
        ax1.plot(time_points, cpu_data, color='#3498db', linewidth=2)
        ax1.fill_between(time_points, 0, cpu_data, alpha=0.3, color='#3498db')
        ax1.set_title('CPU Usage (%)')
        ax1.grid(True, alpha=0.3)
        
        # Plot Memory Usage
        ax2.plot(time_points, memory_data, color='#9b59b6', linewidth=2)
        ax2.fill_between(time_points, 0, memory_data, alpha=0.3, color='#9b59b6')
        ax2.set_title('Memory Usage (%)')
        ax2.grid(True, alpha=0.3)
        
        # Plot Network Activity
        ax3.plot(time_points, network_data, color='#2ecc71', linewidth=2)
        ax3.fill_between(time_points, 0, network_data, alpha=0.3, color='#2ecc71')
        ax3.set_title('Network Activity (MB)')
        ax3.grid(True, alpha=0.3)
        
        # Plot Alerts
        ax4.plot(time_points, alert_data, color='#e74c3c', linewidth=2)
        ax4.fill_between(time_points, 0, alert_data, alpha=0.3, color='#e74c3c')
        ax4.set_title('Security Alerts (per hour)')
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_alerts_grid(self, parent):
        """Create grid of security alerts"""
        # Define alert types and their counts
        alert_types = [
            ("Ransomware", self.chart_data['ransomware_detected'], "#e74c3c"),
            ("Tampering", self.chart_data['tampering_detected'], "#e67e22"),
            ("Anomaly", self.chart_data['anomalies_detected'], "#f1c40f"),
            ("Mass Changes", self.chart_data['mass_changes'], "#2ecc71"),
        ]
        
        # Create grid of alert cards
        grid_frame = ttk.Frame(parent)
        grid_frame.pack(fill=tk.BOTH, expand=True)
        
        for i, (alert_name, count, color) in enumerate(alert_types):
            card = ttk.Frame(grid_frame, relief='solid', borderwidth=1)
            card.grid(row=i//2, column=i%2, padx=10, pady=10, sticky='nsew')
            
            # Configure grid
            grid_frame.grid_columnconfigure(i%2, weight=1)
            grid_frame.grid_rowconfigure(i//2, weight=1)
            
            # Alert icon and name
            icon_label = ttk.Label(card, text="⚠️", font=("Segoe UI", 24))
            icon_label.pack(pady=(10, 5))
            
            name_label = ttk.Label(card, text=alert_name, font=("Segoe UI", 12, 'bold'))
            name_label.pack()
            
            count_label = ttk.Label(card, text=f"Count: {count}", 
                                   font=("Segoe UI", 14, 'bold'),
                                   foreground=color)
            count_label.pack(pady=(5, 10))
    
    def create_metrics_display(self, parent):
        """Create real-time system metrics display"""
        metrics_frame = ttk.Frame(parent)
        metrics_frame.pack(fill=tk.BOTH, expand=True)
        
        # Define metrics
        metrics = [
            ("CPU Usage", f"{psutil.cpu_percent()}%", "#3498db"),
            ("Memory Usage", f"{psutil.virtual_memory().percent}%", "#9b59b6"),
            ("Disk Usage", f"{psutil.disk_usage('/').percent}%", "#2ecc71"),
            ("Network I/O", "Active", "#e74c3c"),
            ("Processes", f"{len(psutil.pids())}", "#f39c12"),
            ("Uptime", self.get_system_uptime(), "#1abc9c"),
        ]
        
        # Create metrics grid
        for i, (metric_name, value, color) in enumerate(metrics):
            metric_frame = ttk.Frame(metrics_frame, relief='solid', borderwidth=1)
            metric_frame.grid(row=i//3, column=i%3, padx=5, pady=5, sticky='nsew')
            
            # Configure grid
            metrics_frame.grid_columnconfigure(i%3, weight=1)
            metrics_frame.grid_rowconfigure(i//3, weight=1)
            
            # Metric name
            name_label = ttk.Label(metric_frame, text=metric_name, 
                                  font=("Segoe UI", 10, 'bold'))
            name_label.pack(pady=(10, 5))
            
            # Metric value
            value_label = ttk.Label(metric_frame, text=value, 
                                   font=("Segoe UI", 14, 'bold'),
                                   foreground=color)
            value_label.pack(pady=(5, 10))
            
            # Store reference for updates
            if metric_name == "CPU Usage":
                self.cpu_label = value_label
            elif metric_name == "Memory Usage":
                self.memory_label = value_label
            elif metric_name == "Disk Usage":
                self.disk_label = value_label
    
    def get_system_uptime(self):
        """Get system uptime"""
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            uptime_str = str(timedelta(seconds=uptime_seconds)).split('.')[0]
            return uptime_str
        except:
            return "N/A"
    
    def refresh_charts(self):
        """Refresh all charts and data"""
        # Update chart data
        self.chart_data.update({
            "threat_value": np.random.randint(25000000, 40000000),
            "ransomware_detected": np.random.randint(5, 20),
            "tampering_detected": np.random.randint(20, 40),
            "anomalies_detected": np.random.randint(10, 30),
            "mass_changes": np.random.randint(30, 50),
        })
        
        # Save updated data
        self.save_chart_data()
        
        # Show refresh message
        print("✓ Charts refreshed")
        
        # In a real implementation, you would redraw the charts here
        # For now, just update the labels
        self.update_metrics()
    
    def save_chart_data(self):
        """Save chart data to file"""
        try:
            os.makedirs("data", exist_ok=True)
            with open("data/dashboard_data.json", 'w') as f:
                json.dump(self.chart_data, f, indent=2)
        except Exception as e:
            print(f"Error saving chart data: {e}")
    
    def update_metrics(self):
        """Update system metrics"""
        try:
            if hasattr(self, 'cpu_label'):
                self.cpu_label.config(text=f"{psutil.cpu_percent()}%")
            
            if hasattr(self, 'memory_label'):
                self.memory_label.config(text=f"{psutil.virtual_memory().percent}%")
            
            if hasattr(self, 'disk_label'):
                self.disk_label.config(text=f"{psutil.disk_usage('/').percent}%")
        except:
            pass
    
    def start_updates(self):
        """Start periodic updates"""
        def update_loop():
            while True:
                try:
                    self.update_metrics()
                    time.sleep(5)  # Update every 5 seconds
                except:
                    break
        
        # Start update thread
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()