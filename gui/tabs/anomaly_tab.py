"""
Anomaly Detection Tab for TrustVault
COMPLETELY FIXED VERSION
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from config import constants
import os
import time
import threading


class AnomalyTab:
    """ML-Based Anomaly Detection Tab for TrustVault"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.frame = tk.Frame(parent, bg=constants.THEMES[app.config["theme"]]["bg"])
        
        # UI components
        self.anomaly_stat_labels = {}
        self.threshold_var = None
        self.threshold_label = None
        self.pattern_text = None
        self.anomaly_history_text = None
        self.status_label = None
        
        # Update flag
        self.update_running = False
        
        # Initialize UI
        self.build_ui()
        
        # Start updates
        self.update_anomaly_stats()
    
    def build_ui(self):
        """Build the complete UI"""
        theme = constants.THEMES[self.app.config["theme"]]
        
        # Create scrollable container
        main_frame = tk.Frame(self.frame, bg=theme["bg"])
        main_frame.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(main_frame, bg=theme["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=theme["bg"])
        
        def on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        scrollable_frame.bind("<Configure>", on_configure)
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        
        # Build sections
        self._create_title(scrollable_frame, theme)
        self._create_status_bar(scrollable_frame, theme)
        self._create_statistics_section(scrollable_frame, theme)
        self._create_control_buttons(scrollable_frame, theme)
        self._create_threshold_control(scrollable_frame, theme)
        self._create_burst_detection_section(scrollable_frame, theme)
        self._create_anomaly_history_section(scrollable_frame, theme)
        self._create_pattern_section(scrollable_frame, theme)
        self._create_test_section(scrollable_frame, theme)
    
    def _create_title(self, parent, theme):
        """Create title"""
        tk.Label(
            parent,
            text="🔍 Anomaly Detection",
            font=("Segoe UI", 24, "bold"),
            fg=theme["fg"],
            bg=theme["bg"]
        ).pack(pady=(10, 20))
    
    def _create_status_bar(self, parent, theme):
        """Create status bar"""
        status_frame = tk.Frame(parent, bg=theme["bg"], relief="solid", bd=1)
        status_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        self.status_label = tk.Label(
            status_frame,
            text="🟢 Monitoring Active",
            fg="#2ecc71",
            bg=theme["bg"],
            font=("Segoe UI", 14, "bold"),
            pady=10
        )
        self.status_label.pack()
    
    def _create_statistics_section(self, parent, theme):
        """Create statistics section"""
        stats_frame = tk.LabelFrame(
            parent,
            text="📊 Real-Time Statistics",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 16, "bold"),
            padx=20,
            pady=20
        )
        stats_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        # Statistics grid
        stats_config = [
            [("📈 Current Rate", "current_rate", "events/min"), 
             ("📊 Baseline Rate", "baseline_rate", "events/min")],
            [("🎯 Z-Score", "z_score", "σ"), 
             ("📐 Std Dev", "stdev", "σ")],
            [("🔢 Total Events", "total_events", ""), 
             ("⏱️ Last Minute", "events_last_minute", "")],
            [("🎓 Learning Phase", "learning_phase", ""), 
             ("📊 Progress", "learning_progress", "%")],
            [("⚠️ Anomalies", "anomaly_count", ""), 
             ("💥 Bursts", "burst_detected", "")],
            [("📈 Peak Rate", "peak_rate", "events/min"), 
             ("🤖 ML Status", "ml_enabled", "")]
        ]
        
        for row_data in stats_config:
            row_frame = tk.Frame(stats_frame, bg=theme["bg"])
            row_frame.pack(fill="x", pady=5)
            
            for label_text, stat_key, unit in row_data:
                cell = tk.Frame(row_frame, bg=theme["bg"], padx=10)
                cell.pack(side="left", fill="x", expand=True)
                
                tk.Label(
                    cell,
                    text=label_text,
                    fg=theme["fg"],
                    bg=theme["bg"],
                    font=("Segoe UI", 11)
                ).pack(anchor="w")
                
                value_label = tk.Label(
                    cell,
                    text="0",
                    fg=theme["select"],
                    bg=theme["bg"],
                    font=("Segoe UI", 16, "bold")
                )
                value_label.pack(anchor="w")
                
                if unit:
                    tk.Label(
                        cell,
                        text=unit,
                        fg=theme["fg"],
                        bg=theme["bg"],
                        font=("Segoe UI", 9)
                    ).pack(anchor="w")
                
                self.anomaly_stat_labels[stat_key] = value_label
    
    def _create_control_buttons(self, parent, theme):
        """Create control buttons"""
        btn_frame = tk.Frame(parent, bg=theme["bg"])
        btn_frame.pack(pady=10)
        
        buttons = [
            ("🔄 Refresh", self.refresh_stats, theme["btn"], theme["btn_fg"]),
            ("🎓 Force Learning", self.force_learning, "#3498db", "white"),
            ("🗑️ Reset", self.reset_detector, "#e74c3c", "white")
        ]
        
        for text, cmd, bg, fg in buttons:
            tk.Button(
                btn_frame,
                text=text,
                command=cmd,
                bg=bg,
                fg=fg,
                font=("Segoe UI", 11, "bold"),
                padx=15,
                pady=8
            ).pack(side="left", padx=5)
    
    def _create_threshold_control(self, parent, theme):
        """Create threshold control"""
        threshold_frame = tk.LabelFrame(
            parent,
            text="🎯 Detection Threshold",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 14, "bold"),
            padx=20,
            pady=15
        )
        threshold_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        control_frame = tk.Frame(threshold_frame, bg=theme["bg"])
        control_frame.pack(fill="x")
        
        tk.Label(
            control_frame,
            text="Sensitivity:",
            fg=theme["fg"],
            bg=theme["bg"],
            font=("Segoe UI", 11)
        ).pack(side="left", padx=5)
        
        self.threshold_var = tk.DoubleVar(value=self.app.anomaly_detector.threshold)
        
        scale = tk.Scale(
            control_frame,
            from_=1.0,
            to=5.0,
            resolution=0.1,
            orient="horizontal",
            variable=self.threshold_var,
            command=self.update_threshold,
            bg=theme["entry_bg"],
            fg=theme["fg"],
            length=300,
            font=("Segoe UI", 9)
        )
        scale.pack(side="left", padx=10, fill="x", expand=True)
        
        self.threshold_label = tk.Label(
            control_frame,
            text=f"{self.app.anomaly_detector.threshold}σ",
            fg=theme["select"],
            bg=theme["bg"],
            font=("Segoe UI", 12, "bold")
        )
        self.threshold_label.pack(side="left", padx=10)
    
    def _create_burst_detection_section(self, parent, theme):
        """Create burst detection section"""
        burst_frame = tk.LabelFrame(
            parent,
            text="💥 Burst Detection",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 14, "bold"),
            padx=20,
            pady=15
        )
        burst_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        info_text = f"Detects {self.app.anomaly_detector.burst_threshold}+ events in {self.app.anomaly_detector.burst_window} seconds"
        
        tk.Label(
            burst_frame,
            text=info_text,
            fg=theme["fg"],
            bg=theme["bg"],
            font=("Segoe UI", 11)
        ).pack(pady=5)
        
        # Last burst info
        self.last_burst_label = tk.Label(
            burst_frame,
            text="Last burst: Never",
            fg=theme["fg"],
            bg=theme["bg"],
            font=("Segoe UI", 10)
        )
        self.last_burst_label.pack(pady=5)
    
    def _create_anomaly_history_section(self, parent, theme):
        """Create anomaly history section"""
        history_frame = tk.LabelFrame(
            parent,
            text="📜 Recent Anomalies",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 14, "bold"),
            padx=20,
            pady=15
        )
        history_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        # History text
        self.anomaly_history_text = tk.Text(
            history_frame,
            height=6,
            bg=theme["text_bg"],
            fg=theme["text_fg"],
            font=("Segoe UI", 10),
            wrap="word"
        )
        self.anomaly_history_text.pack(fill="x", pady=5)
        
        # Controls
        ctrl_frame = tk.Frame(history_frame, bg=theme["bg"])
        ctrl_frame.pack(fill="x", pady=5)
        
        tk.Button(
            ctrl_frame,
            text="🔄 Refresh",
            command=self.refresh_history,
            bg=theme["btn"],
            fg=theme["btn_fg"],
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=5)
        
        tk.Button(
            ctrl_frame,
            text="🗑️ Clear",
            command=self.clear_history,
            bg="#e74c3c",
            fg="white",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=5)
    
    def _create_pattern_section(self, parent, theme):
        """Create pattern detection section"""
        pattern_frame = tk.LabelFrame(
            parent,
            text="🔍 Detected Patterns",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 14, "bold"),
            padx=20,
            pady=15
        )
        pattern_frame.pack(fill="x", pady=(0, 20), padx=10)
        
        self.pattern_text = tk.Text(
            pattern_frame,
            height=4,
            bg=theme["text_bg"],
            fg=theme["text_fg"],
            font=("Segoe UI", 10),
            wrap="word"
        )
        self.pattern_text.pack(fill="x", pady=5)
        
        tk.Button(
            pattern_frame,
            text="🔄 Refresh",
            command=self.refresh_patterns,
            bg=theme["btn"],
            fg=theme["btn_fg"],
            font=("Segoe UI", 9, "bold")
        ).pack(pady=5)

    
    def _create_test_section(self, parent, theme):
        """Create test section"""
        test_frame = tk.LabelFrame(
            parent,
            text="🧪 Testing",
            bg=theme["bg"],
            fg=theme["fg"],
            font=("Segoe UI", 14, "bold"),
            padx=20,
            pady=15
        )
        test_frame.pack(fill="x", pady=(0, 40), padx=10)
        
        # Test burst button
        tk.Button(
            test_frame,
            text="💥 Test Burst (Create 13 Folders)",
            command=self.test_burst,
            bg="#f39c12",
            fg="white",
            font=("Segoe UI", 12, "bold"),
            padx=20,
            pady=10
        ).pack(pady=10)
        
        tk.Label(
            test_frame,
            text="This will create temporary folders to test burst detection",
            fg=theme["fg"],
            bg=theme["bg"],
            font=("Segoe UI", 9)
        ).pack()
    
    # ==================== METHODS ====================
    
    def refresh_stats(self):
        """Refresh statistics"""
        self.update_anomaly_stats()
    
    def refresh_history(self):
        """Refresh anomaly history"""
        self._update_anomaly_history()
    
    def refresh_patterns(self):
        """Refresh patterns"""
        self._update_patterns()
    
    def update_anomaly_stats(self):
        """Update statistics periodically"""
        if not hasattr(self, 'anomaly_stat_labels'):
            return
        
        try:
            stats = self.app.anomaly_detector.get_statistics()
            
            # Update labels
            for key, label in self.anomaly_stat_labels.items():
                value = stats.get(key, "N/A")
                if isinstance(value, bool):
                    text = "Yes" if value else "No"
                elif isinstance(value, float):
                    text = f"{value:.2f}"
                else:
                    text = str(value)
                label.config(text=text)
            
            # Update threshold label
            self.threshold_label.config(text=f"{self.app.anomaly_detector.threshold}σ")
            
            # Update status
            if stats.get('learning_phase', True):
                self.status_label.config(
                    text=f"📚 Learning Phase ({stats.get('learning_progress', 0)}%)",
                    fg="#f39c12"
                )
            else:
                self.status_label.config(
                    text="🟢 Monitoring Active",
                    fg="#2ecc71"
                )
            
            # Update last burst
            last_burst = stats.get('last_burst_time')
            if last_burst:
                self.last_burst_label.config(text=f"Last burst: {last_burst}")
            
            # Update history and patterns
            self._update_anomaly_history()
            self._update_patterns()
            
        except Exception as e:
            print(f"Error updating stats: {e}")
        
        # Schedule next update
        self.frame.after(2000, self.update_anomaly_stats)
    
    def _update_anomaly_history(self):
        """Update anomaly history display"""
        if not hasattr(self, 'anomaly_history_text'):
            return
        
        self.anomaly_history_text.config(state="normal")
        self.anomaly_history_text.delete("1.0", "end")
        
        try:
            history = self.app.anomaly_detector.get_anomaly_history(limit=10)
            
            if history:
                for anomaly in reversed(history):
                    source = anomaly.get('source', 'Unknown')
                    timestamp = anomaly.get('timestamp', '')
                    details = anomaly.get('details', {})
                    
                    icon = "💥" if source == "BURST" else "📊"
                    
                    line = f"{icon} [{timestamp}] {source}: "
                    if source == "BURST":
                        line += f"{details.get('burst_count', 0)} events in {details.get('burst_window', 5)}s\n"
                    else:
                        line += f"Rate {details.get('current_rate', 0)} (z={details.get('z_score', 0):.2f})\n"
                    
                    self.anomaly_history_text.insert("end", line)
            else:
                self.anomaly_history_text.insert("end", "No anomalies detected yet")
        
        except Exception as e:
            self.anomaly_history_text.insert("end", f"Error: {e}")
        
        self.anomaly_history_text.config(state="disabled")
    
    def _update_patterns(self):
        """Update patterns display"""
        if not hasattr(self, 'pattern_text'):
            return
        
        self.pattern_text.config(state="normal")
        self.pattern_text.delete("1.0", "end")
        
        try:
            patterns = self.app.anomaly_detector.get_detected_patterns(limit=5)
            
            if patterns:
                for pattern in patterns:
                    self.pattern_text.insert("end", 
                        f"🔍 {pattern.get('description', 'Unknown')}\n")
            else:
                self.pattern_text.insert("end", "No patterns detected")
        
        except Exception as e:
            self.pattern_text.insert("end", f"Error: {e}")
        
        self.pattern_text.config(state="disabled")
    
    def update_threshold(self, value):
        """Update threshold"""
        try:
            threshold = float(value)
            self.app.anomaly_detector.threshold = threshold
        except:
            pass
    
    def force_learning(self):
        """Force learning mode"""
        if messagebox.askyesno("Force Learning",
            "Reset detector and start learning phase?"):
            self.app.anomaly_detector.reset()
            messagebox.showinfo("Learning Started",
                "Learning phase started. Need 50 events to establish baseline.")
    
    def reset_detector(self):
        """Reset detector"""
        if messagebox.askyesno("Reset Detector",
            "Reset anomaly detector to initial state?"):
            self.app.anomaly_detector.reset()
            messagebox.showinfo("Reset Complete", "Detector reset successfully")
    
    def clear_history(self):
        """Clear anomaly history"""
        if messagebox.askyesno("Clear History", "Clear anomaly history?"):
            self.app.anomaly_detector.anomaly_history.clear()
            self._update_anomaly_history()

    
    def test_burst(self):
        """Test burst detection"""
        if messagebox.askyesno("Test Burst Detection",
            "This will create 13 temporary folders to test burst detection.\n\n"
            "Continue?"):
            
            import tempfile
            import shutil
            
            test_dir = tempfile.mkdtemp()
            print(f"📁 Test directory: {test_dir}")
            
            try:
                for i in range(1, 14):
                    folder = os.path.join(test_dir, f"test_folder_{i}")
                    os.makedirs(folder, exist_ok=True)
                    
                    # Trigger detection
                    self.app.anomaly_detector.detect({
                        'event_type': 'created',
                        'file_path': folder,
                        'is_directory': True
                    })
                    
                    print(f"   Created: folder {i}")
                    time.sleep(0.1)  # Small delay
                
                messagebox.showinfo("Test Complete",
                    "13 folders created!\n\n"
                    "Check for burst detection alert.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Test failed: {e}")
            finally:
                # Cleanup
                try:
                    shutil.rmtree(test_dir)
                    print(f"🧹 Cleaned up: {test_dir}")
                except:
                    pass