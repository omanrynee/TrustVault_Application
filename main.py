#!/usr/bin/env python3
# MIT License
# Copyright © 2026 Oman Ryne. All Rights Reserved.
"""
TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System - Main Entry Point
Entry point for the Secure File Integrity Monitoring System
Web Dashboard Integration Added
Docker Support Added
"""

import os
import sys
import time
import traceback
import platform
import subprocess
from datetime import datetime

# Check for Docker mode FIRST before any GUI imports
DOCKER_MODE = (
    "--docker" in sys.argv or 
    os.getenv("DOCKER_MODE") == "1" or
    os.getenv("DOCKER_CONTAINER") == "true"
)

# Only import tkinter if NOT in Docker mode
if not DOCKER_MODE:
    import tkinter as tk
    from tkinter import messagebox

def check_platform_compatibility():
    """Check if the platform is supported"""
    system = platform.system()
    
    if system == "Windows":
        return True, "Windows"
    elif system == "Linux":
        return True, "Linux"
    elif system == "Darwin":  # macOS
        return True, "macOS"
    else:
        return False, f"Unsupported platform: {system}"

def setup_environment():
    """Setup the application environment"""
    try:
        # Create necessary directories
        directories = [
            "logs",
            "CSV_logs", 
            "certs",
            "keys",
            "data",
            "backups",
            "temp"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            print(f"[OK] Created directory: {directory}")
        
        # Initialize default config files
        import json
        
        # Default configuration
        default_config = {
            "theme": "white",
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
            "last_user": "admin",
            "alert_popup_normal": False,
            "auto_save": True,
            "check_updates": True,
            "auto_clean_logs": True,
            "version": "3.0",
            "first_run": True,
            "install_date": None,
            "license_accepted": False,
            "debug_mode": False  # Added for web dashboard debugging
        }
        
        config_file = "data/config.json"
        if not os.path.exists(config_file):
            default_config["install_date"] = os.path.getctime(__file__) if os.path.exists(__file__) else None
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            print("[OK] Created default configuration")
        
        # Create other data files
        data_files = {
            "data/email_config.json": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender_email": "",
                "sender_password": "",
                "recipients": [],
                "alert_levels": {"CRITICAL": True, "WARNING": True, "INFO": False},
                "use_ssl": False,
                "timeout": 30,
                "test_mode": False
            },
            "data/file_hashes.json": {},
            "data/revoked.json": [],
            "logs/audit_log.json": [],
            "logs/system_log.json": []
        }
        
        for file_path, default_data in data_files.items():
            if not os.path.exists(file_path):
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w') as f:
                    json.dump(default_data, f, indent=2)
                print(f"[OK] Created file: {file_path}")
        
        return True, "Environment setup completed successfully"
        
    except Exception as e:
        return False, f"Failed to setup environment: {str(e)}"

def check_dependencies():
    """Check for required and optional packages"""
    required_packages = [
        "watchdog",      # File monitoring
        "cryptography",  # Encryption and certificates
        "matplotlib",    # Charts and graphs
    ]
    
    optional_packages = [
        "flask",         # Web dashboard (optional)
        "flask-socketio", # Real-time updates for web dashboard (optional)
        "flask-cors",    # CORS for web dashboard (optional)
        "tkcalendar",    # Calendar widget (optional)
        "requests",      # For update checks (optional)
    ]
    
    missing_required = []
    missing_optional = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing_required.append(package)
    
    for package in optional_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing_optional.append(package)
    
    return missing_required, missing_optional

def install_packages(packages):
    """Install packages using pip"""
    try:
        print(f"Installing packages: {', '.join(packages)}")
        
        for package in packages:
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    package, "--quiet", "--disable-pip-version-check"
                ])
                print(f"[OK] Successfully installed: {package}")
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to install: {package}")
                return False
        
        return True
    except Exception as e:
        print(f"Error during installation: {e}")
        return False

def check_python_version():
    """Check Python version compatibility"""
    import sys
    version = sys.version_info
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        return False, f"Python 3.8+ required (current: {version.major}.{version.minor}.{version.micro})"
    
    return True, f"Python {version.major}.{version.minor}.{version.micro}"

def show_splash_screen():
    """Show a splash screen while loading"""
    # This function is only called in GUI mode, so tkinter is safe here
    if DOCKER_MODE:
        return None, None

    from config import constants

    theme = constants.THEMES[constants.DEFAULT_THEME]
    bg = theme["bg"]
    fg = theme["fg"]
    
    splash = tk.Tk()
    splash.title("TrustVault")
    splash.geometry("600x400")
    splash.configure(bg=bg)
    splash.overrideredirect(True)  # Remove window decorations
    
    # Center the splash screen
    splash.update_idletasks()
    width = splash.winfo_width()
    height = splash.winfo_height()
    x = (splash.winfo_screenwidth() // 2) - (width // 2)
    y = (splash.winfo_screenheight() // 2) - (height // 2)
    splash.geometry(f"{width}x{height}+{x}+{y}")
    
    # Add content
    tk.Label(splash, text="🔐 TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System", 
             font=("Segoe UI", 32, "bold"),
             fg=fg, bg=bg).pack(pady=80)
    
    tk.Label(splash, text="Advanced File Integrity Monitoring System",
             font=("Segoe UI", 14),
             fg=fg, bg=bg).pack(pady=10)
    
    progress_frame = tk.Frame(splash, bg=bg)
    progress_frame.pack(pady=40)
    
    progress_label = tk.Label(progress_frame, text="Initializing...",
                             fg=fg, bg=bg,
                             font=("Segoe UI", 12))
    progress_label.pack()
    
    splash.update()
    return splash, progress_label

def check_license():
    """Check and prompt for license agreement"""
    license_file = "data/license_accepted.txt"
    
    # If license already accepted
    if os.path.exists(license_file):
        try:
            with open(license_file, 'r') as f:
                if f.read().strip() == "accepted":
                    return True
        except:
            pass
    
    # If in Docker mode, auto-accept for headless operation
    if DOCKER_MODE:
        print("[DOCKER] Auto-accepting license for headless operation")
        with open(license_file, 'w') as f:
            f.write("accepted")
        return True
    
    # Show license agreement (GUI mode only)
    license_text = """
    TRUSTVAULT - END USER LICENSE AGREEMENT
    
    This software is provided "as-is", without any express or implied warranty.
    In no event shall the authors be held liable for any damages arising from
    the use of this software.
    
    By using TrustVault, you agree to:
    
    1. Use the software only for legitimate security monitoring purposes.
    2. Not use the software for illegal activities.
    3. Respect privacy laws and regulations in your jurisdiction.
    4. Acknowledge that this is a security tool and use it responsibly.
    
    The software includes features for:
    - File integrity monitoring
    - Anomaly detection using machine learning
    - Ransomware detection
    - Email alerts
    - Web dashboard
    
    This software is for educational and professional use only.
    """
    
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    result = messagebox.askyesno(
        "License Agreement",
        f"{license_text}\n\nDo you accept the license agreement?",
        icon='question',
        default='no'
    )
    
    root.destroy()
    
    if result:
        with open(license_file, 'w') as f:
            f.write("accepted")
        return True
    
    return False

def check_for_updates():
    """Check for available updates"""
    try:
        import requests
        import json
        
        # Load current version from config
        config_file = "data/config.json"
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                current_version = config.get("version", "3.0")
        else:
            current_version = "3.0"
        
        # This would check against a remote version file
        # For now, just return current version
        return {
            "current": current_version,
            "latest": current_version,
            "update_available": False,
            "changelog": "Initial release"
        }
        
    except ImportError:
        # Requests not installed
        return None
    except Exception:
        # Network error or other issue
        return None

def cleanup_temp_files():
    """Clean up temporary files"""
    import glob
    import time
    
    try:
        temp_patterns = [
            "*.tmp",
            "*.temp",
            "*~",
            "*.swp",
            "*.bak",
            "temp/*"
        ]
        
        cleaned = 0
        current_time = time.time()
        
        for pattern in temp_patterns:
            for file in glob.glob(pattern, recursive=True):
                try:
                    # Delete files older than 1 hour
                    if os.path.getmtime(file) < current_time - 3600:
                        os.remove(file)
                        cleaned += 1
                except:
                    pass
        
        if cleaned > 0:
            print(f"[OK] Cleaned {cleaned} temporary files")
            
    except Exception as e:
        print(f"Note: Could not clean temp files: {e}")

def setup_web_dashboard(app):
    """Setup web dashboard if enabled in config"""
    try:
        if app.config.get("web_dashboard", False):
            print("[WEB] Setting up web dashboard...")
            
            # Check if Flask is available
            try:
                import flask
                print("[OK] Flask is installed")
            except ImportError:
                print("[WARN] Flask not installed. Web dashboard will be disabled.")
                app.config["web_dashboard"] = False
                return False
            
            # Import web dashboard server
            try:
                # Ensure gui module is in path
                import sys
                import os
                project_root = os.path.dirname(os.path.abspath(__file__))
                if project_root not in sys.path:
                    sys.path.insert(0, project_root)
                    print(f"[DEBUG] setup_web_dashboard: Added {project_root} to sys.path")
                
                from gui.webdashboard_server import WebDashboardServer
                
                port = app.config.get("dashboard_port", 5000)
                app.web_dashboard = WebDashboardServer(port=port, debug=app.config.get("debug_mode", False))
                
                # Start the dashboard
                success, url = app.web_dashboard.start()
                
                if success:
                    print(f"[OK] Web dashboard started at: {url}")
                    
                    # Add startup event
                    app.web_dashboard.add_event({
                        "event_type": "SYSTEM_START",
                        "severity": "info",
                        "message": "TrustVault application started",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    return True
                else:
                    print(f"[ERROR] Failed to start web dashboard: {url}")
                    return False
                    
            except ImportError as e:
                print(f"[ERROR] Web dashboard module not found: {e}")
                import traceback
                traceback.print_exc()
                return False
            except Exception as e:
                print(f"[ERROR] Error starting web dashboard: {e}")
                import traceback
                traceback.print_exc()
                return False
        else:
            print("[INFO] Web dashboard disabled in configuration")
            return False
            
    except Exception as e:
        print(f"[WARN] Error setting up web dashboard: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_docker_mode():
    """Run TrustVault in Docker headless mode"""
    print("[+] Running in Docker headless mode")
    
    # Ensure project root is in path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        print(f"[DOCKER] Added {project_root} to sys.path")
    
    try:
        # Import required modules
        from gui.webdashboard_server import WebDashboardServer
        from monitoring.observer import FileMonitor
        
        # Enable web dashboard by default in Docker
        dashboard = WebDashboardServer(port=5000, debug=True)
        success, url = dashboard.start()
        
        if success:
            print(f"[+] Web dashboard started at: {url}")
        else:
            print(f"[!] Failed to start web dashboard: {url}")
            # Continue without dashboard
        
        # Setup monitoring
        monitor_path = "/monitored"
        
        # Check if path exists, create if needed for Docker
        if not os.path.exists(monitor_path):
            print(f"[!] Monitor path {monitor_path} does not exist")
            print(f"[!] You need to mount a volume at {monitor_path}")
            print(f"[!] Example: docker run -v /host/path:/monitored securefim")
            
            # Create a test directory for demo
            test_path = os.path.join(project_root, "monitored")
            os.makedirs(test_path, exist_ok=True)
            monitor_path = test_path
            print(f"[!] Using test directory: {monitor_path}")
        
        print(f"[+] Monitoring path: {monitor_path}")
        
        # Create monitor instance with correct constructor signature
        monitor = FileMonitor(
            path=monitor_path,
            recursive=True,        # Enable recursive monitoring
            app=None,              # No GUI app in Docker mode
            config={}              # Use default configuration
        )
        
        # If dashboard is available, we need to connect it to the monitor
        # This depends on how FileMonitor is implemented - may need adjustment
        if success and hasattr(monitor, 'set_dashboard'):
            monitor.set_dashboard(dashboard)
        elif success:
            # Alternative: store dashboard reference for later use
            monitor.dashboard = dashboard
        
        # Start monitoring
        monitor.start()
        print("[+] File monitoring started")
        
        # Add startup event to dashboard
        if success:
            dashboard.add_event({
                "event_type": "DOCKER_START",
                "severity": "info",
                "message": f"TrustVault Docker container started. Monitoring: {monitor_path}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        print("[+] TrustVault is running in Docker mode")
        print("[+] Press Ctrl+C to stop")
        print("=" * 60)
        
        # Keep container alive
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] Stopping TrustVault...")
            if success:
                dashboard.add_event({
                    "event_type": "DOCKER_STOP",
                    "severity": "info",
                    "message": "TrustVault Docker container stopping",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                dashboard.stop()
            monitor.stop()
            print("[+] TrustVault stopped")
        
    except ImportError as e:
        print(f"[!] Error importing modules: {e}")
        print("[!] Make sure all dependencies are installed")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"[!] Error in Docker mode: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

def main():
    """Main entry point for TrustVault"""
    
    print("\n" + "="*60)
    print("[START] TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System - Starting up...")
    print("="*60 + "\n")
    
    # Print Docker mode status
    if DOCKER_MODE:
        print("[DOCKER] Docker mode detected")
        print("[DOCKER] Running in headless mode")
        return run_docker_mode()
    
    # Normal GUI mode - continue with existing setup
    print("[NORMAL] Running in normal GUI mode")
    
    # Check platform compatibility
    platform_ok, platform_info = check_platform_compatibility()
    if not platform_ok:
        print(f"[ERROR] {platform_info}")
        # Only use messagebox in GUI mode
        if not DOCKER_MODE:
            messagebox.showerror("Unsupported Platform", platform_info)
        return 1
    
    print(f"[OK] Platform: {platform_info}")
    
    # Check Python version
    python_ok, python_info = check_python_version()
    if not python_ok:
        print(f"[ERROR] {python_info}")
        if not DOCKER_MODE:
            messagebox.showerror("Python Version Error", python_info)
        return 1
    
    print(f"[OK] {python_info}")
    
    # Show splash screen
    splash, progress_label = show_splash_screen()
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Checking license agreement...")
        splash.update()
    
    # Check license
    if not check_license():
        print("[ERROR] License not accepted")
        if splash:
            splash.destroy()
        if not DOCKER_MODE:
            messagebox.showinfo("License Declined", 
                              "You must accept the license agreement to use TrustVault.")
        return 0
    
    print("[OK] License accepted")
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Setting up environment...")
        splash.update()
    
    # Setup environment
    env_ok, env_message = setup_environment()
    if not env_ok:
        print(f"[ERROR] {env_message}")
        if splash:
            splash.destroy()
        if not DOCKER_MODE:
            messagebox.showerror("Environment Error", env_message)
        return 1
    
    print("[OK] Environment setup complete")
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Checking dependencies...")
        splash.update()
    
    # Check dependencies
    missing_required, missing_optional = check_dependencies()
    
    if missing_required:
        print(f"[ERROR] Missing required packages: {', '.join(missing_required)}")
        
        if splash:
            splash.destroy()
        
        if not DOCKER_MODE:
            response = messagebox.askyesno(
                "Missing Dependencies",
                f"The following required packages are missing:\n\n"
                f"{', '.join(missing_required)}\n\n"
                "Would you like to install them automatically?\n\n"
                "Click Yes to install, No to exit."
            )
        else:
            response = False
            print("[DOCKER] Please install missing packages manually")
        
        if response:
            print("Installing missing packages...")
            if not install_packages(missing_required):
                if not DOCKER_MODE:
                    messagebox.showerror(
                        "Installation Failed",
                        "Failed to install required packages.\n\n"
                        "Please install manually:\n"
                        f"pip install {' '.join(missing_required)}"
                    )
                return 1
            print("[OK] Required packages installed")
            
            # Re-check after installation
            missing_required, missing_optional = check_dependencies()
            if missing_required:
                if not DOCKER_MODE:
                    messagebox.showerror(
                        "Installation Failed",
                        "Some packages could not be installed.\n\n"
                        "Please install manually:\n"
                        f"pip install {' '.join(missing_required)}"
                    )
                return 1
        else:
            print("[ERROR] User declined to install dependencies")
            return 0
    else:
        print("[OK] All required dependencies are installed")
    
    # Warn about optional packages
    if missing_optional:
        print(f"[WARN] Missing optional packages: {', '.join(missing_optional)}")
        # Offer to install optional packages
        if missing_optional and "flask" in missing_optional:
            print("[WARN] Flask is required for web dashboard. Install with: pip install flask flask-socketio flask-cors")
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Cleaning up temporary files...")
        splash.update()
    
    # Cleanup temp files
    cleanup_temp_files()
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Checking for updates...")
        splash.update()
    
    # Check for updates
    update_info = check_for_updates()
    if update_info and update_info.get("update_available", False):
        print(f"[WARN] Update available: {update_info['current']} -> {update_info['latest']}")
    
    # Update progress
    if splash and progress_label:
        progress_label.config(text="Starting application...")
        splash.update()
    
    # Close splash screen
    if splash:
        splash.destroy()
    
    try:
        # Import and start the application
        print("[OK] Starting TrustVault application...")
        
        # Add project root to path for imports
        project_root = os.path.dirname(os.path.abspath(__file__))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
            print(f"[DEBUG] main.py: Added {project_root} to sys.path")
        
        # Check if we're in the modular version
        if os.path.exists("gui/app.py"):
            from gui.app import FIMApp
            print("[OK] Loading modular version...")
            
            # Create the main Tkinter window
            root = tk.Tk()
            root.title("TrustVault - A PKI-Based Real-Time Cryptographic Monitoring System")
            
            # Set window size and position
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            window_width = 1400
            window_height = 900
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2
            root.geometry(f"{window_width}x{window_height}+{x}+{y}")
            root.minsize(1000, 600)
            
            # Create the app instance
            app = FIMApp(root)
            
            # Setup web dashboard AFTER app is created
            setup_web_dashboard(app)
            
            # Start the main event loop
            root.mainloop()
            
            print("\n" + "="*60)
            print("[OK] TrustVault started successfully!")
            print("="*60 + "\n")
            
            # Cleanup web dashboard on exit
            if hasattr(app, 'web_dashboard') and app.web_dashboard:
                print("[STOP] Stopping web dashboard...")
                app.web_dashboard.stop()
            
            return 0
        else:
            # Fallback to original version
            print("[WARN] Modular version not found, using fallback...")
            # We'll create a simple fallback app if needed
            if not DOCKER_MODE:
                messagebox.showinfo(
                    "Development Mode",
                    "Running in development mode. Some features may be limited."
                )
                
                # Create a simple fallback application
                root = tk.Tk()
                root.title("TrustVault - Development Mode")
                root.geometry("800x600")
                
                tk.Label(root, text="🔐 TrustVault", 
                        font=("Segoe UI", 24, "bold")).pack(pady=100)
                
                tk.Label(root, text="Running in development mode", 
                        font=("Segoe UI", 14)).pack(pady=20)
                
                tk.Label(root, text="Please ensure all modules are properly installed", 
                        font=("Segoe UI", 10)).pack(pady=10)
                
                def exit_app():
                    root.destroy()
                
                tk.Button(root, text="Exit", command=exit_app,
                         bg="#e74c3c", fg="white", font=("Segoe UI", 12),
                         padx=30, pady=10).pack(pady=50)
                
                root.mainloop()
            else:
                print("[DOCKER] No GUI available in Docker mode")
            return 0
        
    except ImportError as e:
        print(f"[ERROR] Import error: {e}")
        traceback.print_exc()
        
        if not DOCKER_MODE:
            messagebox.showerror(
                "Module Error",
                f"Failed to import required modules:\n\n{e}\n\n"
                "Please ensure all dependencies are installed:\n"
                "pip install watchdog cryptography matplotlib"
            )
        return 1
        
    except Exception as e:
        print(f"[ERROR] Error starting application: {e}")
        traceback.print_exc()
        
        # Create error log
        error_log = f"logs/error_{os.getpid()}.log"
        with open(error_log, 'w') as f:
            f.write(f"TrustVault Error Report\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Error: {str(e)}\n\n")
            f.write("Traceback:\n")
            f.write(traceback.format_exc())
        
        if not DOCKER_MODE:
            messagebox.showerror(
                "Application Error",
                f"Failed to start TrustVault:\n\n{str(e)}\n\n"
                f"Error details saved to: {error_log}\n\n"
                "Please check the log file for details."
            )
        return 1

if __name__ == "__main__":
    # Run the application
    exit_code = main()
    
    # Cleanup before exit
    if os.path.exists("temp"):
        try:
            import shutil
            shutil.rmtree("temp", ignore_errors=True)
        except:
            pass
    
    print(f"\nExit code: {exit_code}")
    sys.exit(exit_code)
