#!/usr/bin/env python3
"""
TrustVault - Main Application Runner
File Integrity Monitoring System
"""

import os
import sys
import signal
import argparse
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.helpers import get_system_info, backup_data_files, cleanup_temp_files, rotate_logs, get_available_port
from config import constants
from monitoring.handler import EnhancedRealtimeHandler  # Changed from core.monitor
from gui.webdashboard_server import WebDashboardServer
from utils.logger import setup_logger

class SecureFIMRunner:
    def __init__(self):
        self.monitor = None
        self.dashboard_process = None
        self.logger = setup_logger('runner')
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def setup_environment(self):
        """Setup required directories and files"""
        self.logger.info("Setting up environment...")
        
        # Create necessary directories
        directories = [
            constants.LOG_DIR,
            constants.BACKUP_DIR,
            constants.DATA_DIR,
            'config'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Created directory: {directory}")
        
        # Create default config files if they don't exist
        self.create_default_configs()
        
        # Cleanup temporary files
        cleanup_temp_files()
        
        self.logger.info("Environment setup complete")
    
    def create_default_configs(self):
        """Create default configuration files if they don't exist"""
        configs = [
            {
                'path': constants.CONFIG_FILE,
                'default': {
                    'monitored_directories': ['/etc', '/var/www', '/home'],
                    'excluded_patterns': ['.log', '.tmp', '.cache'],
                    'scan_interval': 300,
                    'hash_algorithm': 'sha256',
                    'real_time_monitoring': True,
                    'max_file_size': 104857600  # 100MB
                }
            },
            {
                'path': constants.EMAIL_CONFIG_FILE,
                'default': {
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'sender_email': 'omanrynee@gmail.com',
                    'sender_password': 'ccjw kqmm fzre zqky',
                    'recipient_emails': ['omanrynee@gmail.com'],
                    'enable_ssl': True,
                    'send_alerts': False
                }
            },
            {
                'path': constants.HASH_DB_FILE,
                'default': {}
            },
            {
                'path': constants.REVOKED_FILE,
                'default': []
            }
        ]
        
        for config in configs:
            if not os.path.exists(config['path']):
                import json
                with open(config['path'], 'w') as f:
                    json.dump(config['default'], f, indent=2)
                self.logger.debug(f"Created default config: {config['path']}")
    
    def start_monitor(self, config_file=None, scan_only=False):
        """Start the file integrity monitor"""
        self.logger.info("Starting File Integrity Monitor...")
        
        # Create backup before starting
        backup_dir = backup_data_files()
        if backup_dir:
            self.logger.info(f"Backup created at: {backup_dir}")
        
        # Initialize monitor
        self.monitor = EnhancedRealtimeHandler(config_file=config_file)  # Changed here
        
        if scan_only:
            self.logger.info("Running one-time scan...")
            self.monitor.run_scan()  # Assuming EnhancedRealtimeHandler has run_scan method
            self.logger.info("One-time scan completed")
        else:
            self.logger.info("Starting continuous monitoring...")
            self.monitor.start()  # Assuming EnhancedRealtimeHandler has start method
            try:
                from alerts.alert_manager import AlertManager
                AlertManager.monitoring_started(self.monitor.monitored_path if hasattr(self.monitor, 'monitored_path') else "CLI Folder")
            except Exception as e:
                print(f"AlertManager error: {e}")
        
        return self.monitor
    
    def start_dashboard(self, port=None, host='0.0.0.0', debug=False):
        """Start the web dashboard"""
        self.logger.info("Starting Web Dashboard...")
        
        if not port:
            port = get_available_port(5000)
        
        self.logger.info(f"Dashboard will be available at: http://{host}:{port}")
        self.logger.info("Press Ctrl+C to stop the dashboard")
        
        dashboard = WebDashboardServer(port=port, debug=debug)
        success, url = dashboard.start()
        if not success:
            raise RuntimeError(url)

        self.logger.info(f"Dashboard started at: {url}")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            dashboard.stop()
    
    def start_all(self, config_file=None, dashboard=True, dashboard_port=None):
        """Start both monitor and dashboard"""
        self.setup_environment()
        
        # Start monitor in a separate thread/process
        import threading
        monitor_thread = threading.Thread(
            target=self.start_monitor,
            args=(config_file, False)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        if dashboard:
            # Start dashboard (this will block)
            self.start_dashboard(port=dashboard_port)
        else:
            # Keep main thread alive
            try:
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
    
    def stop(self):
        """Stop all components"""
        self.logger.info("Stopping TrustVault...")
        
        if self.monitor:
            self.monitor.stop()  # Assuming EnhancedRealtimeHandler has stop method
            self.logger.info("Monitor stopped")
            try:
                from alerts.alert_manager import AlertManager
                AlertManager.monitoring_stopped("CLI Folder")
            except Exception as e:
                print(f"AlertManager error: {e}")
        
        # Rotate logs before exit
        rotate_logs()
        
        self.logger.info("TrustVault shutdown complete")
    
    def show_status(self):
        """Show current system status"""
        self.logger.info("=== TrustVault Status ===")
        
        # System info
        sys_info = get_system_info()
        for key, value in sys_info.items():
            self.logger.info(f"{key}: {value}")
        
        # Check if monitor is running
        if self.monitor and self.monitor.is_running:  # Assuming EnhancedRealtimeHandler has is_running attribute
            self.logger.info("Monitor: RUNNING")
        else:
            self.logger.info("Monitor: STOPPED")
        
        # Check dashboard status
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 5000))
        if result == 0:
            self.logger.info("Dashboard: RUNNING on port 5000")
        else:
            self.logger.info("Dashboard: NOT RUNNING")
        sock.close()
        
        # Show log sizes
        if os.path.exists(constants.LOG_DIR):
            log_files = list(Path(constants.LOG_DIR).glob('*.log'))
            log_files.extend(list(Path(constants.LOG_DIR).glob('*.json')))
            
            for log_file in log_files:
                if log_file.exists():
                    size = log_file.stat().st_size
                    from utils.helpers import format_file_size
                    self.logger.info(f"Log {log_file.name}: {format_file_size(size)}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='TrustVault - File Integrity Monitoring System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s monitor          # Start monitoring only
  %(prog)s dashboard        # Start web dashboard only
  %(prog)s all              # Start both monitor and dashboard
  %(prog)s scan             # Run one-time scan
  %(prog)s backup           # Create backup of all data
  %(prog)s status           # Show system status
  %(prog)s cleanup          # Cleanup temporary files
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start file monitoring')
    monitor_parser.add_argument('--config', '-c', help='Configuration file path')
    monitor_parser.add_argument('--scan-only', '-s', action='store_true', 
                               help='Run one-time scan only')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dashboard_parser.add_argument('--port', '-p', type=int, default=5000,
                                 help='Port to run dashboard on (default: 5000)')
    dashboard_parser.add_argument('--host', default='0.0.0.0',
                                 help='Host to bind dashboard to (default: 0.0.0.0)')
    dashboard_parser.add_argument('--debug', '-d', action='store_true',
                                 help='Enable debug mode')
    
    # All command
    all_parser = subparsers.add_parser('all', help='Start both monitor and dashboard')
    all_parser.add_argument('--config', '-c', help='Configuration file path')
    all_parser.add_argument('--dashboard-port', type=int, default=5000,
                           help='Dashboard port (default: 5000)')
    
    # Other commands
    subparsers.add_parser('scan', help='Run one-time integrity scan')
    subparsers.add_parser('backup', help='Create backup of all data')
    subparsers.add_parser('status', help='Show system status')
    subparsers.add_parser('cleanup', help='Cleanup temporary files')
    subparsers.add_parser('setup', help='Setup environment')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    runner = SecureFIMRunner()
    
    if args.command == 'monitor':
        runner.setup_environment()
        runner.start_monitor(config_file=args.config, scan_only=args.scan_only)
        
        if not args.scan_only:
            # Keep running until interrupted
            try:
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                runner.stop()
    
    elif args.command == 'dashboard':
        runner.setup_environment()
        runner.start_dashboard(port=args.port, host=args.host, debug=args.debug)
    
    elif args.command == 'all':
        runner.start_all(config_file=args.config, dashboard_port=args.dashboard_port)
    
    elif args.command == 'scan':
        runner.setup_environment()
        runner.start_monitor(config_file=args.config, scan_only=True)
    
    elif args.command == 'backup':
        backup_dir = backup_data_files()
        if backup_dir:
            print(f"[OK] Backup created successfully at: {backup_dir}")
        else:
            print("[ERROR] Backup failed!")
    
    elif args.command == 'status':
        runner.show_status()
    
    elif args.command == 'cleanup':
        if cleanup_temp_files():
            print("[OK] Temporary files cleaned up successfully")
        else:
            print("[ERROR] Cleanup failed!")
    
    elif args.command == 'setup':
        runner.setup_environment()
        print("[OK] Environment setup complete")
    
    else:
        print("Error: No command specified")
        print("Use '--help' for usage information")
        sys.exit(1)

if __name__ == "__main__":
    # ASCII Art Banner
    banner = """
    ============================================================
                      TrustVault
          File Integrity Monitoring - Version 2.0 Pro
    ============================================================
    """

    print(banner)
    main()