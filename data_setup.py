#!/usr/bin/env python3
"""
Data Setup Script for TrustVault
Run this script manually to setup/verify data directories and files
"""

import os
import sys
import json
import shutil
from datetime import datetime
from pathlib import Path

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"🔧 {title}")
    print("="*60)

def create_directories():
    """Create all necessary directories"""
    print_header("Creating Directories")
    
    directories = [
        'logs',
        'CSV_logs',
        'certs',
        'keys',
        'data',
        'backups',
        'temp'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            if os.path.exists(directory):
                print(f"✓ {directory}/")
            else:
                print(f"✗ Failed to create {directory}/")
        except Exception as e:
            print(f"✗ Error creating {directory}/: {e}")

def create_config_files():
    """Create default configuration files"""
    print_header("Creating Configuration Files")
    
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
        "install_date": datetime.now().isoformat(),
        "license_accepted": True,
        "setup_complete": True,
        "last_setup": datetime.now().isoformat()
    }
    
    # Create config.json
    config_file = "data/config.json"
    try:
        os.makedirs("data", exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"✓ Created: {config_file}")
    except Exception as e:
        print(f"✗ Error creating {config_file}: {e}")
    
    # Create email_config.json
    email_config = {
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
    }
    
    email_file = "data/email_config.json"
    try:
        with open(email_file, 'w') as f:
            json.dump(email_config, f, indent=2)
        print(f"✓ Created: {email_file}")
    except Exception as e:
        print(f"✗ Error creating {email_file}: {e}")
    
    # Create file_hashes.json
    hash_file = "data/file_hashes.json"
    try:
        with open(hash_file, 'w') as f:
            json.dump({}, f, indent=2)
        print(f"✓ Created: {hash_file}")
    except Exception as e:
        print(f"✗ Error creating {hash_file}: {e}")
    
    # Create revoked.json
    revoked_file = "data/revoked.json"
    try:
        with open(revoked_file, 'w') as f:
            json.dump([], f, indent=2)
        print(f"✓ Created: {revoked_file}")
    except Exception as e:
        print(f"✗ Error creating {revoked_file}: {e}")

def create_log_files():
    """Create default log files"""
    print_header("Creating Log Files")
    
    # Create audit log
    audit_file = "logs/audit_log.json"
    try:
        os.makedirs("logs", exist_ok=True)
        with open(audit_file, 'w') as f:
            json.dump([], f, indent=2)
        print(f"✓ Created: {audit_file}")
    except Exception as e:
        print(f"✗ Error creating {audit_file}: {e}")
    
    # Create system log
    system_file = "logs/system.log"
    try:
        with open(system_file, 'w') as f:
            f.write(f"TrustVault System Log\n")
            f.write(f"Created: {datetime.now().isoformat()}\n")
            f.write("="*60 + "\n\n")
        print(f"✓ Created: {system_file}")
    except Exception as e:
        print(f"✗ Error creating {system_file}: {e}")
    
    # Create README in CSV_logs
    csv_readme = "CSV_logs/README.txt"
    try:
        os.makedirs("CSV_logs", exist_ok=True)
        with open(csv_readme, 'w') as f:
            f.write("CSV Logs Directory\n")
            f.write("="*40 + "\n")
            f.write("This directory contains exported logs in CSV format.\n")
            f.write("Files are automatically created when you export logs.\n")
            f.write(f"Created: {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"✓ Created: {csv_readme}")
    except Exception as e:
        print(f"✗ Error creating {csv_readme}: {e}")

def create_certificate_directories():
    """Create certificate directories with README files"""
    print_header("Setting Up Certificate Directories")
    
    # Create certs directory with README
    certs_readme = "certs/README.txt"
    try:
        os.makedirs("certs", exist_ok=True)
        with open(certs_readme, 'w') as f:
            f.write("Certificates Directory\n")
            f.write("="*40 + "\n")
            f.write("This directory stores user certificates (.pem files).\n")
            f.write("Certificates are generated from the Users tab.\n")
            f.write("DO NOT DELETE files from this directory manually.\n")
            f.write(f"Created: {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"✓ Created: {certs_readme}")
    except Exception as e:
        print(f"✗ Error creating {certs_readme}: {e}")
    
    # Create keys directory with README
    keys_readme = "keys/README.txt"
    try:
        os.makedirs("keys", exist_ok=True)
        with open(keys_readme, 'w') as f:
            f.write("Private Keys Directory\n")
            f.write("="*40 + "\n")
            f.write("This directory stores private keys (.pem files).\n")
            f.write("Keys are generated when creating certificates.\n")
            f.write("KEEP THIS DIRECTORY SECURE AND PRIVATE.\n")
            f.write("DO NOT SHARE OR BACKUP THESE FILES PUBLICLY.\n")
            f.write(f"Created: {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"✓ Created: {keys_readme}")
    except Exception as e:
        print(f"✗ Error creating {keys_readme}: {e}")
    
    # Create backups directory
    backups_readme = "backups/README.txt"
    try:
        os.makedirs("backups", exist_ok=True)
        with open(backups_readme, 'w') as f:
            f.write("Backups Directory\n")
            f.write("="*40 + "\n")
            f.write("This directory stores automatic backups.\n")
            f.write("Backups are created periodically and before updates.\n")
            f.write("Keep backups for disaster recovery.\n")
            f.write(f"Created: {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"✓ Created: {backups_readme}")
    except Exception as e:
        print(f"✗ Error creating {backups_readme}: {e}")

def create_license_file():
    """Create license acceptance file"""
    print_header("Creating License File")
    
    license_file = "data/license_accepted.txt"
    try:
        os.makedirs("data", exist_ok=True)
        with open(license_file, 'w') as f:
            f.write("accepted\n")
            f.write(f"Accepted on: {datetime.now().isoformat()}\n")
            f.write("By: Data Setup Script\n")
        print(f"✓ Created: {license_file}")
    except Exception as e:
        print(f"✗ Error creating {license_file}: {e}")

def create_sample_data():
    """Create sample data for testing"""
    print_header("Creating Sample Data")
    
    # Create sample hash database entry
    try:
        with open("data/file_hashes.json", 'r') as f:
            hashes = json.load(f)
    except:
        hashes = {}
    
    # Add a sample entry
    sample_file = "/path/to/important_file.txt"
    if sample_file not in hashes:
        hashes[sample_file] = {
            'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Empty file SHA256
            'registered': datetime.now().isoformat(),
            'last_verified': None,
            'filename': 'important_file.txt',
            'size': 0,
            'modified_time': datetime.now().timestamp(),
            'permissions': '644'
        }
        
        with open("data/file_hashes.json", 'w') as f:
            json.dump(hashes, f, indent=2)
        print("✓ Added sample hash entry")
    
    # Create sample audit log entry
    try:
        with open("logs/audit_log.json", 'r') as f:
            audit_log = json.load(f)
    except:
        audit_log = []
    
    sample_audit = {
        "timestamp": datetime.now().isoformat(),
        "user": "setup_script",
        "action": "DATA_SETUP_COMPLETE",
        "ip": "127.0.0.1",
        "details": "Data directories and files created successfully"
    }
    
    audit_log.append(sample_audit)
    
    with open("logs/audit_log.json", 'w') as f:
        json.dump(audit_log, f, indent=2)
    
    print("✓ Added sample audit log entry")

def verify_setup():
    """Verify that all directories and files were created successfully"""
    print_header("Verifying Setup")
    
    required_dirs = [
        'logs',
        'CSV_logs',
        'certs',
        'keys',
        'data',
        'backups',
        'temp'
    ]
    
    required_files = [
        'data/config.json',
        'data/email_config.json',
        'data/file_hashes.json',
        'data/revoked.json',
        'data/license_accepted.txt',
        'logs/audit_log.json',
        'logs/system.log',
        'certs/README.txt',
        'keys/README.txt',
        'CSV_logs/README.txt',
        'backups/README.txt'
    ]
    
    all_good = True
    
    # Check directories
    print("📁 Checking directories:")
    for directory in required_dirs:
        if os.path.exists(directory) and os.path.isdir(directory):
            print(f"  ✓ {directory}/")
        else:
            print(f"  ✗ {directory}/ (MISSING)")
            all_good = False
    
    print("\n📄 Checking files:")
    for file in required_files:
        if os.path.exists(file) and os.path.isfile(file):
            size = os.path.getsize(file)
            print(f"  ✓ {file} ({size} bytes)")
        else:
            print(f"  ✗ {file} (MISSING)")
            all_good = False
    
    return all_good

def cleanup_old_backups():
    """Clean up old backup files (older than 30 days)"""
    print_header("Cleaning Up Old Backups")
    
    try:
        if not os.path.exists("backups"):
            print("✓ No backups directory to clean")
            return
        
        current_time = datetime.now().timestamp()
        cutoff = current_time - (30 * 24 * 60 * 60)  # 30 days
        deleted = 0
        
        for backup_dir in Path("backups").glob("backup_*"):
            if backup_dir.is_dir():
                try:
                    dir_time = backup_dir.stat().st_mtime
                    if dir_time < cutoff:
                        shutil.rmtree(backup_dir)
                        deleted += 1
                        print(f"✓ Deleted old backup: {backup_dir.name}")
                except Exception as e:
                    print(f"✗ Error deleting {backup_dir}: {e}")
        
        print(f"✓ Cleaned up {deleted} old backups")
        
    except Exception as e:
        print(f"✗ Error during backup cleanup: {e}")

def show_summary():
    """Show setup summary"""
    print_header("Setup Summary")
    
    total_size = 0
    dir_count = 0
    file_count = 0
    
    # Calculate total size
    for root, dirs, files in os.walk("."):
        # Skip hidden directories and virtual environments
        if any(x in root for x in ['.git', '__pycache__', 'venv', '.venv', '.idea']):
            continue
            
        dir_count += len(dirs)
        for file in files:
            try:
                filepath = os.path.join(root, file)
                total_size += os.path.getsize(filepath)
                file_count += 1
            except:
                pass
    
    print(f"📊 Statistics:")
    print(f"  • Total directories: {dir_count}")
    print(f"  • Total files: {file_count}")
    print(f"  • Total size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")
    
    # Show disk space
    try:
        import shutil
        total, used, free = shutil.disk_usage(".")
        print(f"\n💾 Disk Space:")
        print(f"  • Total: {total // (2**30)} GB")
        print(f"  • Used: {used // (2**30)} GB")
        print(f"  • Free: {free // (2**30)} GB")
    except:
        pass

def main():
    """Main function for data setup"""
    print("\n" + "="*60)
    print("🔐 TRUSTVAULT - DATA SETUP SCRIPT")
    print("="*60)
    print("Version: 3.0")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")
    
    try:
        # Get confirmation
        response = input("This will setup all data directories and files.\nContinue? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("\nSetup cancelled.")
            return
        
        # Run setup steps
        create_directories()
        create_config_files()
        create_log_files()
        create_certificate_directories()
        create_license_file()
        
        # Ask about sample data
        response = input("\nCreate sample data for testing? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            create_sample_data()
        
        # Cleanup old backups
        cleanup_old_backups()
        
        # Verify setup
        success = verify_setup()
        
        if success:
            print("\n" + "="*60)
            print("✅ DATA SETUP COMPLETED SUCCESSFULLY!")
            print("="*60)
            
            show_summary()
            
            print("\n📋 Next Steps:")
            print("  1. Run the application: python main.py")
            print("  2. Configure email settings in the Email Alerts tab")
            print("  3. Add folders to monitor in the Monitor tab")
            print("  4. Register files for hash verification")
            print("\n⚠️  Remember:")
            print("  • Keep your private keys (keys/) secure")
            print("  • Regular backups are in backups/ directory")
            print("  • Check logs/ for system events")
            
        else:
            print("\n" + "="*60)
            print("⚠️  SETUP COMPLETED WITH ERRORS")
            print("="*60)
            print("Some files or directories could not be created.")
            print("Please check permissions and try again.")
        
        # Save setup log
        with open("logs/setup.log", 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Setup run: {datetime.now().isoformat()}\n")
            f.write(f"Success: {success}\n")
            f.write(f"{'='*60}\n")
        
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Make sure we're in the right directory
    if not os.path.exists("main.py"):
        print("⚠️  Warning: main.py not found in current directory.")
        print("Please run this script from the TrustVault root directory.")
        response = input("Continue anyway? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            sys.exit(1)
    
    main()
