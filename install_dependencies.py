#!/usr/bin/env python3
"""
Installation script for TrustVault dependencies
"""

import subprocess
import sys
import os

def run_command(command):
    """Run a shell command"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Success: {command}")
            return True
        else:
            print(f"❌ Failed: {command}")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Exception running {command}: {e}")
        return False

def main():
    print("=" * 60)
    print("TrustVault Dependency Installation")
    print("=" * 60)
    
    dependencies = [
        "watchdog",      # File monitoring
        "requests",      # HTTP requests
        "cryptography",  # Encryption
        "matplotlib",    # Charts and graphs
        "pillow",        # Image processing
        "tkcalendar",    # Calendar widget
    ]
    
    print("\nInstalling dependencies...")
    
    for dep in dependencies:
        if not run_command(f"{sys.executable} -m pip install {dep}"):
            print(f"Failed to install {dep}")
    
    print("\n" + "=" * 60)
    print("Installation complete!")
    print("=" * 60)
    
    # Test imports
    print("\nTesting imports...")
    try:
        import watchdog
        print("✅ watchdog imported successfully")
    except ImportError:
        print("❌ Failed to import watchdog")
    
    try:
        import requests
        print("✅ requests imported successfully")
    except ImportError:
        print("❌ Failed to import requests")
    
    print("\nNow run: python app.py")

if __name__ == "__main__":
    main()
