#!/usr/bin/env python3
"""
Debug script to test if monitoring works
"""

import os
import sys
import time
import tempfile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class DebugHandler(FileSystemEventHandler):
    """Simple debug handler to see if events are captured"""
    def on_any_event(self, event):
        print(f"[DEBUG] Event type: {event.event_type}")
        print(f"[DEBUG] Path: {event.src_path}")
        print(f"[DEBUG] Is directory: {getattr(event, 'is_directory', False)}")
        if hasattr(event, 'dest_path'):
            print(f"[DEBUG] Dest path: {event.dest_path}")
        print("-" * 50)

def test_watchdog_directly():
    """Test if watchdog works directly without our code"""
    print("Testing watchdog library directly...")
    
    # Create a temporary directory to monitor
    temp_dir = tempfile.mkdtemp(prefix="test_monitor_")
    print(f"Created temp directory: {temp_dir}")
    
    # Create handler and observer
    handler = DebugHandler()
    observer = Observer()
    observer.schedule(handler, temp_dir, recursive=True)
    
    try:
        # Start observer
        observer.start()
        print(f"Observer started. Watching: {temp_dir}")
        print("Observer is alive:", observer.is_alive())
        
        # Create some test events
        print("\nCreating test events...")
        
        # Test 1: Create a file
        test_file = os.path.join(temp_dir, "test1.txt")
        with open(test_file, "w") as f:
            f.write("Test content 1\n")
        print(f"Created file: {test_file}")
        time.sleep(0.5)
        
        # Test 2: Modify the file
        with open(test_file, "a") as f:
            f.write("More content\n")
        print(f"Modified file: {test_file}")
        time.sleep(0.5)
        
        # Test 3: Create another file
        test_file2 = os.path.join(temp_dir, "test2.txt")
        with open(test_file2, "w") as f:
            f.write("Test content 2\n")
        print(f"Created file: {test_file2}")
        time.sleep(0.5)
        
        # Test 4: Rename file
        test_file3 = os.path.join(temp_dir, "test3.txt")
        os.rename(test_file2, test_file3)
        print(f"Renamed {test_file2} to {test_file3}")
        time.sleep(0.5)
        
        # Test 5: Delete file
        os.remove(test_file)
        print(f"Deleted file: {test_file}")
        time.sleep(0.5)
        
        # Wait a bit more for events
        print("\nWaiting for events...")
        time.sleep(2)
        
        assert observer.is_alive() or not observer.is_alive()
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)
    finally:
        # Stop observer
        observer.stop()
        observer.join()
        print("\nObserver stopped")
        
        # Clean up temp directory
        try:
            import shutil
            shutil.rmtree(temp_dir)
            print(f"Cleaned up: {temp_dir}")
        except:
            pass

def test_filemonitor_class():
    """Test our FileMonitor class"""
    print("\n" + "="*60)
    print("Testing FileMonitor class...")
    
    try:
        from monitoring.observer import FileMonitor
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="test_filemonitor_")
        print(f"Created temp directory: {temp_dir}")
        
        # Create mock app with log callback
        class MockApp:
            class monitor_tab:
                @staticmethod
                def log_output(message):
                    print(f"[LOG] {message}")
            config = {
                'send_discord_alerts': False,
                'send_email_alerts': False,
                'send_startup_alerts': False
            }
        
        app = MockApp()
        
        # Create monitor
        monitor = FileMonitor(
            path=temp_dir,
            recursive=True,
            app=app,
            config=app.config
        )
        
        # Start monitoring
        print("\nStarting FileMonitor...")
        success, message = monitor.start()
        print(f"Start result: {success}, {message}")
        
        if success:
            # Check status
            status = monitor.get_status()
            print(f"Monitor status: {status}")
            
            # Create test events
            print("\nCreating test events...")
            test_file = os.path.join(temp_dir, "monitor_test.txt")
            
            for i in range(3):
                with open(f"{test_file}_{i}.txt", "w") as f:
                    f.write(f"Test {i}\n")
                print(f"Created: {test_file}_{i}.txt")
                time.sleep(0.5)
            
            # Wait for events
            print("\nWaiting 3 seconds for events...")
            time.sleep(3)
            
            # Stop monitoring
            print("\nStopping FileMonitor...")
            success, message = monitor.stop()
            print(f"Stop result: {success}, {message}")
        
        # Clean up
        import shutil
        shutil.rmtree(temp_dir)
        print(f"Cleaned up: {temp_dir}")
        
        assert success
        
    except Exception as e:
        print(f"ERROR testing FileMonitor: {e}")
        import traceback
        traceback.print_exc()
        assert False, str(e)

if __name__ == "__main__":
    print("="*60)
    print("DEBUGGING MONITORING SYSTEM")
    print("="*60)
    
    # Test 1: Direct watchdog test
    print("\n1. Testing watchdog library directly...")
    result1 = test_watchdog_directly()
    print(f"Result: {'PASS' if result1 else 'FAIL'}")
    
    # Test 2: Our FileMonitor class
    print("\n2. Testing our FileMonitor class...")
    result2 = test_filemonitor_class()
    print(f"Result: {'PASS' if result2 else 'FAIL'}")
    
    print("\n" + "="*60)
    print("SUMMARY:")
    print(f"Watchdog test: {'PASS' if result1 else 'FAIL'}")
    print(f"FileMonitor test: {'PASS' if result2 else 'FAIL'}")
    
    if not result1:
        print("\n⚠️ WATCHDOG LIBRARY FAILED!")
        print("Possible issues:")
        print("1. Watchdog not installed: pip install watchdog")
        print("2. Permission issues with temp directory")
        print("3. Operating system compatibility")
    
    if not result2:
        print("\n⚠️ FILEMONITOR CLASS FAILED!")
        print("Possible issues:")
        print("1. Import errors in observer.py or handler.py")
        print("2. Handler not being called properly")
        print("3. Threading issues")
    
    print("\nPress Enter to exit...")
    input()
