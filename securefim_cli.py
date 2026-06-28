#!/usr/bin/env python3
"""
TrustVault - Headless CLI (no GUI/dashboard)

Fixed version with:
- STRICT ransomware detection (ONLY specific extensions trigger alerts)
- No false positives on normal files like "meow"
- File monitoring with anomaly/ransomware detection
- Batch delete/clean command
"""

import argparse
import json
import os
import sys
import time
import hashlib
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure local imports work when running from project root
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from config import constants

from watchdog.observers import Observer
from watchdog.events import FileSystemEvent

# Import SecureFIM core handler
from monitoring.handler import EnhancedRealtimeHandler

# ----------------------------
# Small utilities
# ----------------------------

def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))

def print_event(obj: Any) -> None:
    """
    Print event cleanly and re-show prompt.
    """
    print(json.dumps(obj, indent=2, default=str))
    print("> ", end="", flush=True)

def safe_rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except Exception:
        return str(p)

def parse_value(value: str) -> Any:
    v = value.strip()
    low = v.lower()
    if low in {"true", "on", "yes"}:
        return True
    if low in {"false", "off", "no"}:
        return False
    if low in {"null", "none"}:
        return None

    try:
        if "." in v:
            return float(v)
        return int(v)
    except Exception:
        pass

    try:
        return json.loads(v)
    except Exception:
        return v

# ----------------------------
# STRICT RANSOMWARE DETECTION - ONLY these extensions trigger alerts
# ----------------------------

# ONLY these extensions will trigger ransomware detection
RANSOMWARE_EXTENSIONS = {
    '.locky', '.crypt', '.wncry', '.encrypted', '.rrk', '.wallet', 
    '.cry', '.cryp', '.zepto', '.odc', '.osiris', '.cerber', '.dharma',
    '.phobos', '.magniber', '.stop', '.djvu', '.revil', '.lockbit',
    '.locked', '.encrypt', '.crypto', '.ransom', '.btc', '.bitcoin'
}

# Ransom note patterns (exact filenames that trigger detection)
RANSOM_NOTE_PATTERNS = {
    'readme_to_decrypt.txt', 'readme.txt', 'how_to_decrypt.txt', 
    'how_to_recover.txt', 'ransom_note.txt', 'decrypt_instructions.txt',
    '!!!_read_me_!!!.txt', 'recover_files.txt', 'restore_files.txt',
    'help_decrypt.txt', 'decrypt_files.txt', 'payment_instructions.txt'
}

def is_ransomware_file(file_path: str) -> bool:
    """Strictly check if file is ransomware - ONLY returns True for known ransomware patterns"""
    path = Path(file_path)
    name = path.name.lower()
    ext = path.suffix.lower()
    
    # Check for exact ransom note matches
    if name in RANSOM_NOTE_PATTERNS:
        return True
    
    # Check for suspicious extensions (ONLY these)
    if ext in RANSOMWARE_EXTENSIONS:
        return True
    
    return False  # Everything else is NOT ransomware

# ----------------------------
# Custom handler with proper method signatures
# ----------------------------

class CLIFullHandler(EnhancedRealtimeHandler):
    """
    Extends EnhancedRealtimeHandler with proper method signatures.
    """

    def _process_event(self, event: FileSystemEvent, event_type: str) -> None:
        """
        Process a file system event with the correct signature.
        This matches the parent class method signature.
        """
        try:
            # Get file path
            file_path = Path(event.src_path)
            
            # Build event data dictionary
            event_data = {
                "file_path": str(file_path),
                "event_type": event_type,
                "timestamp": now_iso(),
                "is_directory": event.is_directory,
                "file_size": file_path.stat().st_size if file_path.exists() and file_path.is_file() else 0,
            }

            # Add destination path for moved events
            if event_type == "MOVED" and hasattr(event, 'dest_path'):
                event_data["dest_path"] = str(event.dest_path)

            # Calculate hash if needed and file exists
            if file_path.exists() and file_path.is_file() and self.hash_verifier:
                try:
                    import hashlib
                    h = hashlib.sha256()
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            h.update(chunk)
                    event_data["file_hash"] = h.hexdigest()
                except Exception:
                    event_data["file_hash"] = None

            # Check for anomalies FIRST (pattern-based)
            event_data["is_anomaly"] = False
            if self.anomaly_detector and file_path.exists() and not event_data["is_directory"]:
                try:
                    if hasattr(self.anomaly_detector, 'analyze_event'):
                        is_anomaly = self.anomaly_detector.analyze_event(event_data)
                        event_data["is_anomaly"] = bool(is_anomaly)
                except Exception as e:
                    print_event({
                        "time": now_iso(),
                        "event": "ERROR",
                        "message": f"Anomaly detection failed: {e}"
                    })

            # Check for ransomware (STRICT checking - ONLY known ransomware patterns)
            event_data["is_ransomware"] = False
            if not event_data["is_anomaly"] and file_path.exists() and file_path.is_file():
                # Use our strict checking function
                event_data["is_ransomware"] = is_ransomware_file(str(file_path))
                
                # Use ransomware detector if available (but only if it returns True for actual ransomware)
                if not event_data["is_ransomware"] and self.ransomware_detector:
                    try:
                        if hasattr(self.ransomware_detector, 'check_suspicious_extension'):
                            detector_result = self.ransomware_detector.check_suspicious_extension(str(file_path))
                            # Only trust detector if it returns True and the extension is in our list
                            if detector_result and file_path.suffix.lower() in RANSOMWARE_EXTENSIONS:
                                event_data["is_ransomware"] = True
                    except Exception as e:
                        print_event({
                            "time": now_iso(),
                            "event": "ERROR",
                            "message": f"Ransomware detection failed: {e}"
                        })

            # Send alerts (including directories)
            self._send_alerts(event_data)

            # Log to callback with appropriate level
            if self.log_callback:
                if event_data.get("is_ransomware"):
                    level = "RANSOMWARE"
                elif event_data.get("is_anomaly"):
                    level = "ANOMALY"
                elif event_data["is_directory"]:
                    level = "INFO"
                elif event_type in ["DELETED", "MOVED"]:
                    level = "WARNING"
                else:
                    level = "INFO"
                    
                item_type = "directory" if event_data["is_directory"] else "file"
                self.log_callback(
                    f"{item_type.title()} {event_type.lower()}: {event_data['file_path']}",
                    level=level
                )

        except Exception as e:
            print_event({
                "time": now_iso(),
                "event": "ERROR",
                "message": f"Error processing event: {e}"
            })

    def _send_alerts(self, event_data: Dict[str, Any]) -> None:
        """Send alerts for file events."""
        event_type = event_data.get("event_type", "UNKNOWN")

        # Decide alert level
        if event_data.get("is_ransomware", False):
            alert_level = "RANSOMWARE"
        elif event_data.get("is_anomaly", False):
            alert_level = "ANOMALY"
        elif event_type in ["DELETED", "MOVED"]:
            alert_level = "WARNING"
        else:
            alert_level = "INFO"

        # Email (only for critical alerts)
        if (self.email_system and self.alert_thresholds.get("send_email_alerts", True) and
                alert_level in ["ANOMALY", "RANSOMWARE"]):
            try:
                item_type = "Directory" if event_data.get("is_directory") else "File"
                subject = f"{alert_level}: {item_type} {event_type.lower()} - {os.path.basename(event_data['file_path'])}"
                message = f"""
TrustVault Alert - {alert_level}

Event: {event_type}
Type: {item_type}
Path: {event_data.get('file_path')}
Time: {event_data.get('timestamp')}
Ransomware: {event_data.get('is_ransomware', False)}
Anomaly: {event_data.get('is_anomaly', False)}

This alert was generated by TrustVault (CLI).
"""
                self.email_system.send_alert(subject, message)
            except Exception as e:
                print_event({
                    "time": now_iso(),
                    "event": "ERROR",
                    "message": f"Failed to send email alert: {e}"
                })

# ----------------------------
# Status / Config / Alerts
# ----------------------------

def cmd_status(fmt: str = "json") -> int:
    cfg = settings.load_config()
    important_paths = [
        "data",
        "logs",
        "config",
        "data/config.json",
        "data/file_hashes.json",
        "data/alert_history.json",
        "data/email_config.json",
        "data/revoked.json",
        "logs/audit_log.json",
    ]

    out = {
        "ok": True,
        "time": now_iso(),
        "project_root": str(PROJECT_ROOT),
        "loaded_config_type": type(cfg).__name__,
        "paths_exist": {p: (PROJECT_ROOT / p).exists() for p in important_paths},
        "anomaly_detection": bool(cfg.get("anomaly_detection", False)),
        "ransomware_detection": bool(cfg.get("ransomware_detection", False)),
        "hash_verification": bool(cfg.get("hash_verification", False)),
        "monitor_recursive": bool(cfg.get("monitor_recursive", True)),
    }

    if fmt == "json":
        print_json(out)
    else:
        print(f"[{out['time']}] TrustVault CLI status")
        for k, v in out.items():
            if k not in {"paths_exist"}:
                print(f"  {k}: {v}")
    return 0

def cmd_config_show(fmt: str = "json") -> int:
    cfg = settings.load_config()
    print_json({"ok": True, "time": now_iso(), "config": cfg})
    return 0

def cmd_config_get(key: str, fmt: str = "json") -> int:
    cfg = settings.load_config()
    if key not in cfg:
        print_json({"ok": False, "time": now_iso(), "error": f"Config key not found: {key}"})
        return 2
    print_json({"ok": True, "time": now_iso(), "key": key, "value": cfg.get(key)})
    return 0

def cmd_config_set(key: str, value_raw: str, fmt: str = "json") -> int:
    cfg = settings.load_config()
    old = cfg.get(key, None)
    cfg[key] = parse_value(value_raw)
    ok = settings.save_config(cfg)
    if not ok:
        print_json({"ok": False, "time": now_iso(), "error": "Failed to save config"})
        return 1
    print_json({"ok": True, "time": now_iso(), "key": key, "old": old, "new": cfg[key]})
    return 0

def cmd_config_toggle(key: str, state: str, fmt: str = "json") -> int:
    cfg = settings.load_config()
    old = cfg.get(key, None)
    cfg[key] = True if state == "on" else False
    ok = settings.save_config(cfg)
    if not ok:
        print_json({"ok": False, "time": now_iso(), "error": "Failed to save config"})
        return 1
    print_json({"ok": True, "time": now_iso(), "key": key, "old": old, "new": cfg[key]})
    return 0

def cmd_config_validate(fmt: str = "json") -> int:
    cfg = settings.load_config()
    defaults = constants.DEFAULT_CONFIG
    missing = [k for k in defaults.keys() if k not in cfg]
    extra = [k for k in cfg.keys() if k not in defaults]
    print_json({
        "ok": True,
        "time": now_iso(),
        "missing_keys": missing,
        "extra_keys": extra,
        "missing_count": len(missing),
        "extra_count": len(extra),
    })
    return 0

def cmd_alerts_list(limit: int = 20, level: Optional[str] = None, fmt: str = "json") -> int:
    path = PROJECT_ROOT / "data" / "alert_history.json"
    if not path.exists():
        print_json({"ok": True, "time": now_iso(), "count": 0, "alerts": []})
        return 0

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("alert_history.json is not a list")
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": f"Failed to read alert_history.json: {e}"})
        return 1

    if level:
        lvl = level.strip().upper()
        data = [a for a in data if str(a.get("level", "")).upper() == lvl]

    data = data[-limit:]
    print_json({"ok": True, "time": now_iso(), "count": len(data), "alerts": data})
    return 0

def cmd_alerts_tail(follow: bool, interval: float, fmt: str = "json") -> int:
    path = PROJECT_ROOT / "data" / "alert_history.json"
    last_len = 0

    def read_list() -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return d if isinstance(d, list) else []
        except Exception:
            return []

    first = read_list()
    last_len = len(first)
    print_json({"ok": True, "time": now_iso(), "count": last_len, "alerts": first[-20:]})

    if not follow:
        return 0

    try:
        while True:
            time.sleep(max(0.2, interval))
            d = read_list()
            if len(d) > last_len:
                new_items = d[last_len:]
                last_len = len(d)
                print_json({"ok": True, "time": now_iso(), "new": len(new_items), "alerts": new_items})
    except KeyboardInterrupt:
        return 0

# ----------------------------
# Monitor with interactive prompt
# ----------------------------

def initial_scan_simple(root: Path, recursive: bool) -> Dict[str, Any]:
    files = 0
    dirs = 0
    it = root.rglob("*") if recursive else root.glob("*")
    for p in it:
        if p.is_dir():
            dirs += 1
        elif p.is_file():
            files += 1
    return {"files": files, "dirs": dirs}

def run_monitor_interactive(
    root: Path,
    recursive: bool,
    cfg: Dict[str, Any],
    no_alerts: bool = False,
) -> int:
    """
    Start watchdog Observer with SecureFIM handler, then interactive prompt.
    """
    # Create security modules
    anomaly_detector = None
    ransomware_detector = None
    hash_verifier = None

    # Anomaly detector - handle window_size safely
    if bool(cfg.get("anomaly_detection", False)):
        try:
            from security.anomaly_detector import AnomalyDetector
            # Extract window_size safely
            window_size = cfg.get("window_size", 60)
            if isinstance(window_size, str) and 'x' in window_size:
                window_size = 60
                print_event({
                    "time": now_iso(),
                    "event": "INFO",
                    "message": "Using default window_size=60 (resolution string detected)"
                })
            else:
                try:
                    window_size = int(window_size)
                except (ValueError, TypeError):
                    window_size = 60
            
            # Handle threshold
            threshold = cfg.get("threshold", 2.5)
            try:
                threshold = float(threshold)
            except (ValueError, TypeError):
                threshold = 2.5
            
            anomaly_detector = AnomalyDetector(
                window_size=window_size,
                threshold=threshold
            )
            
            print_event({
                "time": now_iso(),
                "event": "INFO",
                "message": f"Anomaly detector initialized with window_size={window_size}"
            })
        except Exception as e:
            print_event({
                "time": now_iso(),
                "event": "WARN",
                "message": f"Failed to init anomaly detector: {e}"
            })

    # Ransomware detector
    if bool(cfg.get("ransomware_detection", False)):
        try:
            from security.ransomware_detector import RansomwareDetector
            ransomware_detector = RansomwareDetector()
            # Log available methods for debugging
            methods = [m for m in dir(ransomware_detector) if not m.startswith('_')]
            print_event({
                "time": now_iso(),
                "event": "INFO",
                "message": f"Ransomware detector initialized with methods: {methods}"
            })
        except Exception as e:
            print_event({
                "time": now_iso(),
                "event": "WARN",
                "message": f"Failed to init ransomware detector: {e}"
            })

    # Hash verifier
    if bool(cfg.get("hash_verification", False)):
        try:
            from security.hash_verifier import FileHashVerifier
            hash_verifier = FileHashVerifier()
        except Exception as e:
            print_event({
                "time": now_iso(),
                "event": "WARN",
                "message": f"Failed to init hash verifier: {e}"
            })

    # Log callback
    def log_callback(message: str, level: str = "INFO"):
        print_event({"time": now_iso(), "event": "LOG", "level": level, "message": message})

    # Use our custom handler
    handler = CLIFullHandler(
        log_callback=log_callback,
        anomaly_detector=anomaly_detector,
        web_dashboard=None,
        hash_verifier=hash_verifier,
        email_system=None,
        ransomware_detector=ransomware_detector,
        app=None,
        config=cfg,
    )

    observer = Observer()
    observer.schedule(handler, str(root), recursive=recursive)
    observer.start()
    # Header
    print_json({
        "ok": True,
        "time": now_iso(),
        "message": "Monitoring started (TrustVault pipeline)",
        "root": str(root),
        "recursive": recursive,
        "anomaly_detection": bool(anomaly_detector is not None),
        "ransomware_detection": bool(ransomware_detector is not None),
        "hash_verification": bool(hash_verifier is not None),
    })

    print("`nCommands: help, status, ls, touch <file>, write <file> <text>, delete <file>, mkdir <dir>, rmdir <dir>,")
    print("            clean <pattern>, clean all, ransomware <file> [content], ransomnote, encrypt <file>,")
    print("            locky <file>, crypto <file>, wannacry <file>, rapid <count> [prefix], exit")
    print("=" * 60)
    print("> ", end="", flush=True)

    # Interactive loop
    try:
        while True:
            try:
                line = input().strip()
            except EOFError:
                line = "exit"

            if not line:
                print("> ", end="", flush=True)
                continue

            try:
                parts = shlex.split(line)
            except Exception:
                parts = line.split()

            if not parts:
                print("> ", end="", flush=True)
                continue

            cmd = parts[0].lower()

            if cmd in {"exit", "quit"}:
                break

            elif cmd == "help":
                print("\n📚 Available Commands:")
                print("  help                          - Show this help")
                print("  status                        - Show monitoring status")
                print("  ls [path]                     - List files")
                print("  touch <file>                  - Create empty file (NEVER triggers ransomware)")
                print("  write <file> <text>           - Write text to file (NEVER triggers ransomware)")
                print("  delete <file>                  - Delete a single file")
                print("  mkdir <dir>                   - Create directory")
                print("  rmdir <dir>                   - Remove empty directory")
                print("\n  🗑️  BATCH DELETE COMMANDS:")
                print("  clean <pattern>                - Delete files matching pattern (e.g., clean *.tmp)")
                print("  clean all                      - Delete ALL files (with confirmation)")
                print("  clean now/*                    - Delete all files in 'now' directory")
                print("\n  🚨 RANSOMWARE TESTING COMMANDS (These WILL trigger alerts):")
                print("  ransomware <file> [content]   - Create file with .locked extension")
                print("  ransomnote                    - Create a ransom note file")
                print("  encrypt <file>                 - Create file with .encrypted extension")
                print("  locky <file>                   - Create .locky ransomware file")
                print("  crypto <file>                  - Create .crypt ransomware file")
                print("  wannacry <file>                - Create .wncry ransomware file")
                print("\n  📊 ANOMALY TESTING COMMANDS:")
                print("  rapid <count> [prefix]        - Rapidly create multiple files (triggers anomaly)")
                print("  exit                          - Stop monitoring\n")
                print("> ", end="", flush=True)

            elif cmd == "status":
                print_json({
                    "time": now_iso(),
                    "root": str(root),
                    "recursive": recursive,
                    "anomaly_detection": bool(anomaly_detector is not None),
                    "ransomware_detection": bool(ransomware_detector is not None),
                    "hash_verification": bool(hash_verifier is not None),
                })
                print("> ", end="", flush=True)

            elif cmd == "ls":
                rel = parts[1] if len(parts) > 1 else "."
                target = root / rel
                if not target.exists():
                    print(f"❌ Not found: {rel}")
                elif target.is_file():
                    size = target.stat().st_size
                    ext = target.suffix.lower()
                    # Check if it's a ransomware file
                    if is_ransomware_file(str(target)):
                        icon = "🔴"
                    else:
                        icon = "📄"
                    print(f"{icon} {rel} ({size:,} bytes)")
                else:
                    for p in sorted(target.glob("*")):
                        if p.is_dir():
                            print(f"📁 {safe_rel(root, p)}/")
                        else:
                            size = p.stat().st_size
                            if is_ransomware_file(str(p)):
                                icon = "🔴"
                            else:
                                icon = "📄"
                            print(f"{icon} {safe_rel(root, p)} ({size:,} bytes)")
                print("> ", end="", flush=True)

            elif cmd == "touch":
                if len(parts) < 2:
                    print("❌ Usage: touch <file>")
                else:
                    f = root / parts[1]
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.touch()
                    print(f"✅ Touched: {safe_rel(root, f)}")
                    print("   ✅ This is a NORMAL file - will NOT trigger ransomware")
                print("> ", end="", flush=True)

            elif cmd == "write":
                if len(parts) < 3:
                    print("❌ Usage: write <file> <text>")
                else:
                    f = root / parts[1]
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text(parts[2], encoding="utf-8")
                    print(f"✅ Wrote to: {safe_rel(root, f)}")
                    if is_ransomware_file(str(f)):
                        print("   ⚠️ This file WILL trigger ransomware detection!")
                    else:
                        print("   ✅ This is a NORMAL file - safe")
                print("> ", end="", flush=True)

            elif cmd == "delete":
                if len(parts) < 2:
                    print("❌ Usage: delete <file>")
                else:
                    f = root / parts[1]
                    if f.exists() and f.is_file():
                        f.unlink()
                        print(f"✅ Deleted: {safe_rel(root, f)}")
                    else:
                        print(f"❌ Not found or not a file: {parts[1]}")
                print("> ", end="", flush=True)

            elif cmd == "mkdir":
                if len(parts) < 2:
                    print("❌ Usage: mkdir <dir>")
                else:
                    d = root / parts[1]
                    d.mkdir(parents=True, exist_ok=True)
                    print(f"✅ Created directory: {safe_rel(root, d)}")
                print("> ", end="", flush=True)

            elif cmd == "rmdir":
                if len(parts) < 2:
                    print("❌ Usage: rmdir <dir>")
                else:
                    d = root / parts[1]
                    if d.exists() and d.is_dir():
                        try:
                            d.rmdir()
                            print(f"✅ Removed directory: {safe_rel(root, d)}")
                        except OSError:
                            print("❌ Directory not empty")
                    else:
                        print("❌ Not found or not a directory")
                print("> ", end="", flush=True)

            # BATCH DELETE COMMANDS
            elif cmd == "clean":
                if len(parts) < 2:
                    print("\n📋 Usage: clean <pattern>")
                    print("   Examples:")
                    print("     clean *.tmp           - Delete all .tmp files")
                    print("     clean testfile_*       - Delete all files starting with 'testfile_'")
                    print("     clean burst_*          - Delete all burst files")
                    print("     clean data_*           - Delete all data files")
                    print("     clean all              - Delete ALL files (use with caution!)")
                    print("     clean now/*            - Delete all files in 'now' directory\n")
                else:
                    pattern = parts[1]
                    try:
                        if pattern == "all":
                            # Delete ALL files in root
                            files = [f for f in root.iterdir() if f.is_file()]
                            if not files:
                                print("📂 No files to delete")
                            else:
                                print(f"\n⚠️  Found {len(files)} files to delete:")
                                for i, f in enumerate(files[:10]):
                                    print(f"   {i+1}. {safe_rel(root, f)}")
                                if len(files) > 10:
                                    print(f"   ... and {len(files)-10} more")
                                
                                confirm = input(f"\n❗ Delete ALL {len(files)} files? (yes/no): ")
                                if confirm.lower() == "yes":
                                    for f in files:
                                        f.unlink()
                                    print(f"✅ Deleted {len(files)} files")
                                else:
                                    print("❌ Cancelled")
                        
                        elif "/" in pattern or "\\" in pattern:
                            # Handle path patterns like "now/*"
                            pattern_path = root / pattern
                            parent = pattern_path.parent
                            pat = pattern_path.name
                            if parent.exists():
                                files = [f for f in parent.glob(pat) if f.is_file()]
                                if not files:
                                    print(f"📂 No files match '{pattern}'")
                                else:
                                    print(f"\n📋 Found {len(files)} files in {safe_rel(root, parent)}:")
                                    for i, f in enumerate(files[:10]):
                                        print(f"   {i+1}. {f.name}")
                                    if len(files) > 10:
                                        print(f"   ... and {len(files)-10} more")
                                    
                                    confirm = input(f"\n❗ Delete these {len(files)} files? (yes/no): ")
                                    if confirm.lower() == "yes":
                                        for f in files:
                                            f.unlink()
                                        print(f"✅ Deleted {len(files)} files")
                                    else:
                                        print("❌ Cancelled")
                            else:
                                print(f"❌ Directory not found: {parent}")
                        
                        elif "*" in pattern:
                            # Pattern matching in current directory
                            files = [f for f in root.glob(pattern) if f.is_file()]
                            if not files:
                                print(f"📂 No files match pattern: {pattern}")
                            else:
                                print(f"\n📋 Found {len(files)} files matching '{pattern}':")
                                # Group by extension for better overview
                                ext_count = {}
                                for f in files:
                                    ext = f.suffix or "(no extension)"
                                    ext_count[ext] = ext_count.get(ext, 0) + 1
                                
                                print("   Summary by type:")
                                for ext, count in sorted(ext_count.items()):
                                    print(f"     {ext}: {count} files")
                                
                                print(f"\n   First few files:")
                                for i, f in enumerate(files[:10]):
                                    print(f"     {i+1}. {safe_rel(root, f)}")
                                if len(files) > 10:
                                    print(f"     ... and {len(files)-10} more")
                                
                                confirm = input(f"\n❗ Delete these {len(files)} files? (yes/no): ")
                                if confirm.lower() == "yes":
                                    for f in files:
                                        f.unlink()
                                    print(f"✅ Deleted {len(files)} files")
                                else:
                                    print("❌ Cancelled")
                        else:
                            # Single file - use delete command
                            f = root / pattern
                            if f.exists() and f.is_file():
                                confirm = input(f"❗ Delete '{pattern}'? (yes/no): ")
                                if confirm.lower() == "yes":
                                    f.unlink()
                                    print(f"✅ Deleted: {pattern}")
                                else:
                                    print("❌ Cancelled")
                            else:
                                print(f"❌ File not found: {pattern}")
                    
                    except Exception as e:
                        print(f"❌ Error: {e}")
                print("> ", end="", flush=True)

            # Ransomware testing commands (these WILL trigger alerts)
            elif cmd == "ransomware":
                if len(parts) < 2:
                    print("❌ Usage: ransomware <file> [content]")
                else:
                    # Add .locked extension to trigger ransomware
                    f = root / f"{parts[1]}.locked"
                    f.parent.mkdir(parents=True, exist_ok=True)
                    content = parts[2] if len(parts) > 2 else "YOUR FILES ARE ENCRYPTED! Send Bitcoin to decrypt."
                    f.write_text(content, encoding="utf-8")
                    print(f"✅ Created ransomware test file: {safe_rel(root, f)}")
                    print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "ransomnote":
                f = root / "README_TO_DECRYPT.txt"
                content = """*** YOUR FILES ARE ENCRYPTED ***

All your documents, photos, databases and other important files have been encrypted.

To decrypt your files you must pay 0.5 Bitcoin to the following address:
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, contact us at: decrypthelp@onionmail.org

You have 72 hours to pay. After that the price doubles.

Do not try to decrypt files yourself, you will lose them forever!
"""
                f.write_text(content, encoding="utf-8")
                print(f"✅ Created ransom note: {safe_rel(root, f)}")
                print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "encrypt":
                if len(parts) < 2:
                    print("❌ Usage: encrypt <file>")
                else:
                    # Create file with .encrypted extension
                    f = root / f"{parts[1]}.encrypted"
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text("ENCRYPTED DATA - Cannot be read without decryption key", encoding="utf-8")
                    print(f"✅ Created encrypted file: {safe_rel(root, f)}")
                    print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "locky":
                if len(parts) < 2:
                    print("❌ Usage: locky <file>")
                else:
                    f = root / f"{parts[1]}.locky"
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text("Locky ransomware encrypted file", encoding="utf-8")
                    print(f"✅ Created Locky ransomware file: {safe_rel(root, f)}")
                    print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "crypto":
                if len(parts) < 2:
                    print("❌ Usage: crypto <file>")
                else:
                    f = root / f"{parts[1]}.crypt"
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text("CryptoLocker encrypted file", encoding="utf-8")
                    print(f"✅ Created CryptoLocker file: {safe_rel(root, f)}")
                    print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "wannacry":
                if len(parts) < 2:
                    print("❌ Usage: wannacry <file>")
                else:
                    f = root / f"{parts[1]}.wncry"
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text("WannaCry ransomware - Your files have been encrypted!", encoding="utf-8")
                    print(f"✅ Created WannaCry file: {safe_rel(root, f)}")
                    print("   WARNING: This should trigger ransomware detection!")
                print("> ", end="", flush=True)

            elif cmd == "rapid":
                # Rapidly create multiple files to trigger anomaly detection
                try:
                    count = int(parts[1]) if len(parts) > 1 else 10
                    prefix = parts[2] if len(parts) > 2 else "rapid"
                    
                    print(f"⚡ Creating {count} files rapidly to trigger anomaly detection...")
                    for i in range(count):
                        f = root / f"{prefix}_{i:03d}.tmp"
                        f.write_text(f"Test file {i}", encoding="utf-8")
                        time.sleep(0.01)  # Small delay but still rapid
                    print(f"✅ Created {count} files")
                    print("   This should trigger ANOMALY detection!")
                except Exception as e:
                    print(f"❌ Error: {e}")
                print("> ", end="", flush=True)

            else:
                print(f"❌ Unknown command: {cmd} (type 'help')")
                print("> ", end="", flush=True)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping monitor...")

    finally:
        try:
            observer.stop()
            observer.join(timeout=5)
        except Exception:
            pass

    print("`nMonitoring stopped.")
    return 0

def cmd_monitor(path: str, recursive_flag: Optional[bool], no_alerts: bool) -> int:
    root = (PROJECT_ROOT / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()

    if not root.exists():
        print_json({"ok": False, "time": now_iso(), "error": f"Path does not exist: {root}"})
        return 2
    if not root.is_dir():
        print_json({"ok": False, "time": now_iso(), "error": f"Path is not a directory: {root}"})
        return 2

    cfg = settings.load_config()

    if recursive_flag is None:
        recursive = bool(cfg.get("monitor_recursive", True))
    else:
        recursive = recursive_flag

    scan_counts = initial_scan_simple(root, recursive)
    print_json({"ok": True, "event": "INITIAL_SCAN", "time": now_iso(), "root": str(root), "recursive": recursive, **scan_counts})

    return run_monitor_interactive(
        root=root,
        recursive=recursive,
        cfg=cfg,
        no_alerts=no_alerts,
    )

# ----------------------------
# Parser
# ----------------------------


# ─────────────────────────────────────────────────────────────────────────────
# CLI commands for digital signing and hybrid encryption (Improvement v2)
# ─────────────────────────────────────────────────────────────────────────────

def cmd_sign(filepath: str, key_path: str, sig_path: Optional[str],
             password: Optional[str], algorithm: str) -> int:
    """CLI: sign a file and write a detached .sig JSON file."""
    try:
        from security.signing import sign_file
        ok, msg = sign_file(filepath, key_path, sig_path,
                            password=password, algorithm=algorithm)
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1


def cmd_verify_sig(filepath: str, cert_path: str, sig_path: Optional[str]) -> int:
    """CLI: verify a detached .sig JSON signature."""
    try:
        from security.signing import verify_file
        ok, msg = verify_file(filepath, cert_path, sig_path)
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1


def cmd_encrypt(filepath: str, cert_path: str, out_path: Optional[str]) -> int:
    """CLI: encrypt a file with AES-256-GCM + RSA-OAEP."""
    try:
        from security.encryption import encrypt_file
        ok, msg = encrypt_file(filepath, cert_path, out_path)
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1


def cmd_decrypt(enc_path: str, key_path: str, out_path: Optional[str],
                password: Optional[str]) -> int:
    """CLI: decrypt a hybrid-encrypted .enc file."""
    try:
        from security.encryption import decrypt_file
        ok, msg = decrypt_file(enc_path, key_path, out_path, password=password)
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1


def cmd_gencert(name: str, password: Optional[str], validity_days: int,
                export_pkcs12: bool, algorithm: str) -> int:
    """CLI: generate an RSA/EC key pair and CA-signed certificate."""
    try:
        from security.key_certificate import generate_certificate
        ok, msg = generate_certificate(
            name,
            password=password,
            validity_days=validity_days,
            export_pkcs12=export_pkcs12,
            key_algorithm=algorithm,
        )
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1


def cmd_auth(username: str, password: str, pkcs12_path: str, keystore_password: str) -> int:
    """CLI: authenticate with account password plus PKCS#12 challenge response."""
    try:
        from security.key_certificate import authenticate_with_certificate
        ok, msg = authenticate_with_certificate(username, password, pkcs12_path, keystore_password)
        print_json({"ok": ok, "time": now_iso(), "message": msg})
        return 0 if ok else 1
    except Exception as e:
        print_json({"ok": False, "time": now_iso(), "error": str(e)})
        return 1

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="securefim",
        description="TrustVault (Headless CLI) - TrustVault pipeline"
    )
    sub = p.add_subparsers(dest="cmd")

    st = sub.add_parser("status", help="Show status")
    st.add_argument("--format", choices=["text", "json"], default="json")

    mon = sub.add_parser("monitor", help="Initial scan + live monitoring + anomaly/ransomware")
    mon.add_argument("path", help="Folder to monitor (relative to project root or absolute)")
    mon.add_argument("--recursive", action="store_true", help="Force recursive ON")
    mon.add_argument("--no-recursive", action="store_true", help="Force recursive OFF")
    mon.add_argument("--no-alerts", action="store_true", help="Disable alerts for this run")

    cfg = sub.add_parser("config", help="View and edit config")
    cfg_sub = cfg.add_subparsers(dest="cfg_cmd")
    sh = cfg_sub.add_parser("show", help="Print full config")
    sh.add_argument("--format", choices=["text", "json"], default="json")
    g = cfg_sub.add_parser("get", help="Get config key")
    g.add_argument("key")
    g.add_argument("--format", choices=["text", "json"], default="json")
    s = cfg_sub.add_parser("set", help="Set config key")
    s.add_argument("key")
    s.add_argument("value")
    s.add_argument("--format", choices=["text", "json"], default="json")
    t = cfg_sub.add_parser("toggle", help="Toggle boolean config key")
    t.add_argument("key")
    t.add_argument("state", choices=["on", "off"])
    t.add_argument("--format", choices=["text", "json"], default="json")
    v = cfg_sub.add_parser("validate", help="Validate config keys vs defaults")
    v.add_argument("--format", choices=["text", "json"], default="json")

    al = sub.add_parser("alerts", help="Read alert history")
    al_sub = al.add_subparsers(dest="al_cmd")
    lst = al_sub.add_parser("list", help="List alerts")
    lst.add_argument("--limit", type=int, default=20)
    lst.add_argument("--level", default=None)
    lst.add_argument("--format", choices=["text", "json"], default="json")
    tail = al_sub.add_parser("tail", help="Tail alerts")
    tail.add_argument("--follow", action="store_true")
    tail.add_argument("--interval", type=float, default=1.0)
    tail.add_argument("--format", choices=["text", "json"], default="json")


    # ── sign ──────────────────────────────────────────────────────────────────
    sg = sub.add_parser("sign", help="Sign a file with RSA-PSS or ECDSA")
    sg.add_argument("file", help="File to sign")
    sg.add_argument("--key", required=True, help="Password-protected private keystore (.p12/.pfx)")
    sg.add_argument("--sig", default=None, help="Output .sig path (default: <file>.sig)")
    sg.add_argument("--password", default=None, help="Key passphrase")
    sg.add_argument("--algorithm", choices=["RSA-PSS", "ECDSA"], default="RSA-PSS")

    # ── verify ─────────────────────────────────────────────────────────────────
    vs = sub.add_parser("verify", help="Verify a file signature")
    vs.add_argument("file", help="Signed file")
    vs.add_argument("--cert", required=True, help="X.509 certificate or public key")
    vs.add_argument("--sig", default=None, help=".sig file (default: <file>.sig)")

    # ── encrypt ────────────────────────────────────────────────────────────────
    en = sub.add_parser("encrypt", help="Encrypt a file (AES-256-GCM + RSA-OAEP)")
    en.add_argument("file", help="File to encrypt")
    en.add_argument("--cert", required=True, help="Recipient X.509 certificate or public key")
    en.add_argument("--out", default=None, help="Output .enc path (default: <file>.enc)")

    # ── decrypt ────────────────────────────────────────────────────────────────
    de = sub.add_parser("decrypt", help="Decrypt a hybrid-encrypted .enc file")
    de.add_argument("file", help="Encrypted .enc file")
    de.add_argument("--key", required=True, help="Password-protected private keystore (.p12/.pfx)")
    de.add_argument("--out", default=None, help="Output path (default: strip .enc)")
    de.add_argument("--password", default=None, help="Key passphrase")

    # ── gencert ────────────────────────────────────────────────────────────────
    gc = sub.add_parser("gencert", help="Generate a CA-signed certificate and PKCS#12 keystore")
    gc.add_argument("name", help="Common name for the certificate")
    gc.add_argument("--password", required=True, help="Required PKCS#12 keystore password")
    gc.add_argument("--days", type=int, default=365, help="Validity in days (default 365)")
    gc.add_argument("--pkcs12", action="store_true", help="Compatibility flag; PKCS#12 export is always enabled")
    gc.add_argument("--algorithm", choices=["RSA", "EC"], default="RSA", help="Key algorithm")

    au = sub.add_parser("auth", help="Authenticate with certificate challenge-response")
    au.add_argument("username", help="Stored username")
    au.add_argument("--password", required=True, help="Account password")
    au.add_argument("--p12", required=True, help="PKCS#12 keystore path")
    au.add_argument("--keystore-password", required=True, help="PKCS#12 keystore password")

    return p

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "cmd", None):
        return cmd_status(fmt="json")

    if args.cmd == "status":
        return cmd_status(fmt=args.format)

    if args.cmd == "monitor":
        if args.recursive and args.no_recursive:
            print_json({"ok": False, "time": now_iso(), "error": "Use only one: --recursive OR --no-recursive"})
            return 2

        recursive_flag = True if args.recursive else False if args.no_recursive else None

        return cmd_monitor(args.path, recursive_flag, no_alerts=args.no_alerts)

    if args.cmd == "config":
        if not getattr(args, "cfg_cmd", None):
            print_json({"ok": False, "time": now_iso(), "error": "Missing config subcommand (show/get/set/toggle/validate)"})
            return 2
        if args.cfg_cmd == "show":
            return cmd_config_show(fmt=args.format)
        if args.cfg_cmd == "get":
            return cmd_config_get(args.key, fmt=args.format)
        if args.cfg_cmd == "set":
            return cmd_config_set(args.key, args.value, fmt=args.format)
        if args.cfg_cmd == "toggle":
            return cmd_config_toggle(args.key, args.state, fmt=args.format)
        if args.cfg_cmd == "validate":
            return cmd_config_validate(fmt=args.format)

    if args.cmd == "alerts":
        if not getattr(args, "al_cmd", None):
            print_json({"ok": False, "time": now_iso(), "error": "Missing alerts subcommand (list/tail)"})
            return 2
        if args.al_cmd == "list":
            return cmd_alerts_list(limit=args.limit, level=args.level, fmt=args.format)
        if args.al_cmd == "tail":
            return cmd_alerts_tail(follow=args.follow, interval=args.interval, fmt=args.format)

    if args.cmd == "sign":
        return cmd_sign(args.file, args.key, args.sig,
                        password=args.password, algorithm=args.algorithm)

    if args.cmd == "verify":
        return cmd_verify_sig(args.file, args.cert, args.sig)

    if args.cmd == "encrypt":
        return cmd_encrypt(args.file, args.cert, args.out)

    if args.cmd == "decrypt":
        return cmd_decrypt(args.file, args.key, args.out, password=args.password)

    if args.cmd == "gencert":
        return cmd_gencert(args.name, password=args.password,
                           validity_days=args.days, export_pkcs12=args.pkcs12,
                           algorithm=args.algorithm)

    if args.cmd == "auth":
        return cmd_auth(args.username, args.password, args.p12, args.keystore_password)

    parser.print_help()
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
