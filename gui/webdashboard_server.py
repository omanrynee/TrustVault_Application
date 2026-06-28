"""
Web Dashboard Server for TrustVault
Location: V2/gui/webdashboard_server.py
Enhanced version with debugging and better event handling
"""

import socket
import threading
import time
import secrets
import urllib.request
from datetime import datetime
import json

from flask import Flask, jsonify, request

try:
    from flask_socketio import SocketIO
    SOCKETIO_AVAILABLE = True
except Exception:
    SocketIO = None
    SOCKETIO_AVAILABLE = False


class WebDashboardServer:
    def __init__(self, port=5000, debug=False):
        self.port = int(port)
        self.is_running = False
        self.app = None
        self.socketio = None
        self.thread = None
        self.start_time = None
        self.shutdown_token = secrets.token_urlsafe(16)
        self.debug = debug

        # Statistics tracking
        self.stats = {
            "total_events": 0,
            "critical_events": 0,
            "warnings": 0,
            "modifications": 0,
            "deletions": 0,
            "creations": 0,
        }

        self.recent_events = []
        self.max_events = 200
        self._lock = threading.Lock()

    def _log(self, message):
        """Internal logging"""
        if self.debug:
            print(f"[WebDashboard] {message}")

    # --------------------------------------------------
    # PORT HANDLING (AUTO + REUSE)
    # --------------------------------------------------

    def _port_free(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False

    def _find_free_port(self, start_port):
        for p in range(start_port, start_port + 100):
            if self._port_free(p):
                return p
        raise RuntimeError("No free ports available")

    def _wait_for_port(self, timeout=3):
        start = time.time()
        while time.time() - start < timeout:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def _local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    # --------------------------------------------------
    # FLASK APP
    # --------------------------------------------------

    def _create_app(self):
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "securefim-dashboard"

        socketio = None
        if SOCKETIO_AVAILABLE:
            socketio = SocketIO(
                app,
                cors_allowed_origins="*",
                async_mode="threading"
            )
            self._log("SocketIO initialized")
        else:
            self._log("WARNING: SocketIO not available - live updates disabled")

        @app.route("/")
        def index():
            return self._dashboard_html()

        @app.route("/api/stats")
        def api_stats():
            with self._lock:
                uptime = int(time.time() - self.start_time) if self.start_time else 0
                return jsonify({
                    "stats": self.stats.copy(),
                    "uptime": uptime,
                    "recent_events": self.recent_events[-20:],
                    "server_info": {
                        "socketio_available": SOCKETIO_AVAILABLE,
                        "is_running": self.is_running,
                        "port": self.port
                    }
                })

        @app.route("/api/events")
        def api_events():
            limit = request.args.get("limit", 50, type=int)
            with self._lock:
                return jsonify({
                    "events": self.recent_events[-limit:],
                    "total": len(self.recent_events)
                })

        @app.route("/api/clear")
        def api_clear():
            with self._lock:
                self.recent_events.clear()
                self.stats = {
                    "total_events": 0,
                    "critical_events": 0,
                    "warnings": 0,
                    "modifications": 0,
                    "deletions": 0,
                    "creations": 0,
                }
            return jsonify({"ok": True, "message": "Stats cleared"})

        @app.route("/shutdown")
        def shutdown():
            if request.args.get("token") != self.shutdown_token:
                return jsonify({"error": "unauthorized"}), 401

            func = request.environ.get("werkzeug.server.shutdown")
            if func:
                func()

            self.is_running = False
            return jsonify({"ok": True})

        return app, socketio

    # --------------------------------------------------
    # SERVER CONTROL
    # --------------------------------------------------

    def start(self):
        if self.is_running:
            self._log("Server already running")
            return True, self.get_network_url()

        self.port = self._find_free_port(self.port)
        self._log(f"Starting server on port {self.port}")

        self.app, self.socketio = self._create_app()
        self.start_time = time.time()

        def run():
            try:
                if self.socketio:
                    self.socketio.run(
                        self.app,
                        host="0.0.0.0",
                        port=self.port,
                        debug=False,
                        use_reloader=False,
                        allow_unsafe_werkzeug=True
                    )
                else:
                    self.app.run(
                        host="0.0.0.0",
                        port=self.port,
                        debug=False,
                        use_reloader=False,
                        threaded=True
                    )
            except Exception as e:
                self._log(f"Server error: {e}")
            finally:
                self.is_running = False

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

        if not self._wait_for_port():
            self._log("Server failed to start")
            return False, "Server failed to start"

        self.is_running = True
        self._log(f"Server started successfully at {self.get_network_url()}")
        return True, self.get_network_url()

    def stop(self):
        if not self.is_running:
            return True, "Already stopped"

        try:
            self._log("Stopping server...")
            url = f"http://127.0.0.1:{self.port}/shutdown?token={self.shutdown_token}"
            urllib.request.urlopen(url, timeout=2)
            time.sleep(0.8)
            self.is_running = False
            self._log("Server stopped")
            return True, "Stopped"
        except Exception as e:
            self._log(f"Error stopping server: {e}")
            return False, str(e)

    # --------------------------------------------------
    # EVENT INGESTION (KEY PART)
    # --------------------------------------------------

    def add_event(self, event: dict):
        """
        Called by monitoring engine to add new events
        
        Args:
            event: Dictionary containing event data with keys like:
                   - event_type: Type of event (e.g., "FILE_MODIFIED")
                   - severity: "critical", "warning", "info"
                   - message: Human-readable message
                   - file: File path (optional)
                   - timestamp: Event timestamp (auto-generated if missing)
        """
        with self._lock:
            self.stats["total_events"] += 1

            etype = (event.get("event_type") or "").lower()
            severity = (event.get("severity") or "info").lower()

            # Count by severity
            if severity == "critical" or "critical" in etype:
                self.stats["critical_events"] += 1
            elif severity == "warning":
                self.stats["warnings"] += 1

            # Count by event type
            if "modif" in etype:
                self.stats["modifications"] += 1
            elif "delet" in etype:
                self.stats["deletions"] += 1
            elif "creat" in etype:
                self.stats["creations"] += 1

            # Ensure timestamp
            if "timestamp" not in event:
                event["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Add to recent events
            self.recent_events.append(event)
            if len(self.recent_events) > self.max_events:
                self.recent_events.pop(0)

        # Live push via SocketIO
        if self.socketio and self.is_running:
            try:
                self.socketio.emit("new_event", event)
                self._log(f"Event pushed: {event.get('event_type')} - {event.get('message', 'N/A')}")
            except Exception as e:
                self._log(f"Error pushing event: {e}")
        else:
            self._log(f"Event logged (no live push): {event.get('event_type')}")

    def add_events_batch(self, events: list):
        """Add multiple events at once"""
        for event in events:
            self.add_event(event)

    # --------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------

    def get_url(self):
        return f"http://localhost:{self.port}"

    def get_network_url(self):
        return f"http://{self._local_ip()}:{self.port}"

    def get_stats(self):
        """Get current statistics"""
        with self._lock:
            return self.stats.copy()

    def get_recent_events(self, limit=20):
        """Get recent events"""
        with self._lock:
            return self.recent_events[-limit:]

    # --------------------------------------------------
    # UI
    # --------------------------------------------------

    def _dashboard_html(self):
        return """
<!DOCTYPE html>
<html>
<head>
    <title>TrustVault Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Times, serif;
            background: #0a0e27;
            color: #e0e0e0;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        .status {
            display: inline-block;
            padding: 5px 15px;
            background: rgba(0,255,0,0.2);
            border-radius: 20px;
            font-size: 14px;
            border: 1px solid #00ff00;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .stat-card h3 {
            font-size: 14px;
            color: #a0a0a0;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #fff;
        }
        .critical { border-left-color: #ff4444; }
        .warning { border-left-color: #ffaa00; }
        .success { border-left-color: #00ff88; }
        
        .events-section {
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .events-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .events-header h2 {
            font-size: 20px;
        }
        .clear-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        .clear-btn:hover {
            background: #5568d3;
        }
        .event {
            background: #0f1425;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .event-critical { border-left-color: #ff4444; }
        .event-warning { border-left-color: #ffaa00; }
        .event-info { border-left-color: #4488ff; }
        
        .event-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .event-type {
            font-weight: bold;
            color: #667eea;
            font-size: 14px;
        }
        .event-time {
            color: #888;
            font-size: 12px;
        }
        .event-message {
            color: #e0e0e0;
            font-size: 14px;
            word-break: break-all;
        }
        .no-events {
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }
        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 12px;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
        }
        .connected { border: 1px solid #00ff00; color: #00ff00; }
        .disconnected { border: 1px solid #ff4444; color: #ff4444; }
    </style>
</head>
<body>
    <div id="connection-status" class="connection-status disconnected">
        ⚫ Connecting...
    </div>

    <div class="header">
        <h1>🔒 TrustVault Dashboard</h1>
        <span class="status">● LIVE MONITORING</span>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Events</h3>
            <div class="value" id="total-events">0</div>
        </div>
        <div class="stat-card critical">
            <h3>Critical</h3>
            <div class="value" id="critical-events">0</div>
        </div>
        <div class="stat-card warning">
            <h3>Warnings</h3>
            <div class="value" id="warnings">0</div>
        </div>
        <div class="stat-card success">
            <h3>Modifications</h3>
            <div class="value" id="modifications">0</div>
        </div>
        <div class="stat-card">
            <h3>Deletions</h3>
            <div class="value" id="deletions">0</div>
        </div>
        <div class="stat-card">
            <h3>Creations</h3>
            <div class="value" id="creations">0</div>
        </div>
    </div>

    <div class="events-section">
        <div class="events-header">
            <h2>📊 Recent Events</h2>
            <button class="clear-btn" onclick="clearEvents()">Clear All</button>
        </div>
        <div id="events">
            <div class="no-events">Waiting for events...</div>
        </div>
    </div>

    <script>
        const socket = io();
        let isConnected = false;

        // Connection status
        socket.on('connect', () => {
            isConnected = true;
            updateConnectionStatus();
            console.log('[OK] Connected to server');
        });

        socket.on('disconnect', () => {
            isConnected = false;
            updateConnectionStatus();
            console.log('[ERROR] Disconnected from server');
        });

        function updateConnectionStatus() {
            const status = document.getElementById('connection-status');
            if (isConnected) {
                status.className = 'connection-status connected';
                status.innerHTML = '🟢 Connected';
            } else {
                status.className = 'connection-status disconnected';
                status.innerHTML = '🔴 Disconnected';
            }
        }

        // Live event updates
        socket.on("new_event", e => {
            console.log('[EVENT] New event received:', e);
            addEventToUI(e);
        });

        function addEventToUI(e) {
            const container = document.getElementById("events");
            
            // Remove "no events" message
            if (container.querySelector('.no-events')) {
                container.innerHTML = '';
            }

            const severity = (e.severity || 'info').toLowerCase();
            const eventClass = `event event-${severity}`;
            
            const eventHtml = `
                <div class="${eventClass}">
                    <div class="event-header">
                        <span class="event-type">${e.event_type || 'UNKNOWN'}</span>
                        <span class="event-time">${e.timestamp || 'N/A'}</span>
                    </div>
                    <div class="event-message">
                        ${e.message || e.file || 'No details provided'}
                    </div>
                </div>
            `;
            
            container.insertAdjacentHTML('afterbegin', eventHtml);
            
            // Keep only last 50 events in UI
            const events = container.querySelectorAll('.event');
            if (events.length > 50) {
                events[events.length - 1].remove();
            }
        }

        // Refresh stats
        function refreshStats() {
            fetch("/api/stats")
                .then(r => r.json())
                .then(d => {
                    document.getElementById("total-events").textContent = d.stats.total_events;
                    document.getElementById("critical-events").textContent = d.stats.critical_events;
                    document.getElementById("warnings").textContent = d.stats.warnings;
                    document.getElementById("modifications").textContent = d.stats.modifications;
                    document.getElementById("deletions").textContent = d.stats.deletions;
                    document.getElementById("creations").textContent = d.stats.creations;
                    
                    // Load recent events if container is empty
                    const container = document.getElementById("events");
                    if (container.querySelector('.no-events') && d.recent_events.length > 0) {
                        container.innerHTML = '';
                        d.recent_events.reverse().forEach(e => addEventToUI(e));
                    }
                })
                .catch(err => console.error('Error fetching stats:', err));
        }

        function clearEvents() {
            if (confirm('Clear all events and statistics?')) {
                fetch("/api/clear")
                    .then(r => r.json())
                    .then(() => {
                        document.getElementById("events").innerHTML = '<div class="no-events">Waiting for events...</div>';
                        refreshStats();
                    });
            }
        }

        // Initial load and periodic refresh
        setInterval(refreshStats, 2000);
        refreshStats();
        updateConnectionStatus();
    </script>
</body>
</html>
        """


# --------------------------------------------------
# TEST FUNCTION
# --------------------------------------------------

def run_test_server():
    """Test the dashboard with simulated events"""
    print("=" * 60)
    print("TrustVault Dashboard - Test Mode")
    print("=" * 60)
    
    server = WebDashboardServer(port=5000, debug=True)
    success, url = server.start()
    
    if not success:
        print(f"[ERROR] Failed to start server: {url}")
        return
    
    print(f"\n[OK] Dashboard running at:")
    print(f"   Local:   {server.get_url()}")
    print(f"   Network: {server.get_network_url()}")
    print(f"\n[STATS] Generating test events...")
    print("   (Open the dashboard in your browser to see live updates)\n")
    
    # Simulate events
    test_events = [
        {
            "event_type": "FILE_MODIFIED",
            "severity": "warning",
            "message": "Configuration file modified",
            "file": "/etc/config/app.conf"
        },
        {
            "event_type": "FILE_DELETED",
            "severity": "critical",
            "message": "Critical system file deleted",
            "file": "/var/log/audit.log"
        },
        {
            "event_type": "FILE_CREATED",
            "severity": "info",
            "message": "New log file created",
            "file": "/var/log/app.log"
        },
        {
            "event_type": "PERMISSION_CHANGED",
            "severity": "warning",
            "message": "File permissions changed to 777",
            "file": "/usr/bin/sensitive_script.sh"
        },
        {
            "event_type": "SUSPICIOUS_ACCESS",
            "severity": "critical",
            "message": "Unauthorized access attempt detected",
            "file": "/root/.ssh/authorized_keys"
        }
    ]
    
    try:
        for i in range(10):
            event = test_events[i % len(test_events)].copy()
            event["message"] = f"{event['message']} (Test #{i+1})"
            
            server.add_event(event)
            print(f"   [OK] Sent: {event['event_type']} - {event['severity']}")
            time.sleep(2)
        
        print(f"\n[STATS] Current Stats:")
        stats = server.get_stats()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        print(f"\n[WEB] Dashboard is running. Press Ctrl+C to stop...")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n[STOP]  Stopping server...")
        server.stop()
        print("[OK] Server stopped. Goodbye!")


if __name__ == "__main__":
    run_test_server()
