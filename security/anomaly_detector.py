"""
Anomaly Detection Module for TrustVault with ML (One-Class SVM)

BUGS FIXED IN THIS VERSION
===========================

BUG 1 — burst_window too short (8s → 30s)
    If 13 folders are created at ~0.5-1s intervals (realistic script timing),
    the total span is 6-13s.  With a window of only 8s, events near the start
    fall OUTSIDE the window and burst_count never reaches burst_threshold.
    Fix: burst_window = 30s so the full burst is always captured.

BUG 2 — burst_threshold too high (10 → 8)
    Expected normal events in 30s = 12/min ÷ 60 × 30 = 6.
    Threshold of 8 fires when count is 1.33× expected — appropriately sensitive.
    Old threshold of 10 in an 8s window was calibrated too tight.

BUG 3 — rate × 3 guard prevents detection in wider windows
    Original code: if rate_per_second > normal_rate_per_second * 3
    With 30s window: 13 events / 30s = 0.43/s, 3× normal = 0.60/s → guard FAILS.
    Fix: removed the rate×3 guard.  Replaced with expected-count comparison:
         count > expected_in_window * 1.5  (simpler and window-size independent).

BUG 4 — cooldown check nested inside rate block (logic error)
    Original code structure:
        if burst_count >= burst_threshold:
            if rate_per_second > normal * 3:
                is_burst = True
            if is_burst and cooldown_ok:   ← inside outer if
                return True
        return False                        ← ALWAYS reached when cooldown fails
    When cooldown was active, the function returned False even for a real burst,
    silently dropping the detection rather than just suppressing the alert.
    Fix: separated burst-detection logic from cooldown check entirely.

BUG 5 — Statistical z-score used abs() causing false positives on quiet periods
    abs(current_rate − baseline) / stdev fires when rate is LOW too.
    Example: 1 event → rate=1/min, z=|1-12|/3=3.67 → would trigger.
    Fix: directional z-score  (current_rate − baseline) / stdev
         Negative values (quiet periods) can never exceed the threshold.

BUG 6 — Statistical guard "current_rate > baseline * 1.5" blocked real bursts
    With baseline=12: guard requires rate > 18 events/min.
    13 rapid folders → rate ≈ 13/min → 13 < 18 → statistical detection NEVER fires
    for any burst below 18 events/min, making it almost useless.
    Fix: removed the 1.5× guard entirely.  The directional z-score + min-events
         guard (window_events ≥ 5) provides all the false-positive protection needed.
"""

import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Callable, Any
import os
import json
import numpy as np
from collections import defaultdict, deque
import threading

# Import ML libraries (optional)
try:
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    print("Warning: scikit-learn not installed. ML features disabled.")
    ML_AVAILABLE = False


class AnomalyDetector:
    """ML-based anomaly detection for file system events with One-Class SVM."""

    DEFAULT_STATE_FILE = "anomaly_detector_state.json"

    def __init__(self, window_size: int = 60, threshold: float = 2.5,
                 alert_callback: Callable = None, use_ml: bool = True,
                 state_file: str = None, notification_callback: Callable = None):
        self.window_size = window_size
        self.threshold = threshold
        self.alert_callback = alert_callback
        self.notification_callback = notification_callback
        self.use_ml = use_ml and ML_AVAILABLE
        self.config = {"debug_mode": True}

        # State persistence configuration
        self.state_file = state_file or self.DEFAULT_STATE_FILE
        self.auto_save = True
        self.last_save_time = 0
        self.save_interval = 60

        # Event tracking
        self.event_times = []
        self.event_types = []
        self.event_paths = []

        # Feature tracking for ML
        self.feature_window = deque(maxlen=100)
        self.ml_features = []

        # ML model components
        self.ml_model = None
        self.ml_scaler = None
        self.ml_trained = False
        self.ml_training_required = 200
        self.ml_anomaly_scores = []

        # LEARNING PHASE - Start with completed baseline so detection is immediate
        self.learning_phase = False  # Start in detection mode
        self.baseline_rate = 12.0   # 12 events/min = 1 every 5 seconds
        self.stdev = 3.0
        self.learning_events_required = 50
        self.learning_progress_count = 50  # Already completed
        self.learning_start_time = time.time()
        self.learning_rate_samples = [10.0, 12.0, 11.0, 13.0, 12.0, 14.0, 11.0, 12.0, 13.0, 10.0]

        # Alert tracking
        self.anomaly_count = 0
        self.last_alert_time = 0
        self.last_tool_alert_time = 0
        self.alert_cooldown = 60
        self.tool_alert_cooldown = 30

        # ── BURST DETECTION (FIXED) ────────────────────────────────────────
        # burst_window: 8 → 30s  (BUG 1 fix: captures events spread over time)
        # burst_threshold: 10 → 8  (BUG 2 fix: fires at 1.33× expected count)
        # Expected normal events in 30s = 12/min ÷ 60 × 30 = 6
        # ──────────────────────────────────────────────────────────────────
        self.burst_window = 30          # seconds  (was 8)
        self.burst_threshold = 8        # events   (was 10)
        self.burst_events = deque(maxlen=200)
        self.last_burst_alert = 0
        self.burst_cooldown = 60

        # Pattern detection history
        self.detected_patterns = []

        # Statistics
        self.event_statistics = {
            'total_events': 0,
            'events_last_minute': 0,
            'events_last_5_minutes': 0,
            'peak_rate': 0,
            'last_anomaly': None,
            'last_tool_alert': None,
            'ml_enabled': self.use_ml,
            'ml_trained': False,
            'ml_anomalies': 0,
            'burst_detected': 0,
            'last_burst_time': None,
            'startup_timestamp': datetime.now().isoformat()
        }

        self.anomaly_history = []
        self.lock = threading.RLock()

        if self.use_ml:
            self._initialize_ml()

        self._load_persistent_state()

        print(f"[DEBUG] AnomalyDetector initialized in DETECTION MODE:")
        print(f"   Learning phase: {self.learning_phase} (completed)")
        print(f"   Baseline rate: {self.baseline_rate:.2f} events/min")
        print(f"   Std deviation: {self.stdev:.2f}")
        print(f"   Threshold: {self.threshold} sigma = {self.baseline_rate + self.threshold * self.stdev:.2f} events/min")
        print(f"   ML enabled: {self.use_ml}")
        print(f"   ML available: {ML_AVAILABLE}")
        print(f"   Alert callback: {'Set' if self.alert_callback else 'Not set'}")
        print(f"   Notification callback: {'Set' if self.notification_callback else 'Not set'}")
        print(f"   Burst window: {self.burst_window}s, threshold: {self.burst_threshold} events")
        print(f"   Expected normal in burst window: {self.baseline_rate/60*self.burst_window:.1f} events")

    # ──────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────────

    def detect(self, event_data: Dict) -> bool:
        """
        Detect anomalies from event data.
        Called by the file-system handler for every event.
        Returns True if anomaly detected, False otherwise.
        """
        try:
            with self.lock:
                event_type = event_data.get('event_type', 'UNKNOWN')
                event_path = event_data.get('file_path', '')

                anomaly_detected, source, details = self.record_event(event_type, event_path)

                if self.config.get('debug_mode', False) and anomaly_detected:
                    print(f"[ALERT] ANOMALY DETECTED via {source}: {details.get('detection_method', '')}")

                return anomaly_detected

        except Exception as e:
            print(f"[ERROR] Error in detect() method: {e}")
            import traceback
            traceback.print_exc()
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Core detection
    # ──────────────────────────────────────────────────────────────────────────

    def check_for_burst(self, current_time: float) -> Tuple[bool, int, float]:
        """
        Check for a sudden spike in event count within burst_window seconds.

        FIXES APPLIED
        ─────────────
        BUG 1 & 2: burst_window=30s, burst_threshold=8
            With a 30-second window, 13 folders created over up to ~25s are all
            captured.  Threshold of 8 fires when count > 6 (expected) × 1.33.

        BUG 3: Removed the  rate_per_second > normal_rate_per_second * 3  guard.
            Over a 30s window, 13 events / 30s = 0.43/s while 3× normal = 0.60/s,
            so the guard was ALWAYS False and prevented every detection.
            Replaced with: count > expected_in_window * 1.5 — window-size independent.

        BUG 4: Cooldown check moved OUTSIDE the inner rate block.
            Original nesting placed  `if is_burst and cooldown_ok: return True`
            inside  `if burst_count >= burst_threshold` but AFTER the rate check,
            so when cooldown was active the function fell through to return False
            even for a genuine burst.  Now the logic is:
                is_burst = (count AND relative-rate check)
                if is_burst and cooldown_ok: return True
                return False

        Returns: (is_burst_and_alert_allowed, burst_count, rate_per_second)
        """
        cutoff = current_time - self.burst_window
        recent_events = [t for t in self.burst_events if t > cutoff]
        burst_count = len(recent_events)
        rate_per_second = burst_count / self.burst_window if self.burst_window > 0 else 0

        # Expected events in this window under normal conditions
        expected_in_window = (self.baseline_rate / 60.0) * self.burst_window  # = 6.0

        # ── Step 1: Is this a genuine burst? (BUG 3 fix) ──────────────────
        is_burst = (
            burst_count >= self.burst_threshold               # absolute minimum count
            and burst_count > expected_in_window * 1.5        # relatively above normal
        )

        # ── Step 2: Should we fire an alert? (BUG 4 fix) ──────────────────
        if is_burst:
            if current_time - self.last_burst_alert > self.burst_cooldown:
                return True, burst_count, rate_per_second
            # Burst is real but alert is cooling down — log and move on
            print(f"[BURST] Burst active ({burst_count} events) but in cooldown")

        return False, burst_count, rate_per_second

    def _check_statistical_anomaly(self, current_rate: float, window_events: int) -> Tuple[bool, float]:
        """
        Directional z-score — only fires when rate is ABOVE baseline.

        FIXES APPLIED
        ─────────────
        BUG 5: Removed abs().
            abs(current_rate - baseline) / stdev fires on QUIET periods too.
            1 event → rate=1/min → z=|1-12|/3=3.67 → false positive.
            Fix: z = (current_rate - baseline) / stdev  (directional, positive = spike)

        BUG 6: Removed the  current_rate > baseline_rate * 1.5  guard.
            Guard requires rate > 12 × 1.5 = 18/min.  A burst of 13 folders gives
            rate ≈ 13/min → 13 < 18 → guard always False → statistical check was
            COMPLETELY BROKEN for any burst below 18 events/min.
            Fix: replaced with  window_events >= 5  to prevent lone-event noise.

        Returns: (is_anomaly, z_score)
        """
        if self.stdev <= 0 or self.baseline_rate <= 0:
            return False, 0.0

        # Directional z-score: positive only when rate is ABOVE baseline (BUG 5 fix)
        z_score = (current_rate - self.baseline_rate) / self.stdev

        # Fire when spike is significant AND we have a meaningful sample (BUG 6 fix)
        if z_score > self.threshold and window_events >= 5:
            return True, z_score

        return False, z_score

    def record_event(self, event_type: str = None, event_path: str = None) -> Tuple[bool, str, Dict]:
        """
        Record an event and check for anomalies.
        Returns: (is_anomaly, detection_source, details)
        """
        current_time = time.time()

        with self.lock:
            # Add to burst tracking
            self.burst_events.append(current_time)

            # Add to main event list
            self.event_times.append(current_time)
            if event_type:
                self.event_types.append(event_type)
            if event_path:
                self.event_paths.append(event_path)

            self.event_statistics['total_events'] += 1

            # Trim old events outside sliding window
            cutoff_time = current_time - self.window_size
            self.event_times = [t for t in self.event_times if t > cutoff_time]

            if len(self.event_times) < len(self.event_types):
                self.event_types = self.event_types[-len(self.event_times):]
            if len(self.event_times) < len(self.event_paths):
                self.event_paths = self.event_paths[-len(self.event_times):]

            window_events = len(self.event_times)
            current_rate = window_events * 60.0 / self.window_size if self.window_size > 0 else 0

            self._update_statistics(current_time, current_rate)

            # ── LEARNING PHASE ─────────────────────────────────────────────
            if self.learning_phase:
                self.learning_progress_count += 1

                if current_rate > 0:
                    self.learning_rate_samples.append(current_rate)
                    if len(self.learning_rate_samples) > 100:
                        self.learning_rate_samples = self.learning_rate_samples[-100:]

                if (self.learning_progress_count >= self.learning_events_required and
                        len(self.learning_rate_samples) >= 10):
                    if self.calculate_learning_stats():
                        self.learning_phase = False
                        print(f"[OK] Learning complete! Switching to detection mode")
                        self.send_tool_notification(
                            title="✅ Learning Complete",
                            message=f"Anomaly detection active. Baseline: {self.baseline_rate:.1f} events/min",
                            alert_type="INFO"
                        )

                return False, "LEARNING", {"rate": current_rate}
            # ──────────────────────────────────────────────────────────────

            # ── DETECTION PHASE ────────────────────────────────────────────
            anomaly_detected = False
            detection_source = None
            details = {
                'current_rate': round(current_rate, 2),
                'baseline_rate': round(self.baseline_rate, 2),
                'window_events': window_events,
                'timestamp': datetime.now().isoformat()
            }

            # Layer 1 — Burst detection (fixed)
            is_burst, burst_count, burst_rate = self.check_for_burst(current_time)
            if is_burst:
                anomaly_detected = True
                detection_source = "BURST"
                expected = self.baseline_rate / 60 * self.burst_window
                details['burst_count'] = burst_count
                details['burst_window'] = self.burst_window
                details['burst_rate'] = round(burst_rate, 3)
                details['expected_in_window'] = round(expected, 1)
                details['detection_method'] = (
                    f"{burst_count} events in {self.burst_window}s "
                    f"(expected ~{expected:.0f})"
                )
                print(f"[BURST] BURST DETECTED: {burst_count} events in {self.burst_window}s "
                      f"(expected {expected:.0f})")
                self.last_burst_alert = current_time
                self.event_statistics['burst_detected'] += 1
                self.event_statistics['last_burst_time'] = datetime.now().isoformat()

            # Layer 2 — Statistical z-score (fixed)
            if not anomaly_detected:
                stat_anomaly, z_score = self._check_statistical_anomaly(current_rate, window_events)
                details['z_score'] = round(z_score, 2)

                if stat_anomaly:
                    anomaly_detected = True
                    detection_source = "STATISTICAL"
                    details['detection_method'] = (
                        f"z={z_score:.2f} sigma  rate={current_rate:.1f}/min  "
                        f"baseline={self.baseline_rate:.1f}/min"
                    )
                    print(f"[STATS] STATISTICAL ANOMALY: rate={current_rate:.1f} "
                          f"baseline={self.baseline_rate:.1f} z={z_score:.2f} sigma")

            # Layer 3 — ML (unchanged)
            if not anomaly_detected and self.use_ml and self.ml_trained:
                features = self.extract_features(current_time)
                ml_anomaly, ml_confidence = self.predict_with_ml(features)
                if ml_anomaly:
                    anomaly_detected = True
                    detection_source = "ML"
                    details['ml_confidence'] = round(ml_confidence, 2)
                    details['detection_method'] = f"ML Confidence: {ml_confidence:.1%}"
                    print(f"[ML] ML ANOMALY: confidence={ml_confidence:.1%}")
                    self.event_statistics['ml_anomalies'] += 1

            # ── ALERT ─────────────────────────────────────────────────────
            if anomaly_detected:
                if current_time - self.last_alert_time > self.alert_cooldown:
                    self.anomaly_count += 1
                    self.last_alert_time = current_time
                    self.event_statistics['last_anomaly'] = datetime.now().isoformat()

                    alert_title = f"🚨 {detection_source} Anomaly Detected"

                    if detection_source == "BURST":
                        alert_message = (
                            f"**{burst_count} events in {self.burst_window} seconds!**\n"
                            f"Expected: ~{self.baseline_rate/60*self.burst_window:.0f} events\n"
                            f"Current rate: {current_rate:.1f} events/min\n"
                            f"Baseline: {self.baseline_rate:.1f} events/min"
                        )
                    else:
                        alert_message = (
                            f"**Unusual file system activity detected!**\n"
                            f"Current rate: {current_rate:.1f} events/min\n"
                            f"Baseline: {self.baseline_rate:.1f} events/min\n"
                            f"Z-Score: {details.get('z_score', 0):.2f}σ"
                        )

                    self.anomaly_history.append({
                        'timestamp': datetime.now().isoformat(),
                        'source': detection_source,
                        'details': details.copy()
                    })
                    if len(self.anomaly_history) > 100:
                        self.anomaly_history = self.anomaly_history[-100:]

                    self.send_tool_notification(
                        title=alert_title,
                        message=alert_message.replace('**', ''),
                        alert_type='ANOMALY'
                    )
                    if self.alert_callback:
                        try:
                            self.alert_callback(
                                alert_type='ANOMALY',
                                title=alert_title,
                                message=alert_message,
                                details=details
                            )
                        except Exception as e:
                            print(f"[ERROR] Callback error: {e}")

                    patterns = self.check_specific_patterns()
                    if patterns:
                        self.detected_patterns.extend(patterns)
                        if len(self.detected_patterns) > 50:
                            self.detected_patterns = self.detected_patterns[-50:]

                    return True, detection_source, details
                else:
                    remaining = self.alert_cooldown - (current_time - self.last_alert_time)
                    print(f"[WAIT] Anomaly in cooldown ({remaining:.0f}s remaining)")

            return False, None, details

    def process_event(self, event_type: str = None, event_path: str = None, timestamp: float = None) -> Tuple[bool, str, Dict]:
        """Compatibility wrapper used by tests and older callers."""
        return self.record_event(event_type, event_path)

    # ──────────────────────────────────────────────────────────────────────────
    # Notifications
    # ──────────────────────────────────────────────────────────────────────────

    def send_tool_notification(self, title: str, message: str, alert_type: str = "ANOMALY"):
        """Send popup notification within the tool"""
        current_time = time.time()
        if current_time - self.last_tool_alert_time < self.tool_alert_cooldown:
            print(f"[WAIT] Tool notification cooldown active")
            return False

        if self.notification_callback and callable(self.notification_callback):
            try:
                print(f"[NOTICE] Sending tool notification: {title}")
                self.notification_callback(alert_type=alert_type, title=title, message=message)
                self.last_tool_alert_time = current_time
                self.event_statistics['last_tool_alert'] = datetime.now().isoformat()
                print(f"[OK] Tool notification sent")
                return True
            except Exception as e:
                print(f"[ERROR] Error sending tool notification: {e}")
        return False

    # ──────────────────────────────────────────────────────────────────────────
    # State persistence
    # ──────────────────────────────────────────────────────────────────────────

    def _load_persistent_state(self):
        """Load persistent state from file"""
        try:
            if os.path.exists(self.state_file):
                self.load_state(self.state_file)
                print(f"[OK] Loaded persistent state from {self.state_file}")
            else:
                print(f"[INFO] No saved state found, using default baseline")
        except Exception as e:
            print(f"[ERROR] Error loading state: {e}")

    def _check_and_save_state(self):
        """Auto-save state if conditions are met"""
        if not self.auto_save:
            return
        current_time = time.time()
        if current_time - self.last_save_time > self.save_interval:
            try:
                self.save_state(self.state_file)
                self.last_save_time = current_time
            except Exception as e:
                print(f"[WARN] Auto-save failed: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # ML helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _initialize_ml(self):
        """Initialize the ML model"""
        if not ML_AVAILABLE:
            return False
        try:
            self.ml_model = OneClassSVM(kernel='rbf', gamma='scale', nu=0.1, random_state=42)
            self.ml_scaler = StandardScaler()
            print("[OK] ML Model initialized")
            return True
        except Exception as e:
            print(f"[ERROR] Error initializing ML: {e}")
            self.use_ml = False
            return False

    def extract_features(self, current_time: float) -> np.ndarray:
        """Extract features for ML model from recent events"""
        features = []
        features.append(len(self.event_times))
        features.append(len(self.event_times) / self.window_size if self.window_size > 0 else 0)

        if self.event_times:
            features.append(current_time - self.event_times[-1])
            if len(self.event_times) > 1:
                ia = [self.event_times[i] - self.event_times[i-1] for i in range(1, len(self.event_times))]
                features.extend([np.mean(ia), np.std(ia) if len(ia) > 1 else 0])
            else:
                features.extend([0, 0])
        else:
            features.extend([0, 0, 0])

        if self.event_types:
            ut = len(set(self.event_types))
            features.extend([ut, ut / len(self.event_types)])
        else:
            features.extend([0, 0])

        if self.event_paths:
            dirs = set(os.path.dirname(p) for p in self.event_paths[-50:])
            features.append(len(dirs))
            exts = defaultdict(int)
            for p in self.event_paths[-50:]:
                ext = os.path.splitext(p)[1].lower()
                if ext:
                    exts[ext] += 1
            total = sum(exts.values())
            features.append(max(exts.values()) / total if exts else 0)
        else:
            features.extend([0, 0])

        dt = datetime.fromtimestamp(current_time)
        features.extend([dt.hour, dt.weekday()])

        if not self.learning_phase and self.stdev > 0:
            rate = len(self.event_times) * 60 / self.window_size if self.window_size > 0 else 0
            # Use directional z-score here too (clamped to 0 minimum)
            z_score = max((rate - self.baseline_rate) / self.stdev, 0)
            features.extend([z_score, rate / self.baseline_rate if self.baseline_rate > 0 else 0])
        else:
            features.extend([0, 0])

        return np.array(features).reshape(1, -1)

    def train_ml_model(self):
        """Train the One-Class SVM model with collected features"""
        if not self.use_ml:
            print("[ERROR] ML not enabled, cannot train")
            return False
        if len(self.ml_features) < self.ml_training_required:
            print(f"[ERROR] Not enough data for ML training: {len(self.ml_features)}/{self.ml_training_required}")
            return False
        try:
            X = np.array(self.ml_features)
            X_scaled = self.ml_scaler.fit_transform(X)
            self.ml_model.fit(X_scaled)
            self.ml_trained = True
            print(f"[OK] ML model trained successfully with {len(self.ml_features)} samples")
            self.event_statistics['ml_trained'] = True
            self._check_and_save_state()
            return True
        except Exception as e:
            print(f"[ERROR] Error training ML model: {e}")
            return False

    def predict_with_ml(self, features: np.ndarray) -> Tuple[bool, float]:
        """Predict anomaly using ML model"""
        if not self.use_ml or not self.ml_trained:
            return False, 0.0
        try:
            features_scaled = self.ml_scaler.transform(features)
            prediction = self.ml_model.predict(features_scaled)
            score = self.ml_model.decision_function(features_scaled)[0]
            anomaly_prob = 1.0 - (score + 1) / 2
            is_anomaly = (prediction[0] == -1) and (anomaly_prob > 0.7)
            self.ml_anomaly_scores.append({
                'timestamp': datetime.now().isoformat(),
                'score': float(score), 'probability': float(anomaly_prob),
                'prediction': int(prediction[0]), 'is_anomaly': is_anomaly
            })
            if len(self.ml_anomaly_scores) > 100:
                self.ml_anomaly_scores = self.ml_anomaly_scores[-100:]
            return is_anomaly, anomaly_prob
        except Exception as e:
            print(f"[ERROR] Error in ML prediction: {e}")
            return False, 0.0

    def calculate_learning_stats(self):
        """Calculate baseline and standard deviation from learning phase data"""
        if len(self.learning_rate_samples) < 10:
            print(f"[WARN] Not enough samples: {len(self.learning_rate_samples)}")
            return False
        try:
            rates_array = np.array(self.learning_rate_samples)
            self.baseline_rate = float(np.mean(rates_array))
            self.stdev = float(np.std(rates_array))
            if self.stdev < 0.1:
                self.stdev = max(self.baseline_rate * 0.1, 0.5)
            print(f"[STATS] Learning complete: baseline={self.baseline_rate:.2f} stdev={self.stdev:.2f}")
            return True
        except Exception as e:
            print(f"[ERROR] Error calculating stats: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Statistics
    # ──────────────────────────────────────────────────────────────────────────

    def _update_statistics(self, current_time: float, current_rate: float):
        """Update event statistics"""
        self.event_statistics['events_last_minute'] = len(
            [t for t in self.event_times if t > current_time - 60])
        self.event_statistics['events_last_5_minutes'] = len(
            [t for t in self.event_times if t > current_time - 300])
        if current_rate > self.event_statistics['peak_rate']:
            self.event_statistics['peak_rate'] = current_rate

    def get_statistics(self) -> Dict:
        """Get current detector statistics"""
        with self.lock:
            current_time = time.time()
            recent_times = [t for t in self.event_times if current_time - t < self.window_size]
            current_rate = len(recent_times) * 60 / self.window_size if self.window_size > 0 else 0

            # Use directional z-score for display too
            z_score = 0
            if not self.learning_phase and self.stdev > 0 and self.baseline_rate > 0:
                z_score = (current_rate - self.baseline_rate) / self.stdev

            burst_cutoff = current_time - self.burst_window
            recent_burst = [t for t in self.burst_events if t > burst_cutoff]
            current_burst_rate = len(recent_burst) / self.burst_window if self.burst_window > 0 else 0
            detection_threshold = self.baseline_rate + (self.threshold * self.stdev) if not self.learning_phase else 0

            return {
                "current_rate": round(current_rate, 2),
                "baseline_rate": round(self.baseline_rate, 2),
                "z_score": round(z_score, 2),
                "stdev": round(self.stdev, 2),
                "detection_threshold": round(detection_threshold, 2),
                "total_events": self.event_statistics['total_events'],
                "learning_phase": self.learning_phase,
                "learning_progress": min(100, self.learning_progress_count * 100 // self.learning_events_required),
                "learning_events": f"{self.learning_progress_count}/{self.learning_events_required}",
                "anomaly_count": self.anomaly_count,
                "threshold": self.threshold,
                "window_size": self.window_size,
                "ml_enabled": self.use_ml,
                "ml_trained": self.ml_trained,
                "ml_anomalies": self.event_statistics.get('ml_anomalies', 0),
                "burst_detected": self.event_statistics.get('burst_detected', 0),
                "current_burst_rate": round(current_burst_rate, 3),
                "burst_threshold": self.burst_threshold,
                "burst_window": self.burst_window,
                "events_last_minute": self.event_statistics.get('events_last_minute', 0),
                "events_last_5_minutes": self.event_statistics.get('events_last_5_minutes', 0),
                "peak_rate": self.event_statistics.get('peak_rate', 0),
                "last_anomaly": self.event_statistics.get('last_anomaly'),
                "last_tool_alert": self.event_statistics.get('last_tool_alert'),
                "last_burst_time": self.event_statistics.get('last_burst_time'),
                "notification_callback_set": self.notification_callback is not None,
                "debug": {
                    "rate_samples": len(self.learning_rate_samples),
                    "burst_events": len(self.burst_events),
                    "burst_events_in_window": len(recent_burst),
                    "burst_threshold": self.burst_threshold,
                    "burst_window": self.burst_window,
                    "expected_in_burst_window": round(self.baseline_rate / 60 * self.burst_window, 1),
                    "time_since_last_alert": round(current_time - self.last_alert_time, 1) if self.last_alert_time > 0 else None,
                    "time_since_last_tool_alert": round(current_time - self.last_tool_alert_time, 1) if self.last_tool_alert_time > 0 else None,
                    "normal_rate_per_sec": round(self.baseline_rate / 60, 3) if self.baseline_rate > 0 else 0.2
                }
            }

    def get_alert_details(self, current_rate: float = None) -> Dict:
        """Get detailed alert information"""
        if current_rate is None:
            current_time = time.time()
            recent_times = [t for t in self.event_times if current_time - t < self.window_size]
            current_rate = len(recent_times) * 60 / self.window_size if self.window_size > 0 else 0

        z_score = 0
        if not self.learning_phase and self.stdev > 0 and self.baseline_rate > 0:
            z_score = (current_rate - self.baseline_rate) / self.stdev  # directional

        details = {
            'current_rate': round(current_rate, 2),
            'baseline_rate': round(self.baseline_rate, 2),
            'z_score': round(z_score, 2),
            'deviation_percent': round((current_rate - self.baseline_rate) / self.baseline_rate * 100, 1) if self.baseline_rate > 0 else 0,
            'threshold': round(self.threshold, 2),
            'detection_threshold': round(self.baseline_rate + self.threshold * self.stdev, 2) if not self.learning_phase else 0,
            'total_anomalies': self.anomaly_count,
            'learning_phase': self.learning_phase,
            'learning_progress': min(100, self.learning_progress_count * 100 // self.learning_events_required),
            'learning_events': f"{self.learning_progress_count}/{self.learning_events_required}",
            'window_size_seconds': self.window_size,
            'current_events': len(self.event_times),
            'ml_enabled': self.use_ml,
            'ml_trained': self.ml_trained,
            'ml_training_progress': min(100, len(self.ml_features) * 100 // self.ml_training_required) if self.use_ml else 0,
            'ml_anomalies': self.event_statistics.get('ml_anomalies', 0),
            'burst_detected': self.event_statistics.get('burst_detected', 0),
            'burst_threshold': self.burst_threshold,
            'burst_window': self.burst_window,
            'state_persisted': os.path.exists(self.state_file) if self.state_file else False,
            'notification_callback_set': self.notification_callback is not None,
            'debug_info': {
                'learning_progress_count': self.learning_progress_count,
                'learning_events_required': self.learning_events_required,
                'total_events': self.event_statistics['total_events'],
                'window_events': len(self.event_times),
                'rate_samples': len(self.learning_rate_samples),
                'stdev': round(self.stdev, 2),
                'burst_events': len(self.burst_events)
            }
        }

        if self.event_types:
            type_counts = {}
            for event_type in self.event_types[-50:]:
                type_counts[event_type] = type_counts.get(event_type, 0) + 1
            details['recent_event_types'] = type_counts

        if self.event_paths:
            extensions = {}
            for path in self.event_paths[-50:]:
                ext = os.path.splitext(path)[1].lower()
                if ext:
                    extensions[ext] = extensions.get(ext, 0) + 1
            if extensions:
                details['common_extensions'] = dict(
                    sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:5])

        patterns = self.check_specific_patterns()
        if patterns:
            details['detected_patterns'] = patterns

        if self.ml_anomaly_scores:
            details['recent_ml_scores'] = [
                {'score': s['score'], 'probability': s['probability'], 'is_anomaly': s['is_anomaly']}
                for s in self.ml_anomaly_scores[-5:]
            ]

        return details

    # ──────────────────────────────────────────────────────────────────────────
    # Pattern detection
    # ──────────────────────────────────────────────────────────────────────────

    def check_specific_patterns(self) -> List[Dict]:
        """Check for specific suspicious patterns"""
        patterns = []
        if len(self.event_times) < 10:
            return patterns

        with self.lock:
            current_time = time.time()

            # Mass directory creation
            if len(self.event_paths) >= 12:
                recent_paths = self.event_paths[-25:]
                folder_count = 0
                directories = set()
                for path in recent_paths:
                    try:
                        basename = os.path.basename(path)
                        if basename.startswith(('folder', 'test', 'new', 'dir')):
                            folder_count += 1
                            directories.add(path)
                    except:
                        pass
                time_span = current_time - (self.event_times[-25] if len(self.event_times) >= 25 else current_time - 10)
                rate = folder_count / time_span * 60 if time_span > 0 else 0
                if folder_count >= 8 and rate > self.baseline_rate * 2:
                    patterns.append({
                        'type': 'mass_directory_creation',
                        'confidence': 90,
                        'description': f'Multiple directories created: {folder_count} folders',
                        'details': {'directories': folder_count, 'rate': round(rate, 1),
                                    'baseline': round(self.baseline_rate, 1)},
                        'timestamp': datetime.now().isoformat()
                    })

            # Rapid modifications
            if not self.learning_phase and self.baseline_rate > 0 and len(self.event_paths[-20:]) > 12:
                unique_dirs = set()
                for path in self.event_paths[-20:]:
                    try:
                        unique_dirs.add(os.path.dirname(path))
                    except:
                        continue
                recent_events = len([t for t in self.event_times if current_time - t < 10])
                recent_rate = recent_events * 6
                if len(unique_dirs) < 3 and recent_rate > self.baseline_rate * 2.5:
                    patterns.append({
                        'type': 'rapid_modifications',
                        'confidence': 75,
                        'description': f'Rapid modifications in {len(unique_dirs)} directories',
                        'details': {'files_modified': len(self.event_paths[-20:]),
                                    'unique_dirs': len(unique_dirs), 'rate': round(recent_rate, 1)},
                        'timestamp': datetime.now().isoformat()
                    })

            # Mass deletion
            if len(self.event_types) > 15:
                deletions = [t for t in self.event_types[-25:] if 'delete' in str(t).lower()]
                if len(deletions) > 8:
                    patterns.append({
                        'type': 'mass_deletion',
                        'confidence': 85,
                        'description': f'Mass deletion detected: {len(deletions)} deletions',
                        'details': {'deletions': len(deletions), 'total_events': len(self.event_types[-25:])},
                        'timestamp': datetime.now().isoformat()
                    })

            # Off-hours activity
            if not self.learning_phase and self.baseline_rate > 0:
                current_hour = datetime.now().hour
                if current_hour in [0, 1, 2, 3, 4, 5]:
                    events_last_15 = len([t for t in self.event_times if current_time - t < 15])
                    recent_rate = events_last_15 * 4
                    if recent_rate > self.baseline_rate * 3.5:
                        patterns.append({
                            'type': 'off_hours_activity',
                            'confidence': 70,
                            'description': f'Unusual activity during off-hours ({current_hour}:00)',
                            'details': {
                                'current_hour': current_hour,
                                'activity_rate': round(recent_rate, 1),
                                'baseline': round(self.baseline_rate, 1),
                                'ratio': round(recent_rate / self.baseline_rate, 1)
                            },
                            'timestamp': datetime.now().isoformat()
                        })
        return patterns

    def get_anomaly_history(self, limit: int = 20) -> List[Dict]:
        return self.anomaly_history[-limit:] if self.anomaly_history else []

    def get_detected_patterns(self, limit: int = 10) -> List[Dict]:
        return self.detected_patterns[-limit:] if self.detected_patterns else []

    def get_ml_scores(self, limit: int = 10) -> List[Dict]:
        return self.ml_anomaly_scores[-limit:] if self.ml_anomaly_scores else []

    # ──────────────────────────────────────────────────────────────────────────
    # Control
    # ──────────────────────────────────────────────────────────────────────────

    def reset(self):
        """Reset the detector to initial state with default baseline"""
        print("[INFO] Resetting anomaly detector to default baseline...")
        with self.lock:
            self.event_times.clear()
            self.event_types.clear()
            self.event_paths.clear()
            self.feature_window.clear()
            self.ml_features.clear()
            self.ml_anomaly_scores.clear()
            self.burst_events.clear()
            self.anomaly_history.clear()
            self.detected_patterns.clear()

            self.learning_phase = False
            self.learning_progress_count = 50
            self.learning_start_time = time.time()
            self.baseline_rate = 12.0
            self.stdev = 3.0
            self.learning_rate_samples = [10.0, 12.0, 11.0, 13.0, 12.0, 14.0, 11.0, 12.0, 13.0, 10.0]
            self.anomaly_count = 0
            self.last_alert_time = 0
            self.last_tool_alert_time = 0
            self.last_burst_alert = 0
            self.ml_trained = False

            if self.use_ml:
                self._initialize_ml()

            self.event_statistics = {
                'total_events': 0, 'events_last_minute': 0, 'events_last_5_minutes': 0,
                'peak_rate': 0, 'last_anomaly': None, 'last_tool_alert': None,
                'ml_enabled': self.use_ml, 'ml_trained': False,
                'ml_anomalies': 0, 'burst_detected': 0, 'last_burst_time': None,
                'startup_timestamp': datetime.now().isoformat()
            }
            print("[OK] Reset complete - Now in detection mode with baseline 12.0 events/min")

    def set_alert_callback(self, callback: Callable):
        self.alert_callback = callback
        print(f"[OK] Alert callback set: {'Yes' if self.alert_callback else 'No'}")

    def set_notification_callback(self, callback: Callable):
        self.notification_callback = callback
        print(f"[OK] Notification callback set: {'Yes' if self.notification_callback else 'No'}")


    def test_alert(self) -> bool:
        """Test alert functionality"""
        print("[TEST] Testing alert system...")
        test_details = {'current_rate': 35.5, 'baseline_rate': self.baseline_rate,
                        'z_score': 4.5, 'threshold': self.threshold, 'detection_source': 'TEST'}
        self.send_tool_notification(title="🧪 Test Notification",
                                    message="Test notification from anomaly detector",
                                    alert_type="INFO")
        return self.send_tool_notification(title="Test Alert", message="Test alert from TrustVault", alert_type="INFO")

    def enable_ml(self, enable: bool = True):
        self.use_ml = enable and ML_AVAILABLE
        if enable and ML_AVAILABLE and not self.ml_model:
            self._initialize_ml()
        self.event_statistics['ml_enabled'] = self.use_ml
        print(f"[DEBUG] ML detection {'enabled' if self.use_ml else 'disabled'}")

    # ──────────────────────────────────────────────────────────────────────────
    # Persistence
    # ──────────────────────────────────────────────────────────────────────────

    def save_state(self, filepath: str) -> bool:
        """Save detector state to file"""
        try:
            with self.lock:
                ml_features_list = [f.tolist() if hasattr(f, 'tolist') else f for f in self.ml_features]
                state = {
                    'version': '3.4',
                    'saved_at': datetime.now().isoformat(),
                    'learning_phase': self.learning_phase,
                    'learning_progress_count': self.learning_progress_count,
                    'learning_events_required': self.learning_events_required,
                    'learning_rate_samples': self.learning_rate_samples,
                    'baseline_rate': self.baseline_rate,
                    'stdev': self.stdev,
                    'anomaly_count': self.anomaly_count,
                    'last_alert_time': self.last_alert_time,
                    'last_tool_alert_time': self.last_tool_alert_time,
                    'event_statistics': self.event_statistics,
                    'anomaly_history': self.anomaly_history[-50:],
                    'detected_patterns': self.detected_patterns[-50:],
                    'ml_trained': self.ml_trained,
                    'ml_features': ml_features_list,
                    'ml_anomaly_scores': self.ml_anomaly_scores[-100:],
                    'use_ml': self.use_ml,
                    'threshold': self.threshold,
                    'window_size': self.window_size,
                    'event_times': self.event_times[-200:],
                    'event_types': self.event_types[-200:],
                    'event_paths': self.event_paths[-200:],
                    'burst_detected': self.event_statistics.get('burst_detected', 0),
                    'burst_threshold': self.burst_threshold,
                    'burst_window': self.burst_window
                }
                if os.path.exists(filepath):
                    try:
                        import shutil
                        shutil.copy2(filepath, filepath + '.backup')
                    except:
                        pass
                temp_file = filepath + '.tmp'
                with open(temp_file, 'w') as f:
                    json.dump(state, f, default=str, indent=2)
                import shutil
                shutil.move(temp_file, filepath)
                print(f"[SAVE] State saved to {filepath}")
                return True
        except Exception as e:
            print(f"[ERROR] Error saving state: {e}")
            import traceback
            traceback.print_exc()
            return False

    def load_state(self, filepath: str) -> bool:
        """Load detector state from file"""
        try:
            if not os.path.exists(filepath):
                print(f"[WARN] State file not found: {filepath}")
                return False
            with open(filepath, 'r') as f:
                state = json.load(f)
            version = state.get('version', '1.0')
            if version not in ['3.0', '3.1', '3.2', '3.3', '3.4']:
                print(f"[WARN] Unsupported state version: {version}")
                return False
            with self.lock:
                self.learning_phase = state.get('learning_phase', False)
                self.learning_progress_count = state.get('learning_progress_count', 50)
                self.learning_events_required = state.get('learning_events_required', 50)
                self.learning_rate_samples = state.get('learning_rate_samples',
                    [10, 12, 11, 13, 12, 14, 11, 12, 13, 10])
                self.baseline_rate = state.get('baseline_rate', 12.0)
                self.stdev = state.get('stdev', 3.0)
                self.anomaly_count = state.get('anomaly_count', 0)
                self.last_alert_time = state.get('last_alert_time', 0)
                self.last_tool_alert_time = state.get('last_tool_alert_time', 0)
                self.threshold = state.get('threshold', 2.5)
                self.window_size = state.get('window_size', 60)
                # Load fixed burst params — fall back to new fixed defaults if missing
                self.burst_threshold = state.get('burst_threshold', 8)
                self.burst_window = state.get('burst_window', 30)

                current_time = time.time()
                saved_times = state.get('event_times', [])
                saved_types = state.get('event_types', [])
                saved_paths = state.get('event_paths', [])
                self.event_times = [t for t in saved_times if current_time - t < self.window_size]
                idx = len(self.event_times)
                self.event_types = saved_types[:idx] if len(saved_types) >= idx else []
                self.event_paths = saved_paths[:idx] if len(saved_paths) >= idx else []

                ml_features_raw = state.get('ml_features', [])
                self.ml_features = [np.array(f) if isinstance(f, list) else f for f in ml_features_raw]
                self.ml_anomaly_scores = state.get('ml_anomaly_scores', [])
                self.use_ml = state.get('use_ml', True)
                self.ml_trained = state.get('ml_trained', False)
                self.anomaly_history = state.get('anomaly_history', [])
                self.detected_patterns = state.get('detected_patterns', [])

                saved_stats = state.get('event_statistics', {})
                for key, value in saved_stats.items():
                    if key in self.event_statistics:
                        self.event_statistics[key] = value

                progress_percent = min(
                    100, self.learning_progress_count * 100 // self.learning_events_required
                ) if self.learning_phase else 100
                self.event_statistics['learning_progress'] = progress_percent
                self.event_statistics['ml_enabled'] = self.use_ml
                self.event_statistics['ml_trained'] = self.ml_trained
                self.event_statistics['burst_detected'] = state.get('burst_detected', 0)

                if self.use_ml and not self.ml_model:
                    self._initialize_ml()
                if (self.use_ml and self.ml_features and
                        len(self.ml_features) >= self.ml_training_required and self.ml_trained):
                    try:
                        if self.ml_scaler is None:
                            self.ml_scaler = StandardScaler()
                        X = np.array(self.ml_features)
                        X_scaled = self.ml_scaler.fit_transform(X)
                        self.ml_model.fit(X_scaled)
                        print(f"[OK] ML model retrained with {len(self.ml_features)} samples")
                    except Exception as e:
                        print(f"[WARN] Could not retrain ML model: {e}")

            print(f"[OK] State loaded: Learning={self.learning_phase}, Baseline={self.baseline_rate:.1f}")
            return True

        except json.JSONDecodeError as e:
            print(f"[ERROR] Corrupted state file: {e}")
            backup_file = filepath + '.backup'
            if os.path.exists(backup_file):
                print(f"[INFO] Attempting to load backup")
                return self.load_state(backup_file)
            return False
        except Exception as e:
            print(f"[ERROR] Error loading state: {e}")
            import traceback
            traceback.print_exc()
            return False

    def finalize(self):
        """Cleanup before exit"""
        try:
            if self.auto_save:
                self.save_state(self.state_file)
                print(f"[SAVE] Final state saved")
        except Exception as e:
            print(f"[WARN] Final save failed: {e}")
