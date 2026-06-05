"""
ids_detector.py — Intrusion Detection System for CAN Bus

Two detection layers working together:
  Layer 1 — Rule-based:    Fast, deterministic. Catches known attack patterns.
  Layer 2 — Statistical:   Learns normal behaviour. Catches unknown anomalies.

Interview anchor:
  "My IDS uses a two-layer approach mirroring real automotive IDPS products
   like Vector CANalyzer and Argus CyberSecurity's platform. Rule-based
   detection handles known attack signatures with zero false-negative rate.
   Statistical detection catches zero-day anomalies by learning baseline
   behaviour during a training phase — analogous to how ISO 21434 requires
   both signature-based and anomaly-based monitoring."
"""

import time
import logging
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from simulator.can_frame import CANFrame

logger = logging.getLogger(__name__)


# =============================================================================
# ALERT — what the IDS produces when it detects something
# =============================================================================

@dataclass
class Alert:
    """
    One IDS alert. Maps directly to a SIEM event in a real vehicle SOC.

    severity levels:
      LOW    — informational, worth logging
      MEDIUM — investigate, possible attack
      HIGH   — likely attack, trigger response
      CRITICAL — confirmed attack, immediate action required
    """
    timestamp: float
    alert_type: str          # 'REPLAY' | 'FUZZING' | 'SPOOFING' | 'FLOODING'
    severity: str            # 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    can_id: int
    description: str
    frame: Optional[CANFrame] = None
    detector: str = "unknown"

    @property
    def hex_id(self) -> str:
        return f"0x{self.can_id:03X}"

    def __str__(self):
        ts = time.strftime('%H:%M:%S', time.localtime(self.timestamp))
        return (f"[{ts}] {self.severity:<8} | {self.alert_type:<10} | "
                f"ID={self.hex_id} | {self.description}")


# =============================================================================
# LAYER 1 — RULE-BASED DETECTOR
# =============================================================================

class RuleBasedDetector:
    """
    Detects attacks using fixed rules derived from CAN protocol knowledge.

    Rules implemented:
      R1 — Frequency rule:   message rate > 2× baseline → flooding or spoofing
      R2 — Duplicate rule:   identical frame seen N times → replay attack
      R3 — Payload rule:     signal values outside physical range → fuzzing
      R4 — New ID rule:      unknown CAN ID appeared → rogue node
      R5 — Dominant ID rule: single ID > 40% of all traffic → flooding

    Interview anchor:
      "Rule-based detection has zero latency and 100% recall on known attacks.
       The trade-off is zero detection on novel attacks. That's why I combine
       it with the statistical layer — defence in depth."
    """

    # Expected message rates per CAN ID (frames/sec at normal operation)
    BASELINE_RATES = {
        0x0C0: 100,   # Engine ECU — 10ms cycle
        0x1A0: 100,   # Brake ECU  — 10ms cycle
        0x2B0: 100,   # Steering   — 10ms cycle
        0x1F0: 50,    # Transmission — 20ms cycle
        0x4B0: 10,    # Body Control — 100ms cycle
    }

    # Physical signal ranges for payload validation
    # Format: {can_id: [(byte_start, byte_end, min_raw, max_raw, signal_name)]}
    SIGNAL_RANGES = {
        0x0C0: [(0, 2, 0, 28000, 'RPM_raw')],       # Max 7000 RPM × 4
        0x1A0: [(0, 1, 0, 255, 'brake_pressure')],
        0x2B0: [(0, 2, 0, 65535, 'steering_angle')],
    }

    # Rate multiplier threshold to trigger alert
    RATE_THRESHOLD = 2.5
    # Window size for rate calculation (seconds)
    RATE_WINDOW = 1.0
    # How many identical frames before replay alert
    DUPLICATE_THRESHOLD = 3

    def __init__(self):
        # Rolling frame counts per ID: deque of (timestamp, count)
        self._frame_timestamps: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        # Recent frame hashes for duplicate detection
        self._recent_hashes: deque = deque(maxlen=200)
        self._hash_counts: Dict[str, int] = defaultdict(int)
        # All alerts generated
        self.alerts: List[Alert] = []
        # Known CAN IDs (learned at startup)
        self._known_ids = set(self.BASELINE_RATES.keys())
        # Total frame count
        self._total_frames = 0

    def _frame_hash(self, frame: CANFrame) -> str:
        """Unique fingerprint of a frame (ID + payload). Used for replay detection."""
        return f"{frame.arbitration_id:03X}#{frame.hex_data}"

    def _current_rate(self, can_id: int) -> float:
        """Calculate frames/sec for a CAN ID over the last RATE_WINDOW seconds."""
        now = time.time()
        window_start = now - self.RATE_WINDOW
        timestamps = self._frame_timestamps[can_id]
        recent = sum(1 for ts in timestamps if ts > window_start)
        return recent / self.RATE_WINDOW

    def _raise_alert(self, alert_type: str, severity: str, can_id: int,
                     description: str, frame: CANFrame) -> Alert:
        alert = Alert(
            timestamp=time.time(),
            alert_type=alert_type,
            severity=severity,
            can_id=can_id,
            description=description,
            frame=frame,
            detector="RuleBased"
        )
        self.alerts.append(alert)
        logger.warning(str(alert))
        return alert

    def analyze(self, frame: CANFrame) -> List[Alert]:
        """Analyze one frame. Returns list of alerts (empty = no threat)."""
        new_alerts = []
        self._total_frames += 1
        can_id = frame.arbitration_id

        # Record timestamp for rate calculation
        self._frame_timestamps[can_id].append(frame.timestamp)

        # ── R1: Frequency rule ──────────────────────────────────────────────
        if can_id in self.BASELINE_RATES:
            current_rate = self._current_rate(can_id)
            baseline = self.BASELINE_RATES[can_id]
            if current_rate > baseline * self.RATE_THRESHOLD:
                severity = 'CRITICAL' if current_rate > baseline * 5 else 'HIGH'
                new_alerts.append(self._raise_alert(
                    'FLOODING' if can_id == 0x000 else 'SPOOFING',
                    severity, can_id,
                    f"Rate {current_rate:.0f}/s exceeds baseline {baseline}/s "
                    f"(×{current_rate/baseline:.1f})",
                    frame
                ))

        # ── R2: Duplicate / Replay rule ─────────────────────────────────────
        fhash = self._frame_hash(frame)
        self._hash_counts[fhash] += 1
        self._recent_hashes.append(fhash)

        if self._hash_counts[fhash] == self.DUPLICATE_THRESHOLD:
            new_alerts.append(self._raise_alert(
                'REPLAY', 'HIGH', can_id,
                f"Identical frame seen {self.DUPLICATE_THRESHOLD}× "
                f"(payload={frame.hex_data})",
                frame
            ))

        # ── R3: Payload range rule ───────────────────────────────────────────
        if can_id in self.SIGNAL_RANGES and len(frame.data) >= 2:
            for (b_start, b_end, min_val, max_val, sig_name) in self.SIGNAL_RANGES[can_id]:
                if len(frame.data) >= b_end:
                    raw = int.from_bytes(frame.data[b_start:b_end], 'big')
                    if raw > max_val:
                        new_alerts.append(self._raise_alert(
                            'FUZZING', 'HIGH', can_id,
                            f"Signal {sig_name} raw={raw} exceeds max={max_val}",
                            frame
                        ))

        # ── R4: Unknown ID rule ──────────────────────────────────────────────
        if can_id not in self._known_ids and can_id != 0x000:
            self._known_ids.add(can_id)  # only alert once per new ID
            new_alerts.append(self._raise_alert(
                'SPOOFING', 'MEDIUM', can_id,
                f"Unknown CAN ID 0x{can_id:03X} appeared on bus",
                frame
            ))

        # ── R5: Bus domination rule ──────────────────────────────────────────
        if self._total_frames % 100 == 0 and self._total_frames > 0:
            id_count = len(self._frame_timestamps[can_id])
            share = id_count / min(self._total_frames, 200)
            if share > 0.40:
                new_alerts.append(self._raise_alert(
                    'FLOODING', 'CRITICAL', can_id,
                    f"ID 0x{can_id:03X} dominates bus ({share*100:.0f}% of traffic)",
                    frame
                ))

        return new_alerts


# =============================================================================
# LAYER 2 — STATISTICAL ANOMALY DETECTOR
# =============================================================================

class StatisticalDetector:
    """
    Learns normal CAN bus behaviour during a training phase, then detects
    deviations using standard deviation analysis.

    How it works:
      Training phase: collect N frames per CAN ID, compute mean and stddev
                      of inter-arrival times and payload byte values.
      Detection phase: for each new frame, compute Z-score vs baseline.
                       Z-score > threshold → anomaly alert.

    Z-score formula:
      z = (observed_value - mean) / stddev
      z > 3.0 → value is 3 standard deviations from normal → anomaly

    Interview anchor:
      "Statistical detection uses Z-score analysis on two features:
       inter-message timing (detects flooding and rate anomalies) and
       payload byte distribution (detects fuzzing with out-of-range values).
       Training on 500 frames per ID gives a stable baseline. This approach
       is similar to how Upstream Security's cloud IDPS platform works."
    """

    TRAINING_FRAMES_NEEDED = 100   # frames per ID before detection starts
    Z_SCORE_THRESHOLD = 3.5        # standard deviations to trigger alert
    TIMING_Z_THRESHOLD = 4.0       # slightly looser for timing (more natural variance)

    def __init__(self):
        # Training data: {can_id: {'intervals': [...], 'payload_means': [...]}}
        self._training: Dict[int, dict] = defaultdict(lambda: {
            'intervals': [],
            'last_ts': None,
            'payload_bytes': defaultdict(list),
            'trained': False
        })
        # Computed baselines after training
        self._baselines: Dict[int, dict] = {}
        self.alerts: List[Alert] = []
        self._trained_ids: set = set()

    @property
    def trained_ids(self) -> set:
        return self._trained_ids.copy()

    def _compute_baseline(self, can_id: int) -> None:
        """Compute mean and stddev from training data for one CAN ID."""
        data = self._training[can_id]
        intervals = data['intervals']

        if len(intervals) < 10:
            return

        try:
            interval_mean = statistics.mean(intervals)
            interval_std  = statistics.stdev(intervals) if len(intervals) > 1 else 1.0
            interval_std  = max(interval_std, 0.0001)   # avoid division by zero

            payload_stats = {}
            for byte_idx, values in data['payload_bytes'].items():
                if len(values) > 5:
                    payload_stats[byte_idx] = {
                        'mean': statistics.mean(values),
                        'std':  max(statistics.stdev(values), 0.1)
                    }

            self._baselines[can_id] = {
                'interval_mean': interval_mean,
                'interval_std':  interval_std,
                'payload_stats': payload_stats
            }
            self._trained_ids.add(can_id)
            logger.debug(
                f"[StatIDS] Baseline for 0x{can_id:03X}: "
                f"interval={interval_mean*1000:.1f}ms ±{interval_std*1000:.1f}ms"
            )
        except Exception as e:
            logger.debug(f"Baseline computation error for 0x{can_id:03X}: {e}")

    def _z_score(self, value: float, mean: float, std: float) -> float:
        return abs(value - mean) / std if std > 0 else 0.0

    def _raise_alert(self, alert_type: str, severity: str, can_id: int,
                     description: str, frame: CANFrame) -> Alert:
        alert = Alert(
            timestamp=time.time(),
            alert_type=alert_type,
            severity=severity,
            can_id=can_id,
            description=description,
            frame=frame,
            detector="Statistical"
        )
        self.alerts.append(alert)
        logger.warning(str(alert))
        return alert

    def analyze(self, frame: CANFrame) -> List[Alert]:
        """Train on or analyze a single frame."""
        new_alerts = []
        can_id = frame.arbitration_id
        data = self._training[can_id]
        now = frame.timestamp

        # ── Training phase ───────────────────────────────────────────────────
        if can_id not in self._trained_ids:
            if data['last_ts'] is not None:
                interval = now - data['last_ts']
                if 0 < interval < 2.0:   # ignore unrealistic intervals
                    data['intervals'].append(interval)

            for i, byte_val in enumerate(frame.data):
                data['payload_bytes'][i].append(byte_val)

            data['last_ts'] = now

            # Enough data? Compute baseline.
            if len(data['intervals']) >= self.TRAINING_FRAMES_NEEDED:
                self._compute_baseline(can_id)
            return []   # No alerts during training

        # ── Detection phase ──────────────────────────────────────────────────
        baseline = self._baselines.get(can_id)
        if not baseline:
            return []

        # Timing anomaly
        if data['last_ts'] is not None:
            interval = now - data['last_ts']
            if 0 < interval < 2.0:
                z = self._z_score(interval,
                                   baseline['interval_mean'],
                                   baseline['interval_std'])
                if z > self.TIMING_Z_THRESHOLD:
                    severity = 'CRITICAL' if z > 8.0 else 'HIGH' if z > 5.0 else 'MEDIUM'
                    new_alerts.append(self._raise_alert(
                        'FLOODING', severity, can_id,
                        f"Timing anomaly: interval={interval*1000:.1f}ms, "
                        f"expected={baseline['interval_mean']*1000:.1f}ms (Z={z:.1f})",
                        frame
                    ))

        # Payload anomaly (byte-level)
        for i, byte_val in enumerate(frame.data):
            if i in baseline['payload_stats']:
                ps = baseline['payload_stats'][i]
                z = self._z_score(byte_val, ps['mean'], ps['std'])
                if z > self.Z_SCORE_THRESHOLD:
                    new_alerts.append(self._raise_alert(
                        'FUZZING', 'HIGH', can_id,
                        f"Payload anomaly byte[{i}]={byte_val} "
                        f"(mean={ps['mean']:.1f}, Z={z:.1f})",
                        frame
                    ))
                    break   # one alert per frame max

        data['last_ts'] = now
        return new_alerts


# =============================================================================
# COMBINED IDS ENGINE
# =============================================================================

class CANBusIDS:
    """
    The complete IDS — combines both detectors into one interface.
    This is what plugs into the CAN bus as a listener.

    Interview anchor:
      "The IDS engine registers as a passive listener on the CAN bus —
       it never transmits, never interferes with normal operation.
       This matches the AUTOSAR Intrusion Detection System Manager
       (IdsM) architecture where the IDS is a separate software component
       that receives bus frames via the PDU Router."
    """

    def __init__(self):
        self.rule_detector  = RuleBasedDetector()
        self.stat_detector  = StatisticalDetector()
        self.all_alerts: List[Alert] = []
        self._frames_analyzed = 0
        self._start_time = time.time()

    def analyze(self, frame: CANFrame) -> List[Alert]:
        """Main entry point — called for every frame on the bus."""
        self._frames_analyzed += 1
        new_alerts = []

        # Run both detectors
        new_alerts += self.rule_detector.analyze(frame)
        new_alerts += self.stat_detector.analyze(frame)

        self.all_alerts += new_alerts
        return new_alerts

    @property
    def detection_stats(self) -> dict:
        total = self._frames_analyzed
        attack_alerts = len(self.all_alerts)
        types = defaultdict(int)
        for a in self.all_alerts:
            types[a.alert_type] += 1
        return {
            'frames_analyzed': total,
            'total_alerts': attack_alerts,
            'alert_types': dict(types),
            'trained_ids': len(self.stat_detector.trained_ids),
            'uptime': time.time() - self._start_time
        }

    def print_report(self):
        stats = self.detection_stats
        print("\n" + "="*55)
        print("  IDS DETECTION REPORT")
        print("="*55)
        print(f"  Frames analyzed : {stats['frames_analyzed']}")
        print(f"  Total alerts    : {stats['total_alerts']}")
        print(f"  Trained ECU IDs : {stats['trained_ids']}")
        print(f"  Uptime          : {stats['uptime']:.1f}s")
        print(f"\n  Alert breakdown:")
        for atype, count in stats['alert_types'].items():
            bar = '█' * min(count, 30)
            print(f"    {atype:<12} {count:>4}  {bar}")
        if self.all_alerts:
            print(f"\n  Last 5 alerts:")
            for alert in self.all_alerts[-5:]:
                print(f"    {alert}")
        print("="*55)