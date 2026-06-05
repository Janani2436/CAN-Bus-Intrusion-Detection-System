"""
attack_engine.py — CAN Bus Attack Simulator

Four attack classes, each exploiting a real CAN bus weakness.
Every attack maps to a real automotive cybersecurity threat vector.

Interview anchor:
  "I implemented four attack classes from the UNECE WP.29 threat catalogue:
   replay, fuzzing, spoofing, and flooding. Each exploits a specific
   design weakness in CAN 2.0 — absence of authentication, no sequence
   numbers, no access control, and priority-based arbitration."
"""

import time
import random
import struct
import threading
import logging
from typing import List, Optional
from simulator.can_frame import CANFrame

logger = logging.getLogger(__name__)


class BaseAttack:
    """Base class for all attack types."""

    def __init__(self, name: str, target_id: int):
        self.name = name
        self.target_id = target_id
        self.frames_injected = 0
        self._active = False

    def generate_frame(self) -> Optional[CANFrame]:
        raise NotImplementedError

    def run_burst(self, bus, count: int, interval: float = 0.001):
        """Inject 'count' attack frames onto the bus."""
        self._active = True
        injected = 0
        for _ in range(count):
            if not self._active:
                break
            frame = self.generate_frame()
            if frame and bus.inject_frame(frame):
                injected += 1
                self.frames_injected += 1
            time.sleep(interval)
        self._active = False
        logger.info(f"[{self.name}] Burst complete: {injected} frames injected")
        return injected

    def stop(self):
        self._active = False


# =============================================================================
# ATTACK 1 — REPLAY ATTACK
# =============================================================================

class ReplayAttack(BaseAttack):
    """
    Replay Attack — capture and retransmit legitimate CAN frames.

    Real-world scenario:
      Attacker connects to OBD-II port, sniffs the door-unlock command
      (e.g. from key fob via Body Control Module), stores it, disconnects.
      Later, attacker replays the exact frame to unlock the car remotely.

    Why it works:
      CAN has NO timestamps, NO sequence numbers, NO session tokens.
      A frame from 10 minutes ago is indistinguishable from a fresh one.
      The receiving ECU has no way to know the message is stale.

    Real incident: Relay attacks on keyless entry systems use this exact
    principle — they amplify the key fob signal and replay it at the door.

    IDS detection strategy:
      - Identical frame (same ID + same payload) appearing repeatedly
      - Frame appearing outside its normal time window
      - Statistical duplicate detection
    """

    def __init__(self, captured_frames: Optional[List[CANFrame]] = None):
        super().__init__("ReplayAttack", target_id=0x4B0)  # Body Control default
        self._captured_frames: List[CANFrame] = captured_frames or []
        self._replay_index = 0

        # If no frames provided, create a realistic door-unlock capture
        if not self._captured_frames:
            self._captured_frames = self._create_default_capture()

    def _create_default_capture(self) -> List[CANFrame]:
        """
        Simulate a captured door-unlock sequence.
        In a real attack, these would come from sniffing the actual bus.
        Byte 1 of Body Control = lock status (0x00 = all unlocked)
        """
        frames = []
        for _ in range(5):
            # Door unlock command: lock byte = 0x00 (all unlocked)
            unlock_frame = CANFrame(
                arbitration_id=0x4B0,
                data=bytes([0x00,  # doors: all closed
                             0x00,  # locks: ALL UNLOCKED  ← the attack payload
                             0x0F,  # windows: up
                             0x00,  # lights: off
                             0x00, 0x00, 0x00, 0x00]),
                source_ecu="ReplayAttack"
            )
            frames.append(unlock_frame)
        logger.info(f"[ReplayAttack] Loaded {len(frames)} captured frames")
        return frames

    def capture_from_bus(self, bus, duration_seconds: float = 2.0,
                          filter_id: Optional[int] = None):
        """
        Capture real frames from the bus for later replay.
        This simulates the sniffing phase of the attack.
        """
        captured = []
        end_time = time.time() + duration_seconds

        def capture_listener(frame: CANFrame):
            if filter_id is None or frame.arbitration_id == filter_id:
                if not frame.is_injected:
                    captured.append(frame)

        bus.add_listener(capture_listener)
        logger.info(f"[ReplayAttack] Sniffing bus for {duration_seconds}s...")
        time.sleep(duration_seconds)

        self._captured_frames = captured[:20]  # Store up to 20 frames
        logger.info(f"[ReplayAttack] Captured {len(self._captured_frames)} frames")
        return len(self._captured_frames)

    def generate_frame(self) -> Optional[CANFrame]:
        """Replay the next captured frame."""
        if not self._captured_frames:
            return None

        # Cycle through captured frames
        original = self._captured_frames[self._replay_index % len(self._captured_frames)]
        self._replay_index += 1

        # Replay: same ID, same payload, but fresh timestamp (injected now)
        return CANFrame(
            arbitration_id=original.arbitration_id,
            data=original.data,
            source_ecu="ReplayAttack",
            is_injected=True
        )


# =============================================================================
# ATTACK 2 — FUZZING ATTACK
# =============================================================================

class FuzzingAttack(BaseAttack):
    """
    Fuzzing Attack — send malformed/random payloads to target ECUs.

    Real-world scenario:
      Attacker targets the Brake ECU or Steering ECU with random byte
      sequences. Goal: find payloads that cause unexpected ECU behaviour —
      crash the ECU firmware, trigger false sensor readings, or cause
      the ECU to enter a fail-safe mode that disables braking.

    Why it works:
      ECU firmware often lacks input validation on CAN payloads.
      If the firmware reads byte 0 as brake pressure without range-checking,
      value 0xFF (255) × 4 = 1020 kPa — maximum emergency braking.
      Injecting this at highway speed could lock all wheels.

    Real incident: Charlie Miller & Chris Valasek (2015 Jeep Cherokee hack)
      used crafted CAN messages to control brakes and steering remotely.

    IDS detection strategy:
      - Payload values outside normal engineering ranges
      - Sudden signal jumps (RPM going from 800 to 65535 in one frame)
      - Statistical outlier detection on payload bytes
    """

    # Target ECUs for fuzzing — safety-critical ones
    FUZZ_TARGETS = {
        'brakes':   {'id': 0x1A0, 'dlc': 7},
        'steering': {'id': 0x2B0, 'dlc': 7},
        'engine':   {'id': 0x0C0, 'dlc': 7},
    }

    def __init__(self, target: str = 'brakes',
                 strategy: str = 'random'):
        """
        Args:
            target: Which ECU to fuzz ('brakes', 'steering', 'engine')
            strategy: 'random' | 'boundary' | 'bitflip'
              - random:   completely random bytes
              - boundary: values at min/max boundaries (0x00, 0xFF)
              - bitflip:  flip individual bits in a valid frame
        """
        target_info = self.FUZZ_TARGETS.get(target, self.FUZZ_TARGETS['brakes'])
        super().__init__(f"FuzzingAttack[{target}]", target_id=target_info['id'])
        self.dlc = target_info['dlc']
        self.strategy = strategy
        self._base_payload = bytes([0x00] * self.dlc)
        logger.info(f"[FuzzingAttack] Target: {target} (ID=0x{self.target_id:03X}), strategy={strategy}")

    def generate_frame(self) -> CANFrame:
        """Generate a fuzzed frame based on the chosen strategy."""
        if self.strategy == 'random':
            payload = self._fuzz_random()
        elif self.strategy == 'boundary':
            payload = self._fuzz_boundary()
        elif self.strategy == 'bitflip':
            payload = self._fuzz_bitflip()
        else:
            payload = self._fuzz_random()

        return CANFrame(
            arbitration_id=self.target_id,
            data=payload,
            source_ecu="FuzzingAttack",
            is_injected=True
        )

    def _fuzz_random(self) -> bytes:
        """Completely random payload — maximum chaos."""
        return bytes([random.randint(0, 255) for _ in range(self.dlc)])

    def _fuzz_boundary(self) -> bytes:
        """
        Boundary value fuzzing — tests ECU input validation.
        Alternates between 0x00 (min) and 0xFF (max) in each byte.
        This is how professional fuzzing tools like CANToolz work.
        """
        payload = []
        for i in range(self.dlc):
            # Each byte cycles through: 0x00, 0xFF, 0x01, 0xFE, 0x7F, 0x80
            boundary_vals = [0x00, 0xFF, 0x01, 0xFE, 0x7F, 0x80]
            payload.append(random.choice(boundary_vals))
        return bytes(payload)

    def _fuzz_bitflip(self) -> bytes:
        """
        Bit-flip fuzzing — take a valid frame and flip random bits.
        More realistic than pure random — tests edge cases near valid values.
        """
        payload = bytearray(self._base_payload)
        # Flip 1–3 random bits
        num_flips = random.randint(1, 3)
        for _ in range(num_flips):
            byte_idx = random.randint(0, len(payload) - 1)
            bit_idx = random.randint(0, 7)
            payload[byte_idx] ^= (1 << bit_idx)
        return bytes(payload)


# =============================================================================
# ATTACK 3 — SPOOFING ATTACK
# =============================================================================

class SpoofingAttack(BaseAttack):
    """
    Spoofing Attack — impersonate a legitimate ECU with false data.

    Real-world scenario:
      Attacker sends frames with the Engine ECU's ID (0x0C0) but with
      a crafted payload showing RPM = 0 (engine stalled) while the car
      is moving. The dashboard, transmission, and cruise control all
      act on this false data. Or: spoof the speed sensor to prevent
      the airbag from deploying in a crash.

    Why it works:
      CAN has no sender authentication. The arbitration ID identifies
      the MESSAGE TYPE, not the sender. Any node can send any ID.
      The receiving ECU cannot distinguish a real Engine ECU frame
      from an attacker's frame with the same ID.

    Real attack: The 2015 Jeep Cherokee attack spoofed the steering
      ECU to turn the wheel while the driver was on the highway.

    IDS detection strategy:
      - Two nodes transmitting the same ID simultaneously (causes errors)
      - Payload values inconsistent with physical reality
        (RPM=0 while speed=100 km/h is physically impossible)
      - Message rate doubling for a specific ID
    """

    # Predefined spoof scenarios
    SPOOF_SCENARIOS = {
        'engine_stall': {
            'id': 0x0C0,
            'payload': bytes([0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0x00]),
            'desc': 'Report engine RPM=0 (fake stall)'
        },
        'engine_redline': {
            'id': 0x0C0,
            'payload': bytes([0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0x01, 0x00]),
            'desc': 'Report engine RPM=16383 (redline)'
        },
        'brake_release': {
            'id': 0x1A0,
            'payload': bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            'desc': 'Report brakes fully released (no pressure)'
        },
        'full_lock': {
            'id': 0x4B0,
            'payload': bytes([0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00]),
            'desc': 'Unlock all doors remotely'
        },
        'max_steering': {
            'id': 0x2B0,
            'payload': bytes([0x7F, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00]),
            'desc': 'Spoof maximum steering angle (hard left)'
        },
    }

    def __init__(self, scenario: str = 'engine_stall'):
        scenario_data = self.SPOOF_SCENARIOS.get(
            scenario, self.SPOOF_SCENARIOS['engine_stall']
        )
        super().__init__(f"SpoofingAttack[{scenario}]",
                         target_id=scenario_data['id'])
        self._payload = scenario_data['payload']
        self._desc = scenario_data['desc']
        logger.info(f"[SpoofingAttack] Scenario: {self._desc}")

    def generate_frame(self) -> CANFrame:
        """Generate a spoofed frame impersonating the target ECU."""
        return CANFrame(
            arbitration_id=self.target_id,
            data=self._payload,
            source_ecu="SpoofingAttack",
            is_injected=True
        )


# =============================================================================
# ATTACK 4 — FLOODING / BUS SATURATION ATTACK
# =============================================================================

class FloodingAttack(BaseAttack):
    """
    Flooding / Bus Saturation Attack — Denial of Service.

    Real-world scenario:
      Attacker floods the bus with ID 0x000 (highest priority) at maximum
      rate. Since CAN arbitration is priority-based (lower ID wins),
      ID 0x000 wins every single arbitration contest. All other ECUs
      keep losing arbitration and retrying — they never get bus access.
      Safety-critical messages (ABS=0x1A0, airbag) are silenced.

    Why it works:
      CAN arbitration is non-destructive but deterministic — lower ID
      always wins. There's no rate limiting or fairness mechanism.
      Any node can monopolise the bus by sending continuously at low ID.

    Consequence:
      At 500 kbps, max frame rate ≈ 5000 frames/sec.
      Flooding at 1000 fps with ID 0x000 consumes 20% of bandwidth.
      At 5000 fps it consumes 100% — complete DoS.

    IDS detection strategy:
      - Total bus frame rate exceeding expected maximum
      - Single ID dominating frame count (>50% of all frames)
      - Known ECUs going silent (no frames from their IDs)
    """

    def __init__(self, flood_id: int = 0x000,
                 payload: Optional[bytes] = None):
        """
        Args:
            flood_id: CAN ID to use for flooding. 0x000 = highest priority.
            payload: Fixed payload. None = random bytes each frame.
        """
        super().__init__("FloodingAttack", target_id=flood_id)
        self._fixed_payload = payload
        logger.info(
            f"[FloodingAttack] Target ID=0x{flood_id:03X} "
            f"({'highest priority!' if flood_id == 0 else 'custom priority'})"
        )

    def generate_frame(self) -> CANFrame:
        """Generate a flood frame. Random or fixed payload."""
        payload = self._fixed_payload or bytes(
            [random.randint(0, 255) for _ in range(8)]
        )
        return CANFrame(
            arbitration_id=self.target_id,
            data=payload,
            source_ecu="FloodingAttack",
            is_injected=True
        )

    def run_continuous(self, bus, duration_seconds: float = 5.0,
                        rate_fps: int = 500):
        """
        Flood the bus continuously at a given frame rate.
        This runs in the current thread — use threading for parallel operation.
        """
        self._active = True
        interval = 1.0 / rate_fps
        end_time = time.time() + duration_seconds
        injected = 0

        logger.info(
            f"[FloodingAttack] Starting flood: {rate_fps} fps "
            f"for {duration_seconds}s"
        )
        while time.time() < end_time and self._active:
            frame = self.generate_frame()
            if bus.inject_frame(frame):
                injected += 1
                self.frames_injected += 1
            time.sleep(interval)

        self._active = False
        logger.info(f"[FloodingAttack] Flood complete: {injected} frames injected")
        return injected


# =============================================================================
# ATTACK ORCHESTRATOR — runs attack scenarios for demo/testing
# =============================================================================

class AttackOrchestrator:
    """
    Coordinates multiple attacks against the CAN bus.
    Used in demo mode and for generating labelled training data for the IDS.

    Interview anchor:
      "The orchestrator runs attacks sequentially with configurable timing,
       generating ground-truth labels (is_injected=True) on every malicious
       frame. This lets me measure IDS detection accuracy precisely."
    """

    def __init__(self, bus):
        self.bus = bus
        self.attack_log = []  # Records of each attack run

    def run_all_attacks(self, verbose: bool = True) -> dict:
        """Run all four attack types sequentially. Returns attack summary."""
        results = {}

        if verbose:
            print("\n" + "="*55)
            print("  ATTACK ENGINE — Running all 4 attack scenarios")
            print("="*55)

        # --- Attack 1: Replay ---
        if verbose:
            print("\n[1/4] Replay Attack (door unlock)")
        replay = ReplayAttack()
        count = replay.run_burst(self.bus, count=20, interval=0.05)
        results['replay'] = count
        if verbose:
            print(f"      Injected {count} replay frames (ID=0x4B0)")
        time.sleep(0.5)

        # --- Attack 2: Fuzzing ---
        if verbose:
            print("\n[2/4] Fuzzing Attack (brake ECU)")
        fuzz = FuzzingAttack(target='brakes', strategy='boundary')
        count = fuzz.run_burst(self.bus, count=30, interval=0.02)
        results['fuzzing'] = count
        if verbose:
            print(f"      Injected {count} fuzz frames (ID=0x1A0)")
        time.sleep(0.5)

        # --- Attack 3: Spoofing ---
        if verbose:
            print("\n[3/4] Spoofing Attack (engine stall)")
        spoof = SpoofingAttack(scenario='engine_stall')
        count = spoof.run_burst(self.bus, count=25, interval=0.01)
        results['spoofing'] = count
        if verbose:
            print(f"      Injected {count} spoof frames (ID=0x0C0)")
        time.sleep(0.5)

        # --- Attack 4: Flooding ---
        if verbose:
            print("\n[4/4] Flooding Attack (bus saturation, 3s)")
        flood = FloodingAttack(flood_id=0x000)
        count = flood.run_continuous(self.bus, duration_seconds=3.0, rate_fps=200)
        results['flooding'] = count
        if verbose:
            print(f"      Injected {count} flood frames (ID=0x000)")

        total = sum(results.values())
        if verbose:
            print(f"\n  Total attack frames injected: {total}")
            print("="*55)

        return results