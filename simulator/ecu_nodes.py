"""
ecu_nodes.py — Virtual ECU implementations

Each class simulates one Electronic Control Unit in a vehicle.
Each ECU has:
  - A fixed CAN ID it broadcasts on
  - Internal state (sensor values)  
  - A realistic update rate (how often it sends)
  - Signal encoding logic (how real values map to bytes)

Interview anchor:
  "I modelled each ECU as a state machine — internal vehicle state updates
   at the ECU's real-world cycle time, then encodes signals into CAN bytes
   using the same bit-packing rules a real DBC file would specify."

Real-world update rates (from automotive standards):
  - Powertrain (engine, brake): 10ms  — safety-critical, fast
  - Chassis (steering, suspension): 10–20ms
  - Body (doors, windows): 100–500ms — comfort, slow is fine
"""

import time
import random
import math
import struct
from abc import ABC, abstractmethod
from typing import Optional
from simulator.can_frame import CANFrame


class BaseECU(ABC):
    """
    Abstract base class for all simulated ECUs.

    Every ECU on a real CAN bus has:
      - One or more CAN IDs it owns
      - A fixed transmission period (cycle time)
      - Internal state representing sensor/actuator values
    """

    def __init__(self, name: str, can_id: int, cycle_time_ms: float):
        self.name = name
        self.can_id = can_id
        self.cycle_time_ms = cycle_time_ms          # How often this ECU broadcasts
        self._last_tx_time: float = 0.0             # Last transmission timestamp
        self._message_count: int = 0

    @abstractmethod
    def _update_state(self) -> None:
        """Update internal ECU state (sensor simulation)."""
        pass

    @abstractmethod
    def _encode_payload(self) -> bytes:
        """
        Encode internal state into CAN data bytes.
        This mirrors how a real ECU firmware encodes signals.
        """
        pass

    def should_transmit(self) -> bool:
        """Return True if enough time has passed for next transmission."""
        now = time.time()
        elapsed_ms = (now - self._last_tx_time) * 1000
        return elapsed_ms >= self.cycle_time_ms

    def generate_frame(self) -> Optional[CANFrame]:
        """
        Generate a CAN frame if it's time to transmit.
        Returns None if within cycle time (not yet due).
        """
        if not self.should_transmit():
            return None

        self._update_state()
        payload = self._encode_payload()
        self._last_tx_time = time.time()
        self._message_count += 1

        return CANFrame(
            arbitration_id=self.can_id,
            data=payload,
            timestamp=time.time(),
            source_ecu=self.name
        )

    def force_generate_frame(self) -> CANFrame:
        """Generate a frame immediately, ignoring cycle time. Used in testing."""
        self._update_state()
        payload = self._encode_payload()
        self._last_tx_time = time.time()
        self._message_count += 1
        return CANFrame(
            arbitration_id=self.can_id,
            data=payload,
            timestamp=time.time(),
            source_ecu=self.name
        )


# =============================================================================
# POWERTRAIN ECUs — safety-critical, 10ms cycle
# =============================================================================

class EngineECU(BaseECU):
    """
    Engine Control Unit (ECU/PCM).
    CAN ID: 0x0C0 — highest priority powertrain message.

    Signals encoded in 8 bytes:
      Bytes 0–1: Engine RPM      (uint16, factor 0.25, range 0–16383 RPM)
      Byte  2:   Throttle pos    (uint8,  factor 0.4,  range 0–100%)
      Byte  3:   Engine temp °C  (uint8,  offset -40,  range -40 to 215°C)
      Byte  4:   Engine load %   (uint8,  factor 0.4)
      Byte  5:   Ignition status (bit 0=on, bit 1=cranking)
      Bytes 6–7: Reserved / padding

    Interview anchor: "RPM is encoded as uint16 with a 0.25 scaling factor —
    so raw value 4000 means 1000 RPM. This is standard DBC signal encoding."
    """

    def __init__(self):
        super().__init__("EngineECU", can_id=0x0C0, cycle_time_ms=10)
        # Initial state — engine warming up
        self.rpm: float = 800.0          # idle RPM
        self.throttle: float = 5.0       # percent
        self.coolant_temp: float = 25.0  # Celsius
        self.engine_load: float = 10.0   # percent
        self.ignition_on: bool = True
        self._running_time: float = 0.0

    def _update_state(self) -> None:
        """Simulate realistic engine state over time."""
        self._running_time += self.cycle_time_ms / 1000.0

        # Engine warms up over first 120 seconds
        if self.coolant_temp < 90:
            self.coolant_temp = min(90, self.coolant_temp + 0.05)

        # RPM fluctuates around idle with occasional revs
        base_rpm = 800
        variation = 30 * math.sin(self._running_time * 0.3)
        noise = random.gauss(0, 15)
        self.rpm = max(600, min(7000, base_rpm + variation + noise))

        # Throttle correlates with RPM deviation from idle
        self.throttle = max(0, min(100,
            5 + (self.rpm - 800) / 80 + random.gauss(0, 0.5)
        ))

        # Load tracks throttle
        self.engine_load = max(0, min(100,
            self.throttle * 1.1 + random.gauss(0, 1)
        ))

    def _encode_payload(self) -> bytes:
        """Encode engine signals into 8 CAN data bytes."""
        # RPM: uint16, raw = RPM / 0.25 = RPM * 4
        rpm_raw = int(min(65535, max(0, self.rpm * 4)))

        # Throttle: uint8, raw = throttle% / 0.4
        throttle_raw = int(min(255, max(0, self.throttle / 0.4)))

        # Coolant temp: uint8, offset -40 → raw = temp + 40
        temp_raw = int(min(255, max(0, self.coolant_temp + 40)))

        # Engine load: uint8, raw = load% / 0.4
        load_raw = int(min(255, max(0, self.engine_load / 0.4)))

        # Ignition byte: bit 0 = ignition on
        ignition_raw = 0x01 if self.ignition_on else 0x00

        return struct.pack('>HBBBBB',
            rpm_raw,        # bytes 0–1 (big-endian uint16)
            throttle_raw,   # byte 2
            temp_raw,       # byte 3
            load_raw,       # byte 4
            ignition_raw,   # byte 5
            0x00            # byte 6: reserved
        )

    @staticmethod
    def decode_payload(data: bytes) -> dict:
        """Decode raw CAN bytes back into engineering values."""
        if len(data) < 6:
            return {}
        rpm_raw, throttle_raw, temp_raw, load_raw, ignition_raw, _ = struct.unpack('>HBBBBB', data[:7])
        return {
            'rpm': rpm_raw * 0.25,
            'throttle_pct': throttle_raw * 0.4,
            'coolant_temp_c': temp_raw - 40,
            'engine_load_pct': load_raw * 0.4,
            'ignition_on': bool(ignition_raw & 0x01)
        }


class BrakeECU(BaseECU):
    """
    Brake Control Module / ABS ECU.
    CAN ID: 0x1A0 — safety-critical.

    Signals:
      Byte 0:   Master cylinder pressure (uint8, factor 4, range 0–1020 kPa)
      Byte 1:   ABS active flags (bit per wheel: FL FR RL RR)
      Bytes 2–3: Vehicle speed (uint16, factor 0.01, km/h)
      Byte 4:   Brake pedal switch (bit 0)
      Bytes 5–7: Reserved
    """

    def __init__(self):
        super().__init__("BrakeECU", can_id=0x1A0, cycle_time_ms=10)
        self.brake_pressure: float = 0.0    # kPa
        self.abs_active: int = 0x00         # bitmask
        self.vehicle_speed: float = 0.0     # km/h
        self.brake_pedal: bool = False
        self._speed_trend: float = 0.0

    def _update_state(self) -> None:
        """Simulate vehicle in gentle motion with occasional braking."""
        # Speed slowly increases then decreases (drive cycle simulation)
        self._speed_trend += random.gauss(0, 0.3)
        self._speed_trend = max(-2, min(2, self._speed_trend))
        self.vehicle_speed = max(0, min(120,
            self.vehicle_speed + self._speed_trend + random.gauss(0, 0.1)
        ))

        # Occasional brake events
        if random.random() < 0.02:  # 2% chance per cycle
            self.brake_pedal = not self.brake_pedal

        if self.brake_pedal:
            self.brake_pressure = min(800, self.brake_pressure + random.gauss(20, 5))
        else:
            self.brake_pressure = max(0, self.brake_pressure - random.gauss(15, 3))

        # ABS activates at high pressure + non-zero speed
        if self.brake_pressure > 600 and self.vehicle_speed > 20:
            self.abs_active = random.randint(0x01, 0x0F)
        else:
            self.abs_active = 0x00

    def _encode_payload(self) -> bytes:
        pressure_raw = int(min(255, max(0, self.brake_pressure / 4)))
        speed_raw = int(min(65535, max(0, self.vehicle_speed / 0.01)))
        pedal_raw = 0x01 if self.brake_pedal else 0x00
        return struct.pack('>BBHBBB',
            pressure_raw,
            self.abs_active,
            speed_raw,
            pedal_raw,
            0x00, 0x00
        )


class SteeringECU(BaseECU):
    """
    Electric Power Steering ECU.
    CAN ID: 0x2B0

    Signals:
      Bytes 0–1: Steering angle (int16, factor 0.1 degrees, range ±780°)
      Byte  2:   Steering torque (uint8, factor 0.5 Nm)
      Byte  3:   EPS status flags
      Bytes 4–7: Reserved
    """

    def __init__(self):
        super().__init__("SteeringECU", can_id=0x2B0, cycle_time_ms=10)
        self.steering_angle: float = 0.0    # degrees (-780 to +780)
        self.torque: float = 0.0            # Nm
        self._angle_velocity: float = 0.0

    def _update_state(self) -> None:
        """Simulate gentle lane changes and straight-line driving."""
        # Smooth steering angle changes (low-pass filtered random walk)
        self._angle_velocity += random.gauss(0, 0.5)
        self._angle_velocity *= 0.92  # damping
        self.steering_angle = max(-780, min(780,
            self.steering_angle + self._angle_velocity
        ))
        # Centre tends to pull back (like real EPS)
        self.steering_angle -= self.steering_angle * 0.005

        # Torque correlates with angle
        self.torque = max(0, abs(self.steering_angle) * 0.02 + random.gauss(0, 0.1))

    def _encode_payload(self) -> bytes:
        # Steering angle: int16, raw = angle / 0.1 (signed)
        angle_raw = int(max(-32768, min(32767, self.steering_angle / 0.1)))
        torque_raw = int(min(255, max(0, self.torque / 0.5)))
        eps_status = 0x01  # EPS active
        return struct.pack('>hBBBBB',
            angle_raw,
            torque_raw,
            eps_status,
            0x00, 0x00, 0x00
        )


class BodyControlECU(BaseECU):
    """
    Body Control Module (BCM).
    CAN ID: 0x4B0 — low priority, comfort functions.

    Signals:
      Byte 0: Door status (bits: FL FR RL RR open/closed)
      Byte 1: Lock status (bits: FL FR RL RR locked)
      Byte 2: Window positions (bits: FL FR RL RR fully up)
      Byte 3: Interior lights
      Bytes 4–7: Reserved
    """

    def __init__(self):
        super().__init__("BodyControlECU", can_id=0x4B0, cycle_time_ms=100)
        self.door_status: int = 0x00    # 0 = all closed
        self.lock_status: int = 0x0F    # 0x0F = all locked
        self.window_status: int = 0x0F  # 0x0F = all fully up
        self.lights: int = 0x00

    def _update_state(self) -> None:
        """BCM state changes slowly — mostly stable."""
        # Very rare door events
        if random.random() < 0.001:
            bit = 1 << random.randint(0, 3)
            self.door_status ^= bit  # toggle a door

    def _encode_payload(self) -> bytes:
        return struct.pack('>BBBBBBBB',
            self.door_status,
            self.lock_status,
            self.window_status,
            self.lights,
            0x00, 0x00, 0x00, 0x00
        )


class TransmissionECU(BaseECU):
    """
    Transmission Control Module (TCM).
    CAN ID: 0x1F0

    Signals:
      Byte 0:   Gear position (0=P, 1=R, 2=N, 3=D, 4–9 = manual gears)
      Bytes 1–2: Output shaft speed (uint16, factor 0.1 RPM)
      Byte 3:   Torque converter lockup (bit 0)
      Bytes 4–7: Reserved
    """

    def __init__(self):
        super().__init__("TransmissionECU", can_id=0x1F0, cycle_time_ms=20)
        self.gear: int = 3          # Drive
        self.output_rpm: float = 0.0
        self.lockup: bool = False

    def _update_state(self) -> None:
        self.output_rpm = max(0, self.output_rpm + random.gauss(0, 5))
        self.lockup = self.output_rpm > 1200

    def _encode_payload(self) -> bytes:
        rpm_raw = int(min(65535, max(0, self.output_rpm / 0.1)))
        lockup_raw = 0x01 if self.lockup else 0x00
        return struct.pack('>BHBBBB',
            self.gear,
            rpm_raw,
            lockup_raw,
            0x00, 0x00, 0x00
        )