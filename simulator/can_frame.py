"""
can_frame.py — Core CAN frame data structure

A CAN frame is the fundamental unit of communication on a CAN bus.
Every message any ECU sends becomes one of these.

Interview anchor:
  "I modelled the CAN frame as a Python dataclass mirroring the ISO 11898
   standard — 11-bit arbitration ID, up to 8 data bytes, timestamp, and
   source ECU label for simulation tracing."
"""

import time
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CANFrame:
    """
    Represents a single CAN 2.0A frame (standard, 11-bit ID).

    Fields mirror the physical frame structure:
      arbitration_id  — 11-bit identifier (0x000–0x7FF)
                        Lower value = higher bus priority
                        NOT a source address — CAN has no addressing
      data            — payload bytes, 0 to 8 bytes (classic CAN)
      timestamp       — Unix time when frame was created/captured
      is_extended_id  — False = standard 11-bit, True = 29-bit CAN 2.0B
      source_ecu      — simulation label only, not part of real CAN frame
      is_injected     — True if this frame was injected by the attack engine
    """

    arbitration_id: int                        # 11-bit: 0x000–0x7FF
    data: bytes = b''                          # 0–8 bytes payload
    timestamp: float = field(default_factory=time.time)
    is_extended_id: bool = False
    source_ecu: str = "unknown"
    is_injected: bool = False                  # ground truth for IDS evaluation

    def __post_init__(self):
        """Validate CAN frame constraints from ISO 11898."""
        # Arbitration ID must fit in 11 bits (standard) or 29 bits (extended)
        max_id = 0x1FFFFFFF if self.is_extended_id else 0x7FF
        if not (0 <= self.arbitration_id <= max_id):
            raise ValueError(
                f"Arbitration ID 0x{self.arbitration_id:X} out of range "
                f"(max 0x{max_id:X} for {'extended' if self.is_extended_id else 'standard'} CAN)"
            )

        # Classic CAN: max 8 bytes. CAN-FD allows up to 64, but we model classic.
        if len(self.data) > 8:
            raise ValueError(
                f"CAN 2.0 data field max 8 bytes, got {len(self.data)}"
            )

        # Ensure data is always bytes type
        if isinstance(self.data, list):
            self.data = bytes(self.data)

    @property
    def dlc(self) -> int:
        """Data Length Code — number of bytes in the data field."""
        return len(self.data)

    @property
    def hex_data(self) -> str:
        """Human-readable hex representation of payload."""
        return ' '.join(f'{b:02X}' for b in self.data)

    @property
    def hex_id(self) -> str:
        """CAN ID in hex with standard prefix width."""
        return f'0x{self.arbitration_id:03X}'

    def to_log_string(self) -> str:
        """
        Candump-compatible log format.
        Real tools (Wireshark, CANalyzer) use this format.
        Example: (1234567890.123) vcan0 0C0#1A2B3C4D5E6F7080
        """
        ts = f"({self.timestamp:.3f})"
        iface = "vcan0"
        can_id = f"{self.arbitration_id:03X}"
        payload = ''.join(f'{b:02X}' for b in self.data)
        marker = " [INJECTED]" if self.is_injected else ""
        return f"{ts} {iface} {can_id}#{payload} [{self.source_ecu}]{marker}"

    def __repr__(self) -> str:
        return (
            f"CANFrame(id={self.hex_id}, "
            f"data=[{self.hex_data}], "
            f"dlc={self.dlc}, "
            f"src={self.source_ecu}, "
            f"ts={self.timestamp:.3f})"
        )