"""
run_simulator.py — Day 1 test: Verify the CAN bus simulator works

Run this to see your virtual vehicle network in action.
This script:
  1. Builds the vehicle CAN network
  2. Starts all ECU threads
  3. Listens on the bus for 10 seconds
  4. Prints a formatted log of captured frames
  5. Shows basic statistics

Expected output:
  You should see frames from 5 ECUs streaming at different rates:
  - Engine (0x0C0): ~100 frames/sec (10ms cycle)
  - Brake  (0x1A0): ~100 frames/sec
  - Steering(0x2B0): ~100 frames/sec
  - Transmission(0x1F0): ~50 frames/sec
  - Body (0x4B0): ~10 frames/sec

Usage:
  python run_simulator.py
"""

import sys
import time
import logging
from collections import defaultdict

# Add project root to path
import os


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulator.can_frame import CANFrame
from simulator.ecu_nodes import EngineECU
from simulator.virtual_can_bus import VirtualCANBus, build_vehicle_network

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('Simulator')


def demo_frame_listener(frame: CANFrame) -> None:
    """Simple listener that prints frames — our 'oscilloscope'."""
    # Only print every 50th frame to avoid flooding the terminal
    if frame._message_count_demo % 50 == 0 if hasattr(frame, '_message_count_demo') else True:
        pass  # controlled print below


def run_demo(duration_seconds: int = 10):
    """Run the simulator and display results."""
    print("\n" + "="*60)
    print("  🚗 Automotive CAN Bus Intrusion Detection System")
    print("  Vehicle Network Simulator")
    print(" ")
    print(" Network:")
    print("  • 5 ECUs")
    print("  • 500 kbps CAN Bus")
    print("  • Real-Time Traffic Monitoring")
    print("="*60)

    # Frame counter per ECU ID
    frame_counts = defaultdict(int)
    frame_samples = defaultdict(list)  # Store sample frames per ID
    MAX_SAMPLES = 3

    def capture_listener(frame: CANFrame):
        """Capture stats and sample frames."""
        frame_counts[frame.arbitration_id] += 1
        if len(frame_samples[frame.arbitration_id]) < MAX_SAMPLES:
            frame_samples[frame.arbitration_id].append(frame)

    # Build vehicle network
    bus = build_vehicle_network()
    bus.add_listener(capture_listener)

    print(f"\n[+] Starting vehicle network ({duration_seconds}s capture)...\n")
    bus.start()

    # Run for specified duration
    try:
        for i in range(duration_seconds):
            time.sleep(1)
            elapsed = i + 1
            total = sum(frame_counts.values())
            print(f"  [{elapsed:02d}s] Total frames captured: {total} | "
                  f"Bus load: {bus.frame_rate:.0f} fps", end='\r')
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

    bus.stop()
    print(f"\n\n{'='*60}")
    print("  CAPTURE RESULTS")
    print(f"{'='*60}")

    # ECU name mapping
    ecu_names = {
        0x0C0: "Engine ECU      ",
        0x1A0: "Brake ECU       ",
        0x1F0: "Transmission ECU",
        0x2B0: "Steering ECU    ",
        0x4B0: "Body Control    ",
    }

    print(f"\n  {'CAN ID':<10} {'ECU Name':<20} {'Frames':>8} {'Rate':>10}")
    print(f"  {'-'*54}")

    for can_id in sorted(frame_counts.keys()):
        name = ecu_names.get(can_id, f"Unknown        ")
        count = frame_counts[can_id]
        rate = count / duration_seconds
        bar = '█' * int(rate / 10)
        print(f"  0x{can_id:03X}     {name}  {count:>6}   {rate:>6.1f}/s  {bar}")

    print(f"\n  Total frames: {sum(frame_counts.values())}")
    print(f"  Unique ECUs:  {len(frame_counts)}")
    bus.print_stats()

    # Show sample frame decoding
    print("  SAMPLE DECODED FRAMES")
    print(f"  {'-'*54}")

    if 0x0C0 in frame_samples:
        sample = frame_samples[0x0C0][0]
        decoded = EngineECU.decode_payload(sample.data)
        print(f"\n  Engine ECU frame (0x0C0):")
        print(f"    Raw:     {sample.hex_data}")
        print(f"    RPM:     {decoded.get('rpm', 0):.0f}")
        print(f"    Throttle:{decoded.get('throttle_pct', 0):.1f}%")
        print(f"    Temp:    {decoded.get('coolant_temp_c', 0):.0f}°C")



    return bus.get_frame_log()


if __name__ == '__main__':
    frames = run_demo(duration_seconds=5)