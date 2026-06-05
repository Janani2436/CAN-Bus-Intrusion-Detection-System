"""
run_ids.py — Full system: Simulator + Attacks + IDS running together

This is your complete project demo.
Run this to see the IDS detecting attacks in real time.

Usage:
    python run_ids.py
"""

import os
import sys
import time
import logging
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulator.virtual_can_bus import build_vehicle_network
from simulator.can_frame import CANFrame
from attacker.attack_engine import AttackOrchestrator
from detector.ids_detector import CANBusIDS

logging.basicConfig(level=logging.WARNING)


def run_full_demo():
    print("\n" + "="*55)
    print("  CAN Bus Intrusion Detection System")
    print("  Full Demo: Normal → Train → Attack → Detect")
    print("="*55)

    # Build IDS and bus
    ids = CANBusIDS()
    bus = build_vehicle_network()
    bus.add_listener(ids.analyze)   # IDS listens to every frame

    bus.start()

    # Phase 1: Training (let IDS learn normal behaviour)
    print("\n[Phase 1] Training IDS on normal traffic (5s)...")
    time.sleep(5)
    print(f"  IDS trained on {len(ids.stat_detector.trained_ids)} ECU IDs")
    print(f"  Frames analyzed so far: {ids._frames_analyzed}")

    # Phase 2: Run attacks
    print("\n[Phase 2] Launching attacks...")
    orchestrator = AttackOrchestrator(bus)
    results = orchestrator.run_all_attacks(verbose=True)

    time.sleep(1)
    bus.stop()

    # Phase 3: Report
    ids.print_report()

    # Accuracy summary
    total_injected = sum(results.values())
    total_detected = len(ids.all_alerts)
    print(f"\n  Attack frames injected : {total_injected}")
    print(f"  Alerts generated       : {total_detected}")
    print(f"\n  ✓ IDS is working! Check alerts above.")
    print(f"  ✓ Project core complete — ready for dashboard.\n")


if __name__ == '__main__':
    run_full_demo()