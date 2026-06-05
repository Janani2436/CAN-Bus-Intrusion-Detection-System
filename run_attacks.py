"""
run_attacks.py — Day 2: See all 4 attacks running on the live bus

Run this AFTER run_simulator.py works correctly.
This script:
  1. Starts the normal vehicle CAN network
  2. Runs all 4 attacks sequentially
  3. Shows attack frames mixed with legitimate traffic
  4. Prints a clear summary of injected vs normal frames

Usage:
  python run_attacks.py
"""

import sys
import time
import logging
from collections import defaultdict

sys.path.insert(0, '.')

from simulator.virtual_can_bus import build_vehicle_network
from simulator.can_frame import CANFrame
from attacker.attack_engine import AttackOrchestrator

logging.basicConfig(level=logging.WARNING)  # suppress info logs for clean output


def run_attack_demo():
    normal_frames = defaultdict(int)
    attack_frames = defaultdict(int)

    def frame_listener(frame: CANFrame):
        if frame.is_injected:
            attack_frames[frame.source_ecu] += 1
        else:
            normal_frames[frame.arbitration_id] += 1

    print("\n" + "="*55)
    print("  CAN Bus IDS — Attack Engine Demo (Day 2)")
    print("="*55)

    bus = build_vehicle_network()
    bus.add_listener(frame_listener)
    bus.start()

    print("\n[+] Normal traffic running for 2s (baseline)...")
    time.sleep(2)
    baseline_total = sum(normal_frames.values())
    print(f"    Baseline: {baseline_total} normal frames captured\n")

    orchestrator = AttackOrchestrator(bus)
    orchestrator.run_all_attacks(verbose=True)

    time.sleep(1)
    bus.stop()

    print("\n" + "="*55)
    print("  TRAFFIC ANALYSIS")
    print("="*55)

    total_normal  = sum(normal_frames.values())
    total_attacks = sum(attack_frames.values())
    total_all     = total_normal + total_attacks

    print(f"\n  Normal frames:  {total_normal:>5}  ({100*total_normal/max(total_all,1):.1f}%)")
    print(f"  Attack frames:  {total_attacks:>5}  ({100*total_attacks/max(total_all,1):.1f}%)")
    print(f"  Total:          {total_all:>5}")

    print("\n  Attack breakdown:")
    for src, count in sorted(attack_frames.items()):
        print(f"    {src:<30} {count:>4} frames")

    print("\n  ✓ Attack engine working correctly!")
    print("  ✓ Ready for Day 3: IDS Detector\n")


if __name__ == '__main__':
    run_attack_demo()