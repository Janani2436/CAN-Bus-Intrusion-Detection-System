"""
run_dashboard.py

AutoShield-CAN IDS Demonstration Module

Demonstrates:
- Vehicle CAN traffic simulation
- Real-time cyberattack injection
- Intrusion detection and alerting
- Security monitoring dashboard

Designed to showcase automotive cybersecurity concepts,
CAN Bus security threats, and IDS-based threat detection.
"""
import os
import sys
import time
import threading
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
logging.disable(logging.CRITICAL)   # clean output — dashboard only

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from simulator.virtual_can_bus import build_vehicle_network
from attacker.attack_engine import AttackOrchestrator
from detector.ids_detector import CANBusIDS
from dashboard.live_dashboard import CANDashboard

console = Console()


def run_dashboard_demo():
    # ── Setup ────────────────────────────────────────────────────────────────
    ids       = CANBusIDS()
    dashboard = CANDashboard()
    bus       = build_vehicle_network()

    # Wire everything together
    def combined_listener(frame):
        dashboard.on_frame(frame)
        alerts = ids.analyze(frame)
        for alert in alerts:
            dashboard.on_alert(alert)

    bus.add_listener(combined_listener)

    # ── Phase labels ─────────────────────────────────────────────────────────
    phase_text = {"current": "Phase 1: Training IDS on normal traffic..."}

    console.print(
    "\n[bold green]🚗 AutoShield-CAN IDS — Automotive Cybersecurity Demonstration[/bold green]\n"
)
    bus.start()

    # ── Live dashboard loop ──────────────────────────────────────────────────
    with Live(
        dashboard.build_layout(),
        console=console,
        refresh_per_second=2,
        screen=True
    ) as live:

        # Phase 1: Training (5 seconds)
        for _ in range(10):   # 10 × 0.5s = 5s
            live.update(dashboard.build_layout())
            time.sleep(0.5)

        # Phase 2: Attacks (run in background thread)
        def run_attacks():
            orchestrator = AttackOrchestrator(bus)
            orchestrator.run_all_attacks(verbose=False)

        attack_thread = threading.Thread(target=run_attacks, daemon=True)
        attack_thread.start()

        # Keep dashboard live during attacks (~12 seconds)
        for _ in range(24):   # 24 × 0.5s = 12s
            live.update(dashboard.build_layout())
            time.sleep(0.5)

        attack_thread.join(timeout=2)

        # Final update
        live.update(dashboard.build_layout())
        time.sleep(1)

    # ── Post-demo report ─────────────────────────────────────────────────────
    bus.stop()
    console.print()
    ids.print_report()

    console.print(Panel(
        Text.assemble(
            ("  Project: ", "bright_black"),   ("AutoShield-CAN IDS\n", "bold white"),
            ("  Focus:   ", "bright_black"),   ("Automotive Cybersecurity & CAN Security\n", "white"),
            ("  Stack:   ", "bright_black"),   ("Python · python-can · Rich · NumPy\n", "white"),
            ("  Detects: ", "bright_black"),   ("Replay · Fuzzing · Spoofing · Flooding\n", "white"),
            ("  Method:  ", "bright_black"),   ("Rule-based + Statistical (Z-score)\n", "white"),
            ("  Standard:", "bright_black"),   ("ISO 21434 threat categories\n", "white"),
        ),
        title="[bold]Resume Summary[/bold]",
        border_style="green"
    ))


if __name__ == '__main__':
    run_dashboard_demo()