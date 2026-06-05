"""
live_dashboard.py — Real-time CAN Bus IDS Terminal Dashboard

Uses the Rich library to display a live updating terminal UI showing:
  - CAN bus traffic per ECU (live frame rates)
  - Attack alerts as they happen (color-coded by severity)
  - IDS detection statistics
  - System status panel

Interview anchor:
  "The dashboard renders in a standard terminal using Rich's Live layout —
   no browser or GUI required. It updates every 500ms showing real-time
   ECU frame rates, color-coded alerts by severity, and a running detection
   accuracy counter. This mirrors how a real vehicle SOC analyst would
   monitor an in-vehicle IDPS."
"""

import time
import logging
from collections import defaultdict, deque
from typing import List, Dict
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from simulator.can_frame import CANFrame
from detector.ids_detector import Alert

# Silence all loggers — dashboard is the only output
logging.disable(logging.CRITICAL)


class CANDashboard:
    """
    Live terminal dashboard for the CAN Bus IDS.
    Attach to a bus as a listener, then call .run() to start rendering.
    """

    SEVERITY_COLORS = {
        'LOW':      'bright_black',
        'MEDIUM':   'yellow',
        'HIGH':     'red',
        'CRITICAL': 'bold red',
    }

    ATTACK_COLORS = {
        'REPLAY':   'cyan',
        'FUZZING':  'magenta',
        'SPOOFING': 'red',
        'FLOODING': 'yellow',
    }

    ECU_NAMES = {
        0x0C0: 'Engine ECU',
        0x1A0: 'Brake ECU',
        0x1F0: 'Transmission',
        0x2B0: 'Steering ECU',
        0x4B0: 'Body Control',
        0x000: '⚠ FLOOD ID',
    }

    def __init__(self):
        self.console = Console()

        # Frame tracking
        self._frame_counts: Dict[int, int]      = defaultdict(int)
        self._frame_times:  Dict[int, deque]    = defaultdict(lambda: deque(maxlen=200))
        self._total_frames  = 0
        self._injected_frames = 0

        # Alert tracking
        self._alerts: List[Alert]               = []
        self._alert_counts: Dict[str, int]      = defaultdict(int)
        self._recent_alerts: deque              = deque(maxlen=8)

        # Timing
        self._start_time = time.time()

    # ── frame listener (plug into bus) ──────────────────────────────────────

    def on_frame(self, frame: CANFrame) -> None:
        """Called for every frame on the bus. Thread-safe reads only."""
        self._total_frames += 1
        self._frame_counts[frame.arbitration_id] += 1
        self._frame_times[frame.arbitration_id].append(time.time())
        if frame.is_injected:
            self._injected_frames += 1

    def on_alert(self, alert: Alert) -> None:
        """Called by IDS when it raises an alert."""
        self._alerts.append(alert)
        self._alert_counts[alert.alert_type] += 1
        self._recent_alerts.append(alert)

    # ── rate calculator ──────────────────────────────────────────────────────

    def _rate(self, can_id: int, window: float = 1.0) -> float:
        now = time.time()
        times = self._frame_times[can_id]
        recent = sum(1 for t in times if t > now - window)
        return recent / window

    # ── panel builders ───────────────────────────────────────────────────────

    def _build_header(self) -> Panel:
        uptime = time.time() - self._start_time
        t = Text()
        t.append("🚗  CAN Bus Intrusion Detection System", style="bold white")
        t.append(f"   │   Uptime: {uptime:.0f}s", style="bright_black")
        t.append(f"   │   Frames: {self._total_frames}", style="bright_black")
        t.append(f"   │   Alerts: {len(self._alerts)}", style="red" if self._alerts else "bright_black")
        return Panel(t, style="bright_black", padding=(0, 1))

    def _build_ecu_table(self) -> Panel:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold bright_black",
            padding=(0, 1),
            expand=True
        )
        table.add_column("CAN ID",   width=8)
        table.add_column("ECU",      width=16)
        table.add_column("Rate/s",   width=8,  justify="right")
        table.add_column("Total",    width=8,  justify="right")
        table.add_column("Status",   width=14)

        # Known ECU IDs to show
        display_ids = [0x0C0, 0x1A0, 0x1F0, 0x2B0, 0x4B0]

        for can_id in display_ids:
            rate  = self._rate(can_id)
            total = self._frame_counts[can_id]
            name  = self.ECU_NAMES.get(can_id, f"0x{can_id:03X}")

            # Status indicator
            if rate == 0 and self._total_frames > 200:
                status = Text("● SILENT", style="red")
            elif rate > 0:
                status = Text("● ACTIVE", style="green")
            else:
                status = Text("○ WAITING", style="bright_black")

            # Rate color — red if anomalous
            expected = {0x0C0:100, 0x1A0:100, 0x2B0:100, 0x1F0:50, 0x4B0:10}
            exp = expected.get(can_id, 100)
            rate_style = "red" if rate > exp * 2 else "white"

            table.add_row(
                f"0x{can_id:03X}",
                name,
                Text(f"{rate:.0f}", style=rate_style),
                str(total),
                status,
            )

        # Show flood ID if active
        flood_count = self._frame_counts.get(0x000, 0)
        if flood_count > 0:
            rate = self._rate(0x000)
            table.add_row(
                "0x000",
                Text("⚠ FLOOD ID", style="bold red"),
                Text(f"{rate:.0f}", style="bold red"),
                str(flood_count),
                Text("● ATTACK!", style="bold red"),
            )

        return Panel(table, title="[bold]ECU Traffic Monitor[/bold]",
                     border_style="bright_black")

    def _build_alert_table(self) -> Panel:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold bright_black",
            padding=(0, 1),
            expand=True
        )
        table.add_column("Time",     width=10)
        table.add_column("Severity", width=10)
        table.add_column("Type",     width=12)
        table.add_column("ID",       width=7)
        table.add_column("Detail",   min_width=20)

        if not self._recent_alerts:
            table.add_row(
                "--:--:--",
                Text("--", style="bright_black"),
                Text("--", style="bright_black"),
                "---",
                Text("No alerts yet — monitoring...", style="bright_black"),
            )
        else:
            for alert in reversed(list(self._recent_alerts)):
                ts       = datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')
                sev_col  = self.SEVERITY_COLORS.get(alert.severity, 'white')
                type_col = self.ATTACK_COLORS.get(alert.alert_type, 'white')
                # Truncate long descriptions
                detail = alert.description[:50] + ('…' if len(alert.description) > 50 else '')
                table.add_row(
                    ts,
                    Text(alert.severity,     style=sev_col),
                    Text(alert.alert_type,   style=type_col),
                    alert.hex_id,
                    detail,
                )

        return Panel(table, title="[bold]Live Alert Feed[/bold]",
                     border_style="red" if self._recent_alerts else "bright_black")

    def _build_stats_panel(self) -> Panel:
        # Alert type summary
        lines = []
        total_alerts = len(self._alerts)

        type_order = ['FLOODING', 'SPOOFING', 'FUZZING', 'REPLAY']
        for atype in type_order:
            count = self._alert_counts.get(atype, 0)
            col   = self.ATTACK_COLORS.get(atype, 'white')
            bar   = '█' * min(int(count / max(total_alerts, 1) * 20), 20)
            t = Text()
            t.append(f"  {atype:<10}", style=col)
            t.append(f" {count:>5}  ", style="white")
            t.append(bar, style=col)
            lines.append(t)

        # Bus health
        bus_rate   = self._rate_all()
        inj_pct    = 100 * self._injected_frames / max(self._total_frames, 1)

        summary = Text()
        summary.append(f"\n  Bus rate: ", style="bright_black")
        summary.append(f"{bus_rate:.0f} fps", style="white")
        summary.append(f"   Injected: ", style="bright_black")
        summary.append(f"{inj_pct:.1f}%", style="red" if inj_pct > 5 else "green")

        content = Text()
        for line in lines:
            content.append_text(line)
            content.append("\n")
        content.append_text(summary)

        return Panel(content, title="[bold]Detection Summary[/bold]",
                     border_style="bright_black")

    def _rate_all(self, window: float = 1.0) -> float:
        now = time.time()
        total = 0
        for times in self._frame_times.values():
            total += sum(1 for t in times if t > now - window)
        return total / window

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._build_header(),      name="header",  size=3),
            Layout(name="middle", ratio=1),
            Layout(self._build_stats_panel(), name="footer",  size=10),
        )
        layout["middle"].split_row(
            Layout(self._build_ecu_table(),   name="left",  ratio=1),
            Layout(self._build_alert_table(), name="right", ratio=2),
        )
        return layout