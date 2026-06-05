"""
virtual_can_bus.py — The shared CAN bus medium

This is the core of the simulation. In a real vehicle:
  - All ECUs share two physical wires (CAN-H and CAN-L)
  - Any ECU can transmit at any time
  - Arbitration resolves collisions (lower ID wins)
  - All ECUs receive all messages (broadcast)

This class simulates that shared medium using a Python queue.
The bus runs in its own thread — ECUs push frames in,
listeners (our IDS) pull frames out.

Interview anchor:
  "I used a thread-safe queue to simulate the CAN bus broadcast medium.
   Producer threads are ECU nodes, consumer threads are the IDS engine.
   This mirrors the publish-subscribe model of a real CAN bus."
"""

import time
import queue
import threading
import logging
from typing import List, Optional, Callable
from simulator.can_frame import CANFrame
from simulator.ecu_nodes import (
    BaseECU, EngineECU, BrakeECU,
    SteeringECU, BodyControlECU, TransmissionECU
)

logger = logging.getLogger(__name__)


class VirtualCANBus:
    """
    Simulates a CAN bus as a shared broadcast medium.

    Architecture:
      - Each ECU runs in its own thread, generating frames at its cycle rate
      - All frames go into a single thread-safe queue (the 'wire')
      - Any number of listeners can read from the bus (IDS, logger, etc.)
      - Supports frame injection (attacker inserts frames directly)

    This is exactly how the Linux SocketCAN kernel module works —
    vcan0 is a virtual CAN interface that queues frames for all listeners.
    """

    def __init__(self, bus_speed_kbps: int = 500):
        """
        Args:
            bus_speed_kbps: CAN bus speed. Common values:
              125 kbps — low-speed CAN (body, comfort)
              250 kbps — mid-speed (chassis)
              500 kbps — high-speed CAN (powertrain) ← default
              1000 kbps — CAN-FD
        """
        self.bus_speed_kbps = bus_speed_kbps
        self._frame_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._ecus: List[BaseECU] = []
        self._ecu_threads: List[threading.Thread] = []
        self._running: bool = False
        self._lock = threading.Lock()

        # Statistics
        self.total_frames: int = 0
        self.injected_frames: int = 0
        self.dropped_frames: int = 0
        self._start_time: float = 0.0

        # Frame log (for IDS training baseline)
        self._frame_log: List[CANFrame] = []
        self._log_enabled: bool = True

        # Listeners — functions called for every frame
        self._listeners: List[Callable[[CANFrame], None]] = []

    def add_ecu(self, ecu: BaseECU) -> None:
        """Register an ECU on the bus."""
        with self._lock:
            self._ecus.append(ecu)
            logger.debug(f"ECU registered: {ecu.name} (ID={ecu.can_id:#05x})")

    def add_listener(self, callback: Callable[[CANFrame], None]) -> None:
        """
        Register a frame listener (e.g., the IDS engine).
        Every frame that hits the bus triggers all listeners.
        """
        self._listeners.append(callback)

    def inject_frame(self, frame: CANFrame) -> bool:
        """
        Inject an arbitrary frame onto the bus.
        This is the attacker's interface — bypasses ECU ownership.

        In a real vehicle, this would require physical or remote access
        to the OBD-II port, a compromised ECU, or a TCU exploit.

        Returns True if frame was accepted, False if bus is full (DoS condition).
        """
        frame.is_injected = True
        frame.timestamp = time.time()
        try:
            self._frame_queue.put_nowait(frame)
            self.injected_frames += 1
            return True
        except queue.Full:
            self.dropped_frames += 1
            logger.warning(f"Bus full! Dropped injected frame {frame.hex_id}")
            return False

    def _ecu_thread(self, ecu: BaseECU) -> None:
        """Worker thread for a single ECU. Generates frames at its cycle rate."""
        logger.debug(f"ECU thread started: {ecu.name}")
        while self._running:
            frame = ecu.generate_frame()
            if frame is not None:
                try:
                    self._frame_queue.put(frame, timeout=0.01)
                except queue.Full:
                    self.dropped_frames += 1

            # Sleep for a fraction of cycle time (oversampling for accuracy)
            time.sleep(ecu.cycle_time_ms / 1000.0 / 4)

    def _dispatch_thread(self) -> None:
        """
        Central dispatcher: pulls frames from queue, notifies all listeners.
        Simulates the CAN controller chip that every node's transceiver has.
        """
        while self._running or not self._frame_queue.empty():
            try:
                frame = self._frame_queue.get(timeout=0.05)
                self.total_frames += 1

                # Log frame
                if self._log_enabled:
                    self._frame_log.append(frame)

                # Notify all listeners (IDS, logger, dashboard)
                for listener in self._listeners:
                    try:
                        listener(frame)
                    except Exception as e:
                        logger.error(f"Listener error: {e}")

                self._frame_queue.task_done()

            except queue.Empty:
                continue

    def start(self) -> None:
        """Start the bus and all registered ECU threads."""
        if self._running:
            logger.warning("Bus already running")
            return

        self._running = True
        self._start_time = time.time()

        # Start one thread per ECU
        for ecu in self._ecus:
            t = threading.Thread(
                target=self._ecu_thread,
                args=(ecu,),
                name=f"ECU-{ecu.name}",
                daemon=True
            )
            t.start()
            self._ecu_threads.append(t)

        # Start dispatcher
        self._dispatch_thread_obj = threading.Thread(
            target=self._dispatch_thread,
            name="CAN-Dispatcher",
            daemon=True
        )
        self._dispatch_thread_obj.start()
        logger.info(
            f"CAN bus started: {len(self._ecus)} ECUs, "
            f"{self.bus_speed_kbps} kbps"
        )

    def stop(self) -> None:
        """Gracefully stop the bus."""
        self._running = False
        for t in self._ecu_threads:
            t.join(timeout=1.0)
        logger.info("CAN bus stopped")

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time if self._start_time else 0.0

    @property
    def frame_rate(self) -> float:
        """Frames per second — useful for flood detection."""
        uptime = self.uptime_seconds
        return self.total_frames / uptime if uptime > 0 else 0.0

    def get_frame_log(self) -> List[CANFrame]:
        """Return a copy of the captured frame log."""
        with self._lock:
            return self._frame_log.copy()

    def print_stats(self) -> None:
        """Print bus statistics — useful for demo."""
        print(f"\n{'='*50}")
        print(f"  CAN Bus Statistics")
        print(f"{'='*50}")
        print(f"  Uptime:          {self.uptime_seconds:.1f}s")
        print(f"  Total frames:    {self.total_frames}")
        print(f"  Injected frames: {self.injected_frames}")
        print(f"  Dropped frames:  {self.dropped_frames}")
        print(f"  Frame rate:      {self.frame_rate:.1f} fps")
        print(f"  ECUs active:     {len(self._ecus)}")
        print(f"{'='*50}\n")


def build_vehicle_network() -> VirtualCANBus:
    """
    Factory function — creates a complete vehicle CAN network.
    This is the standard 500 kbps powertrain bus.

    Call this to get a ready-to-run simulation with all ECUs.
    The IDS will learn normal behaviour from this baseline.
    """
    bus = VirtualCANBus(bus_speed_kbps=500)

    # Register all vehicle ECUs
    bus.add_ecu(EngineECU())
    bus.add_ecu(BrakeECU())
    bus.add_ecu(SteeringECU())
    bus.add_ecu(BodyControlECU())
    bus.add_ecu(TransmissionECU())

    logger.info(f"Vehicle network built: {len(bus._ecus)} ECUs registered")
    return bus