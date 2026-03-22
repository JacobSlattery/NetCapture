"""
CaptureManager — owns the capture lifecycle independently of any WebSocket client.
"""

from __future__ import annotations

import asyncio
import json
import socket as _socket
import time
from collections import deque

from .capture import RawCapture, get_capture_ip, compute_warnings
from .interpreters import find_interpreter
from ._filter import parse_filter, filter_eval, filter_uses_decoded

try:
    from .capture_scapy import ScapyCapture, SCAPY_AVAILABLE, probe_npcap
except ImportError:
    SCAPY_AVAILABLE = False
    ScapyCapture    = None  # type: ignore[assignment,misc]
    def probe_npcap() -> bool: return False  # noqa: E704


# ── Session timer ──────────────────────────────────────────────────────────────
# Persists across stop/start cycles; reset only via reset_session_start().

_session_start: float | None = None


def _get_session_start() -> float:
    global _session_start
    if _session_start is None:
        _session_start = time.time()
    return _session_start


def reset_session_start() -> None:
    global _session_start
    _session_start = None


# ── Capture mode detection ─────────────────────────────────────────────────────

def _determine_mode(iface: str) -> str:
    """
    Probe available capture capabilities and return the best mode.

    The NETCAPTURE_MODE environment variable can pin a specific mode:
        NETCAPTURE_MODE=scapy    — require scapy/npcap (fails if unavailable)
        NETCAPTURE_MODE=real     — require raw sockets (fails if no admin)
    Omit the variable (default) for automatic selection: scapy → real.
    """
    if iface == "injected":
        return "inject"

    import os
    forced = os.environ.get("NETCAPTURE_MODE", "").lower().strip()

    if forced == "scapy":
        return "scapy" if (SCAPY_AVAILABLE and probe_npcap()) else "unavailable"

    if forced == "real":
        bind_ip = get_capture_ip(iface)
        if bind_ip:
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_IP)
                s.bind((bind_ip, 0))
                s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_ON)
                s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_OFF)
                s.close()
                return "real"
            except (PermissionError, OSError):
                pass
        return "unavailable"

    if forced and forced not in ("scapy", "real"):
        print(f"[capture] unknown NETCAPTURE_MODE={forced!r} — falling back to auto-detect")

    # Auto-detect: scapy → real
    if SCAPY_AVAILABLE and probe_npcap():
        return "scapy"

    bind_ip = get_capture_ip(iface)
    if bind_ip:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_IP)
            s.bind((bind_ip, 0))
            s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_ON)
            s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_OFF)
            s.close()
            return "real"
        except (PermissionError, OSError):
            pass

    return "unavailable"


# ── CaptureManager ─────────────────────────────────────────────────────────────

class CaptureManager:
    """
    Owns the capture lifecycle independently of any WebSocket client.

    Subscribers receive live packets + stats via asyncio.Queue.
    A rolling buffer lets reconnecting clients replay recent packets.
    """

    BUFFER_SIZE = 20_000

    def __init__(self) -> None:
        self._running = False
        self._mode    = "idle"
        self._iface   = "any"
        self._task: asyncio.Task | None = None
        self._start_lock = asyncio.Lock()

        self._filter_terms: list[str] = []
        self._filter_ast = None
        self._filter_needs_decoded = False
        self._bpf_filter = ""

        self._seq          = 0
        self._total_bytes  = 0
        self._proto_counts: dict[str, int] = {}
        self._sec_pkts     = 0
        self._sec_bytes    = 0

        self._buffer: deque[dict] = deque(maxlen=self.BUFFER_SIZE)
        self._subs: set[asyncio.Queue] = set()

    async def start(self, iface: str = "any", filter_str: str = "", bpf_filter: str = "") -> str:
        async with self._start_lock:
            return await self._start_locked(iface, filter_str, bpf_filter)

    async def _start_locked(self, iface: str, filter_str: str, bpf_filter: str) -> str:
        if self._running:
            await self.stop()

        self._iface        = iface
        self._filter_terms = filter_str.split() if filter_str.strip() else []
        self._filter_ast   = parse_filter(filter_str) if filter_str.strip() else None
        self._filter_needs_decoded = filter_uses_decoded(self._filter_ast)
        self._bpf_filter   = bpf_filter.strip()

        # Support comma-separated interface list (e.g. "eth0, eth1").
        # _determine_mode probes using the first interface.
        primary_iface = iface.split(",")[0].strip() if "," in iface else iface

        loop = asyncio.get_running_loop()
        mode = await loop.run_in_executor(None, _determine_mode, primary_iface)

        if mode == "unavailable":
            raise RuntimeError(
                "No capture method available. "
                "Run as Administrator for raw socket capture, or install Npcap."
            )

        self._mode    = mode
        self._running = True
        print(f"[capture] starting — mode={mode!r}  iface={iface!r}")

        # When the filter has no decoded/interpreter terms it is safe to
        # evaluate it in the capture thread — non-matching packets are
        # discarded before they ever enter the queue.
        pre_filter = self._matches_filter if (
            self._filter_ast is not None and not self._filter_needs_decoded
        ) else None

        if mode == "inject":
            self._task = asyncio.create_task(self._inject_loop())
        elif mode == "scapy":
            if "," in iface:
                scapy_iface: str | list[str] | None = [
                    i.strip() for i in iface.split(",") if i.strip()
                ]
            else:
                scapy_iface = None if iface == "any" else iface
            self._task = asyncio.create_task(self._scapy_loop(scapy_iface, pre_filter))
        else:
            bind_ip = get_capture_ip(iface)
            if bind_ip is None:
                raise RuntimeError(f"No IPv4 address found for interface {iface!r}")
            self._task = asyncio.create_task(self._real_loop(bind_ip, pre_filter))

        return mode

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._mode = "idle"

    def reset(self) -> None:
        self._buffer.clear()
        self._seq          = 0
        self._total_bytes  = 0
        self._sec_pkts     = 0
        self._sec_bytes    = 0
        self._proto_counts.clear()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.BUFFER_SIZE)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def get_buffer(self) -> list[dict]:
        return list(self._buffer)

    @property
    def is_running(self) -> bool:
        return self._running

    async def import_packets(self, packets: list[dict]) -> int:
        """
        Stop any running capture, reset state, and load the given packets.

        Assigns sequential IDs, updates the buffer, and broadcasts a batch
        message to all subscribers.  Returns the number of imported packets.
        """
        if self._running:
            await self.stop()

        self.reset()
        for i, p in enumerate(packets, start=1):
            p["id"] = i
        self._seq = len(packets)
        self._buffer.extend(packets)

        if packets:
            msg = json.dumps({"type": "batch", "data": list(self._buffer)})
            for q in list(self._subs):
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    pass

        return len(packets)

    def status(self) -> dict:
        return {
            "running": self._running,
            "mode":    self._mode,
            "iface":   self._iface,
            "packets": self._seq,
        }

    def _matches_filter(self, pkt: dict) -> bool:
        if not self._filter_terms:
            return True
        node = self._filter_ast
        if node is None:
            return True
        try:
            return filter_eval(node, pkt)
        except Exception:
            return True

    def _process_packet(self, pkt: dict, apply_filter: bool = True) -> dict | None:
        """
        Run a raw packet through the interpreter + filter pipeline.

        Mutates ``pkt`` in-place (strips internal fields, assigns id).
        Returns the ready-to-serialise dict, or None if the packet is
        filtered out.  Does NOT broadcast to subscribers — callers are
        responsible for that so they can batch multiple packets into one
        WebSocket message.

        Pass ``apply_filter=False`` to bypass the capture pre-filter (used
        for injected packets, which come from an explicit external source
        rather than the network capture stack).
        """
        payload: bytes | None = pkt.pop("_payload", None)
        # _header_bytes and _payload_offset stay in pkt so interpreters can
        # read them during match()/decode(); stripped before JSON serialisation.

        # Run interpreter before filter so that decoded fields and the
        # `interpreter` field are available to filter expressions such as
        # `interpreter == nc-frame` or `decoded.type == 0x01`.
        if payload:
            frame = find_interpreter(pkt, payload)
            if frame is not None:
                decoded = frame.to_dict()
                if pkt.get("_payload_offset"):
                    decoded["payloadOffset"] = pkt["_payload_offset"]
                pkt["decoded"] = decoded

        # Validate checksums for any packet that carries raw bytes.
        # parse_packet() already does this for captured packets; this path
        # covers injected packets (which bypass parse_packet entirely).
        if not pkt.get("warnings"):
            raw_hex = pkt.get("raw_hex")
            if raw_hex:
                try:
                    w = compute_warnings(bytes.fromhex(raw_hex))
                    if w:
                        pkt["warnings"] = w
                except Exception:
                    pass

        if apply_filter and not self._matches_filter(pkt):
            pkt.pop("_header_bytes",   None)
            pkt.pop("_payload_offset", None)
            return None

        pkt.pop("_header_bytes",   None)
        pkt.pop("_payload_offset", None)

        self._seq += 1
        pkt["id"] = self._seq
        self._total_bytes                    += pkt["length"]
        self._proto_counts[pkt["protocol"]]   = self._proto_counts.get(pkt["protocol"], 0) + 1
        self._sec_pkts  += 1
        self._sec_bytes += pkt["length"]
        self._buffer.append(pkt)
        return pkt

    def _broadcast_batch(self, pkts: list[dict]) -> None:
        """Serialise a list of ready packets and push one message to every subscriber."""
        if not pkts:
            return
        msg = json.dumps({"type": "batch", "data": pkts})
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    def _emit_packet(self, pkt: dict) -> None:
        """Process and immediately broadcast a single packet (used by inject mode).

        Injected packets bypass the capture pre-filter — the pre-filter is an
        optimisation for network capture volume, not a gate for explicit test traffic.
        The frontend display filter still applies to injected packets normally.
        """
        processed = self._process_packet(pkt, apply_filter=False)
        if processed is None:
            return
        msg = json.dumps({"type": "packet", "data": processed})
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    def _emit_stats(self) -> None:
        msg = json.dumps({"type": "stats", "data": {
            "total_packets":   self._seq,
            "total_bytes":     self._total_bytes,
            "packets_per_sec": self._sec_pkts,
            "bytes_per_sec":   self._sec_bytes,
            "protocol_counts": dict(self._proto_counts),
        }})
        self._sec_pkts  = 0
        self._sec_bytes = 0
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass

    async def _inject_loop(self) -> None:
        """Stats ticker for inject mode — no capture, just emit stats every second."""
        loop = asyncio.get_running_loop()
        last_tick = loop.time()
        try:
            while self._running:
                await asyncio.sleep(0.1)
                now = loop.time()
                if now - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now
        except asyncio.CancelledError:
            pass

    async def _scapy_loop(self, iface: str | None, pre_filter=None) -> None:
        cap = ScapyCapture(iface, bpf_filter=self._bpf_filter)
        if pre_filter is not None:
            cap.set_filter(pre_filter)
        cap.start(session_start=_get_session_start())
        loop      = asyncio.get_running_loop()
        last_tick = loop.time()
        FLUSH_INTERVAL = 0.05
        try:
            while self._running:
                # drain() blocks up to FLUSH_INTERVAL for the first packet
                # then atomically dequeues everything else without blocking,
                # preventing the queue from filling under heavy traffic.
                pkts = await loop.run_in_executor(None, cap.drain, FLUSH_INTERVAL)
                ready: list[dict] = []
                for i, pkt in enumerate(pkts):
                    del pkt["id"]
                    processed = self._process_packet(pkt)
                    if processed is not None:
                        ready.append(processed)
                    # Yield every 256 packets so the event loop can flush
                    # WebSocket sends during large traffic bursts.
                    if i % 256 == 255:
                        self._broadcast_batch(ready)
                        ready = []
                        await asyncio.sleep(0)
                self._broadcast_batch(ready)
                now = loop.time()
                if now - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now
        except asyncio.CancelledError:
            pass
        finally:
            cap.stop()

    async def _real_loop(self, bind_ip: str, pre_filter=None) -> None:
        cap  = RawCapture(bind_ip)
        if pre_filter is not None:
            cap.set_filter(pre_filter)
        cap.start(session_start=_get_session_start())
        loop      = asyncio.get_running_loop()
        last_tick = loop.time()
        FLUSH_INTERVAL = 0.05
        try:
            while self._running:
                pkts = await loop.run_in_executor(None, cap.drain, FLUSH_INTERVAL)
                ready: list[dict] = []
                for i, pkt in enumerate(pkts):
                    del pkt["id"]
                    processed = self._process_packet(pkt)
                    if processed is not None:
                        ready.append(processed)
                    if i % 256 == 255:
                        self._broadcast_batch(ready)
                        ready = []
                        await asyncio.sleep(0)
                self._broadcast_batch(ready)
                now = loop.time()
                if now - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now
        except asyncio.CancelledError:
            pass
        finally:
            cap.stop()


# Module-level singleton — shared across all router instances
manager = CaptureManager()
