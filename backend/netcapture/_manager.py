"""
CaptureManager — owns the capture lifecycle independently of any WebSocket client.
"""

from __future__ import annotations

import asyncio
import json
import socket as _socket
import time
from collections import deque

from .capture import RawCapture, get_capture_ip
from .interpreters import find_interpreter
from ._filter import parse_filter, filter_eval

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

        self._filter_terms: list[str] = []
        self._filter_ast = None
        self._bpf_filter = ""

        self._seq          = 0
        self._total_bytes  = 0
        self._proto_counts: dict[str, int] = {}
        self._sec_pkts     = 0
        self._sec_bytes    = 0

        self._buffer: deque[dict] = deque(maxlen=self.BUFFER_SIZE)
        self._subs: set[asyncio.Queue] = set()

    async def start(self, iface: str = "any", filter_str: str = "", bpf_filter: str = "") -> str:
        if self._running:
            await self.stop()

        self._iface        = iface
        self._filter_terms = filter_str.split() if filter_str.strip() else []
        self._filter_ast   = parse_filter(filter_str) if filter_str.strip() else None
        self._bpf_filter   = bpf_filter.strip()

        loop = asyncio.get_event_loop()
        mode = await loop.run_in_executor(None, _determine_mode, iface)

        if mode == "unavailable":
            raise RuntimeError(
                "No capture method available. "
                "Run as Administrator for raw socket capture, or install Npcap."
            )

        self._mode    = mode
        self._running = True
        print(f"[capture] starting — mode={mode!r}  iface={iface!r}")

        if mode == "scapy":
            scapy_iface = None if iface == "any" else iface
            self._task = asyncio.create_task(self._scapy_loop(scapy_iface))
        else:
            bind_ip = get_capture_ip(iface)
            assert bind_ip is not None
            self._task = asyncio.create_task(self._real_loop(bind_ip))

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

    def _emit_packet(self, pkt: dict) -> None:
        payload: bytes | None = pkt.pop("_payload", None)

        if not self._matches_filter(pkt):
            return

        if payload:
            frame = find_interpreter(pkt, payload)
            if frame is not None:
                pkt["decoded"] = frame.to_dict()

        self._seq += 1
        pkt["id"] = self._seq
        self._total_bytes                         += pkt["length"]
        self._proto_counts[pkt["protocol"]]        = self._proto_counts.get(pkt["protocol"], 0) + 1
        self._sec_pkts  += 1
        self._sec_bytes += pkt["length"]

        self._buffer.append(pkt)
        msg = json.dumps({"type": "packet", "data": pkt})
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

    async def _scapy_loop(self, iface: str | None) -> None:
        cap = ScapyCapture(iface, bpf_filter=self._bpf_filter)
        cap.start(session_start=_get_session_start())
        loop       = asyncio.get_event_loop()
        last_tick  = loop.time()
        last_flush = loop.time()
        batch: list[dict] = []
        FLUSH_INTERVAL = 0.05
        try:
            while self._running:
                pkt = await loop.run_in_executor(None, cap.get_packet, 0.05)
                if pkt:
                    del pkt["id"]
                    batch.append(pkt)
                now = loop.time()
                if batch and now - last_flush >= FLUSH_INTERVAL:
                    for p in batch:
                        self._emit_packet(p)
                    batch.clear()
                    last_flush = now
                if now - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now
        except asyncio.CancelledError:
            pass
        finally:
            cap.stop()

    async def _real_loop(self, bind_ip: str) -> None:
        cap  = RawCapture(bind_ip)
        cap.start(session_start=_get_session_start())
        loop       = asyncio.get_event_loop()
        last_tick  = loop.time()
        last_flush = loop.time()
        batch: list[dict] = []
        FLUSH_INTERVAL = 0.05
        try:
            while self._running:
                pkt = await loop.run_in_executor(None, cap.get_packet, 0.05)
                if pkt:
                    del pkt["id"]
                    batch.append(pkt)
                now = loop.time()
                if batch and now - last_flush >= FLUSH_INTERVAL:
                    for p in batch:
                        self._emit_packet(p)
                    batch.clear()
                    last_flush = now
                if now - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now
        except asyncio.CancelledError:
            pass
        finally:
            cap.stop()


# Module-level singleton — shared across all router instances
manager = CaptureManager()
