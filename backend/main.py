"""
NetCapture — FastAPI backend

Capture lifecycle is owned by CaptureManager and runs independently of any
WebSocket connection.  Clients subscribe via WS to receive live packets and
a replay of the rolling buffer — disconnecting never stops a capture.

REST API:
  GET  /api/interfaces
  GET  /api/health
  GET  /api/config
  GET  /api/capture/status
  POST /api/capture/start   { "interface": "any" }
  POST /api/capture/stop
  POST /api/reset-session   (clears buffer + resets counters)

WebSocket:
  /ws/capture  — on connect: sends status + buffer replay, then live stream

Capture modes (selected automatically at start):
  real   — Windows raw sockets + SIO_RCVALL (needs Administrator)
  listen — UDP sink on UDP_SINK_PORT; feed with: pixi run mock-device --mode feed
"""

from __future__ import annotations

import asyncio
import json
import socket as _socket
import time
from collections import deque
from datetime import datetime
from pathlib import Path

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from capture import RawCapture, get_capture_ip, build_udp_raw_hex, UDP_SINK_PORT
from interpreters import find_interpreter
from profiles import PROFILES

app = FastAPI(title="NetCapture", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Session timer ─────────────────────────────────────────────────────────────
# Persists across stop/start cycles; reset only via POST /api/reset-session.

_session_start: float | None = None


def _get_session_start() -> float:
    global _session_start
    if _session_start is None:
        _session_start = time.time()
    return _session_start


# ── Capture mode detection ────────────────────────────────────────────────────

def _determine_mode(iface: str) -> str:
    """
    Probe available capture capabilities (blocking — run in executor).
    Returns 'real', 'listen', or 'unavailable'.
    """
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
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", UDP_SINK_PORT))
        s.close()
        return "listen"
    except OSError:
        pass
    return "unavailable"


# ── UDP sink protocol ─────────────────────────────────────────────────────────

class _SinkProtocol(asyncio.DatagramProtocol):
    def __init__(self, q: asyncio.Queue) -> None:
        self._q = q

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._q.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        print(f"[sink] {exc}")


# ── CaptureManager ────────────────────────────────────────────────────────────

class CaptureManager:
    """
    Owns the capture lifecycle independently of any WebSocket client.

    Subscribers receive live packets + stats via asyncio.Queue.
    A rolling buffer lets reconnecting clients replay recent packets.
    Stopping and starting capture (or clients connecting/disconnecting)
    does not reset the session counters — only reset() does.
    """

    BUFFER_SIZE = 20_000

    def __init__(self) -> None:
        self._running = False
        self._mode    = "idle"
        self._iface   = "any"
        self._task: asyncio.Task | None = None

        # Active server-side filter terms (empty = pass all)
        self._filter_terms: list[str] = []

        # Session counters — persist across stop/start
        self._seq          = 0
        self._total_bytes  = 0
        self._proto_counts: dict[str, int] = {}
        self._sec_pkts     = 0
        self._sec_bytes    = 0

        # Rolling buffer for reconnecting clients
        self._buffer: deque[dict] = deque(maxlen=self.BUFFER_SIZE)

        # Live subscriber queues (one per connected WS client)
        self._subs: set[asyncio.Queue] = set()

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self, iface: str = "any", filter_str: str = "") -> str:
        """
        Determine capture mode and start.
        Returns the mode string, or raises RuntimeError if no method is available.
        filter_str is split on whitespace; numeric terms match ports, others match protocol.
        """
        if self._running:
            await self.stop()

        self._iface        = iface
        self._filter_terms = [t.lower() for t in filter_str.split() if t]
        loop = asyncio.get_event_loop()
        mode = await loop.run_in_executor(None, _determine_mode, iface)

        if mode == "unavailable":
            raise RuntimeError(
                "No capture method available. "
                "Run as Administrator for raw capture, or start a UDP feed on "
                f"port {UDP_SINK_PORT} (see: pixi run mock-device --mode feed)."
            )

        self._mode    = mode
        self._running = True
        print(f"[capture] starting — mode={mode!r}  iface={iface!r}")

        if mode == "real":
            bind_ip = get_capture_ip(iface)
            assert bind_ip is not None   # guaranteed: _determine_mode only returns "real" when bind_ip exists
            self._task = asyncio.create_task(self._real_loop(bind_ip))
        else:
            self._task = asyncio.create_task(self._listen_loop())

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
        """Clear buffer and all counters. Called on session reset."""
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

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _matches_filter(self, pkt: dict) -> bool:
        """Return True if pkt passes the active server-side filter (empty filter = pass all)."""
        if not self._filter_terms:
            return True
        src_port = str(pkt.get("src_port") or "")
        dst_port = str(pkt.get("dst_port") or "")
        protocol = (pkt.get("protocol") or "").lower()
        info     = (pkt.get("info") or "").lower()
        return any(
            t in src_port or t in dst_port or t in protocol or t in info
            for t in self._filter_terms
        )

    def _emit_packet(self, pkt: dict) -> None:
        """Assign a session-level ID, run interpreters, update counters, buffer, and broadcast."""
        # Extract and remove the internal payload field before serialising
        payload: bytes | None = pkt.pop("_payload", None)

        # Server-side filter: drop packets that don't match the active profile/filter
        if not self._matches_filter(pkt):
            return

        # Run the interpreter registry; attach decoded fields if a match is found
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
                pass  # slow subscriber — drop

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

    # ── Capture loops (each runs as an independent asyncio Task) ─────────────

    async def _run_sink(self, *, emit_stats: bool = True) -> None:
        """
        Run the UDP sink on UDP_SINK_PORT.
        Used standalone in listen mode; also spawned as a supplementary task in
        real mode so loopback UDP traffic (e.g. udp_device → 127.0.0.1:9001)
        is visible even though raw sockets cannot capture loopback packets.
        When emit_stats=False the stats tick is skipped (real_loop handles it).
        """
        loop = asyncio.get_event_loop()
        q: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue(maxsize=10_000)
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SinkProtocol(q),
                local_addr=("0.0.0.0", UDP_SINK_PORT),
            )
        except OSError as exc:
            print(f"[sink] could not bind UDP :{UDP_SINK_PORT} — {exc}")
            return

        print(f"[sink] listening on UDP :{UDP_SINK_PORT}")
        session_start = _get_session_start()
        last_tick     = loop.time()

        try:
            while self._running:
                while not q.empty():
                    data, (src_ip, src_port) = q.get_nowait()
                    now = datetime.now()
                    rel = time.time() - session_start
                    self._emit_packet({
                        "timestamp": f"{int(rel // 60):02d}:{rel % 60:06.3f}",
                        "abs_time":  now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}",
                        "src_ip":    src_ip,
                        "src_port":  src_port,
                        "dst_ip":    "127.0.0.1",
                        "dst_port":  UDP_SINK_PORT,
                        "protocol":  "UDP",
                        "length":    len(data),
                        "ttl":       64,
                        "flags":     None,
                        "info":      f"{src_ip}:{src_port} → :{UDP_SINK_PORT}  Len={len(data)}",
                        "raw_hex":   build_udp_raw_hex(src_ip, "127.0.0.1", src_port, UDP_SINK_PORT, data),
                        # Internal — consumed by _emit_packet to run interpreters
                        "_payload":  data,
                    })

                now_t = loop.time()
                if emit_stats and now_t - last_tick >= 1.0:
                    self._emit_stats()
                    last_tick = now_t
                await asyncio.sleep(0.02)
        except asyncio.CancelledError:
            pass
        finally:
            transport.close()

    async def _real_loop(self, bind_ip: str) -> None:
        cap  = RawCapture(bind_ip)
        cap.start(session_start=_get_session_start())
        loop       = asyncio.get_event_loop()
        last_tick  = loop.time()
        last_flush = loop.time()
        batch: list[dict] = []
        FLUSH_INTERVAL = 0.05

        # Supplement raw capture with a UDP sink so loopback traffic
        # (e.g. udp_device → 127.0.0.1:9001) is visible. Raw sockets
        # cannot capture loopback, so there is no double-capture risk.
        sink_task = asyncio.create_task(self._run_sink(emit_stats=False))

        try:
            while self._running:
                pkt = await loop.run_in_executor(None, cap.get_packet, 0.05)
                if pkt:
                    del pkt["id"]   # manager assigns session-level ID
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
            sink_task.cancel()
            try:
                await sink_task
            except asyncio.CancelledError:
                pass
            cap.stop()

    async def _listen_loop(self) -> None:
        await self._run_sink(emit_stats=True)



# Module-level singleton
manager = CaptureManager()


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/interfaces")
async def list_interfaces():
    """Return only interfaces that are up and have a non-loopback IPv4 address."""
    ifaces = []
    try:
        addr_map  = psutil.net_if_addrs()
        stats_map = psutil.net_if_stats()
        for name, addr_list in addr_map.items():
            # Skip interfaces that are down
            if name in stats_map and not stats_map[name].isup:
                continue
            ipv4 = next(
                (a.address for a in addr_list
                 if a.family.name == "AF_INET" and not a.address.startswith("127.")),
                None,
            )
            if ipv4 is None:
                continue
            ifaces.append({"name": name, "description": f"{name}  ({ipv4})", "ip": ipv4})
    except Exception as exc:
        print(f"[interfaces] {exc}")

    # Prepend "any" only when there are real interfaces to back it
    if ifaces:
        ifaces.insert(0, {"name": "any", "description": "Any interface", "ip": None})
    return {"interfaces": ifaces}


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/config")
async def config():
    return {"udp_sink_port": UDP_SINK_PORT}


@app.get("/api/profiles")
async def list_profiles():
    """Return the named capture profiles defined in profiles.py."""
    return {"profiles": PROFILES}


@app.get("/api/capture/status")
async def capture_status():
    return manager.status()


class StartRequest(BaseModel):
    interface: str = "any"
    filter:    str = ""


@app.post("/api/capture/start")
async def start_capture(req: StartRequest):
    try:
        mode = await manager.start(req.interface, req.filter)
        return {"status": "ok", "mode": mode}
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc)}


@app.post("/api/capture/stop")
async def stop_capture():
    await manager.stop()
    return {"status": "ok"}


@app.post("/api/reset-session")
async def reset_session():
    global _session_start
    _session_start = None
    manager.reset()
    return {"status": "ok"}


# ── WebSocket subscriber ──────────────────────────────────────────────────────

@app.websocket("/ws/capture")
async def ws_capture(websocket: WebSocket):
    await websocket.accept()

    # Immediately tell the client the current capture state
    await websocket.send_text(json.dumps({"type": "status", "data": manager.status()}))

    # Replay the rolling buffer so the client catches up on missed packets
    buf = manager.get_buffer()
    if buf:
        await websocket.send_text(json.dumps({"type": "batch", "data": buf}))

    q = manager.subscribe()

    async def _send() -> None:
        """Forward queued messages to the WebSocket."""
        while True:
            msg = await q.get()
            await websocket.send_text(msg)   # already JSON-encoded

    async def _recv() -> None:
        """Drain incoming frames so the WS stack detects disconnects."""
        while True:
            await websocket.receive_text()

    send_task = asyncio.create_task(_send())
    recv_task = asyncio.create_task(_recv())
    try:
        await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        send_task.cancel()
        recv_task.cancel()
        manager.unsubscribe(q)
        for t in [send_task, recv_task]:
            try:
                await t
            except (asyncio.CancelledError, WebSocketDisconnect, RuntimeError):
                pass


# ── Static file serving (production) ─────────────────────────────────────────

_static = Path(__file__).parent / "static"
if _static.exists():
    app.mount("/", StaticFiles(directory=str(_static), html=True), name="frontend")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
