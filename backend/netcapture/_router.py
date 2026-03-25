"""
NetCapture FastAPI router — mount this into any FastAPI application.

Usage:
    from netcapture import create_router
    app.include_router(create_router(), prefix="/netcapture")

Customisation:
    from netcapture import create_router, Interpreter, DecodedFrame, DecodedField

    class MyInterpreter:
        name = "My Protocol"
        def match(self, pkt: dict, payload: bytes) -> bool: ...
        def decode(self, payload: bytes) -> DecodedFrame: ...

    app.include_router(create_router(
        profiles=[
            {"id": "dev", "name": "My Device", "interface": "eth0", "filter": "port == 5000"},
        ],
        extra_interpreters=[MyInterpreter()],
    ), prefix="/netcapture")
"""

from __future__ import annotations

import asyncio
import csv as _csv
import io
import json
import socket as _dns_socket
import time as _time
from datetime import datetime as _datetime
from pathlib import Path
from typing import Sequence

import psutil
from fastapi import APIRouter, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ._manager import manager, reset_session_start, _get_session_start
from .interpreters import Interpreter, register
from .profiles import ProfileStore, DEFAULT_PROFILES
from .watchlists import WatchlistStore, DEFAULT_WATCHLISTS


def _parse_pcap_bytes(data: bytes) -> list[dict]:
    """
    Parse raw PCAP bytes into a list of frontend-compatible packet dicts.

    Tries scapy/rdpcap first (handles IPv4, IPv6, ARP, DNS, VLAN, etc.).
    Falls back to the stdlib struct reader + parse_packet() for IPv4-only
    if scapy is unavailable or the parse fails.
    """
    import time as _time
    from datetime import datetime as _datetime

    # ── scapy path ────────────────────────────────────────────────────────────
    try:
        from scapy.utils import rdpcap as _rdpcap # type: ignore
        from .capture_scapy import _parse_scapy

        pkts = _rdpcap(io.BytesIO(data))
        if not pkts:
            return []

        first_epoch = float(pkts[0].time)
        results: list[dict] = []
        for seq, pkt in enumerate(pkts, start=1):
            pkt_epoch  = float(pkt.time)
            # Reconstruct a fake start_time so rel = pkt_epoch - first_epoch
            fake_start = _time.time() - (pkt_epoch - first_epoch)
            parsed = _parse_scapy(pkt, fake_start, seq)
            if parsed is None:
                continue
            # Overwrite abs_time with the real PCAP wall-clock timestamp
            dt = _datetime.fromtimestamp(pkt_epoch)
            parsed["abs_time"] = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
            parsed["_epoch_ts"] = pkt_epoch
            results.append(parsed)
        return results

    except Exception:
        pass

    # ── stdlib fallback (IPv4 only) ───────────────────────────────────────────
    from .pcap_io import read_pcap
    from .capture import parse_packet

    _linktype, frames = read_pcap(data)
    first_epoch: float | None = None
    results = []
    for seq, frame in enumerate(frames, start=1):
        pkt_epoch = frame.get("_epoch_ts", _time.time())
        if first_epoch is None:
            first_epoch = pkt_epoch
        fake_start = _time.time() - (pkt_epoch - first_epoch)
        raw = bytes.fromhex(frame["raw_hex"])
        parsed = parse_packet(raw, fake_start, seq)
        if parsed is None:
            continue
        dt = _datetime.fromtimestamp(pkt_epoch)
        parsed["abs_time"] = dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        parsed["_epoch_ts"] = pkt_epoch
        results.append(parsed)
    return results


def _normalize_inject_packet(pkt: dict) -> None:
    """Fill in default fields and decode ``payload_hex`` → ``_payload`` in-place."""
    now     = _datetime.now()
    rel     = _time.time() - _get_session_start()
    ts_str  = f"{int(rel // 60):02d}:{rel % 60:06.3f}"
    abs_str = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"

    pkt.setdefault("abs_time",  abs_str)
    pkt.setdefault("timestamp", ts_str)
    pkt.setdefault("src_ip",    None)
    pkt.setdefault("dst_ip",    None)
    pkt.setdefault("src_port",  None)
    pkt.setdefault("dst_port",  None)
    pkt.setdefault("protocol",  "Unknown")
    pkt.setdefault("length",    0)
    pkt.setdefault("info",      "")
    pkt.setdefault("raw_hex",   "")
    pkt.setdefault("ttl",       None)
    pkt.setdefault("flags",     None)

    payload_hex = pkt.pop("payload_hex", None)
    if payload_hex and len(payload_hex) <= 131072:  # 64 KB decoded
        try:
            pkt["_payload"] = bytes.fromhex(payload_hex)
        except ValueError:
            pass


def inject_packet(pkt: dict) -> bool:
    """
    Inject a single packet directly into the live stream from Python code.

    This is the zero-overhead path for callers that run **in the same process**
    as NetCapture.  The packet bypasses all network and WebSocket machinery and
    is handed straight to the capture manager.

    Parameters
    ----------
    pkt:
        Packet dict.  Accepts the same fields as the ``/ws/inject`` WebSocket
        endpoint (``protocol``, ``length``, ``src_ip``, ``dst_ip``,
        ``src_port``, ``dst_port``, ``info``, ``raw_hex``, ``payload_hex``,
        ``abs_time``, ``timestamp``).  Missing fields are filled with defaults.
        The dict is modified in-place.

    Returns
    -------
    bool
        ``True`` if the packet was accepted and emitted.
        ``False`` if capture is not currently running (packet discarded).

    Example
    -------
    ::

        import netcapture

        netcapture.inject_packet({
            "protocol":    "UDP",
            "length":      48,
            "src_ip":      "192.168.1.50",
            "dst_ip":      "192.168.1.1",
            "src_port":    9001,
            "dst_port":    9001,
            "info":        "sensor reading",
            "payload_hex": "4e430108...",
        })
    """
    if not manager.is_running:
        return False
    _normalize_inject_packet(pkt)
    manager._emit_packet(pkt)
    return True


def inject_batch(packets: list[dict]) -> int:
    """
    Inject multiple packets in a single batched broadcast.

    This is the high-throughput variant of :func:`inject_packet`.  All packets
    are normalized, processed, and then broadcast as one WebSocket message —
    significantly more efficient than calling ``inject_packet()`` in a loop
    when sending many packets at once.

    Parameters
    ----------
    packets:
        List of packet dicts (same format as ``inject_packet``).
        Each dict is modified in-place.

    Returns
    -------
    int
        Number of packets accepted and emitted.  Returns ``0`` if capture
        is not currently running (all packets discarded).
    """
    if not manager.is_running:
        return 0
    ready: list[dict] = []
    for pkt in packets:
        if not isinstance(pkt, dict):
            continue
        _normalize_inject_packet(pkt)
        processed = manager._process_packet(pkt, apply_filter=False)
        if processed is not None:
            ready.append(processed)
    manager._broadcast_batch(ready)
    return len(ready)


async def start_capture(
    interface: str = "injected",
    filter: str = "",
    bpf_filter: str = "",
) -> str:
    """
    Start the capture engine programmatically.

    This is the in-process equivalent of ``POST /api/capture/start``.
    Defaults to ``interface="injected"`` (injection-only mode — no network
    capture, just accept packets from ``inject_packet`` / ``inject_batch``).

    Parameters
    ----------
    interface:
        Network interface name (``"any"``, ``"Ethernet"``, ``"loopback"``,
        etc.) or ``"injected"`` for injection-only mode.
    filter:
        Python-style capture filter (e.g. ``"port == 5000"``).
    bpf_filter:
        BPF filter string (npcap mode only).

    Returns
    -------
    str
        The capture mode that was started (``"inject"``, ``"scapy"``,
        ``"real"``).

    Raises
    ------
    RuntimeError
        If no capture method is available for the requested interface.
    """
    return await manager.start(interface, filter, bpf_filter=bpf_filter)


async def stop_capture() -> None:
    """
    Stop the capture engine programmatically.

    This is the in-process equivalent of ``POST /api/capture/stop``.
    Safe to call even when capture is not running.
    """
    await manager.stop()


def reset_session() -> None:
    """
    Reset the session timer and clear the packet buffer.

    This is the in-process equivalent of ``POST /api/reset-session``.
    """
    reset_session_start()
    manager.reset()


def get_status() -> dict:
    """
    Return the current capture status.

    This is the in-process equivalent of ``GET /api/capture/status``.

    Returns
    -------
    dict
        Keys: ``running`` (bool), ``mode`` (str), ``iface`` (str),
        ``packets`` (int).
    """
    return manager.status()


def get_buffer() -> list[dict]:
    """
    Return a snapshot of the current packet buffer.

    Returns a list of all packets currently in the rolling buffer (up to
    ``CaptureManager.BUFFER_SIZE`` most recent packets).  Each entry is
    a fully processed packet dict with ``id``, ``protocol``, ``decoded``,
    etc.

    The returned list is a copy — mutating it does not affect the internal
    buffer.
    """
    return manager.get_buffer()


def on_packet(callback) -> None:
    """
    Register a callback that fires for every captured or injected packet.

    The callback receives a single argument: the processed packet dict
    (same shape as the dicts in :func:`get_buffer`).  It is called
    synchronously on the asyncio event loop thread — keep it lightweight
    or offload heavy work to a thread/queue.

    **Do not mutate the dict** — it is shared with the packet buffer and
    WebSocket serialisation path.

    Can also be used as a decorator::

        @netcapture.on_packet
        def handle(pkt):
            print(pkt["protocol"], pkt.get("decoded"))

    Parameters
    ----------
    callback:
        ``(pkt: dict) -> None``
    """
    if callback not in manager._packet_cbs:
        manager._packet_cbs.append(callback)
    return callback  # allow decorator usage


def off_packet(callback) -> None:
    """
    Unregister a packet callback previously registered with :func:`on_packet`.
    """
    try:
        manager._packet_cbs.remove(callback)
    except ValueError:
        pass


def on_stats(callback) -> None:
    """
    Register a callback that fires on every stats tick (~1 second).

    The callback receives a dict with keys: ``total_packets``,
    ``total_bytes``, ``packets_per_sec``, ``bytes_per_sec``,
    ``protocol_counts``.

    Can also be used as a decorator::

        @netcapture.on_stats
        def handle(stats):
            print(f"{stats['packets_per_sec']} pkt/s")
    """
    if callback not in manager._stats_cbs:
        manager._stats_cbs.append(callback)
    return callback


def off_stats(callback) -> None:
    """
    Unregister a stats callback previously registered with :func:`on_stats`.
    """
    try:
        manager._stats_cbs.remove(callback)
    except ValueError:
        pass


class PacketStream:
    """
    Async iterator that yields packet dicts as they arrive.

    The queue is registered immediately on construction so that packets
    injected between creation and the first iteration are not lost.

    Usage::

        async for pkt in netcapture.packet_stream():
            print(pkt["src_ip"], "→", pkt["dst_ip"])
            if should_stop:
                break

        # Or with manual lifecycle:
        stream = netcapture.packet_stream()
        pkt = await stream.__anext__()
        stream.close()  # unregisters from the manager

    Parameters
    ----------
    queue_size:
        Maximum number of packets buffered before new arrivals are dropped.
    """

    __slots__ = ("_q",)

    def __init__(self, queue_size: int = 1000) -> None:
        self._q: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        manager._packet_queues.add(self._q)

    def __aiter__(self):
        return self

    async def __anext__(self) -> dict:
        return await self._q.get()

    def close(self) -> None:
        """Unregister the queue from the manager."""
        manager._packet_queues.discard(self._q)

    async def aclose(self) -> None:
        """Async close for ``async for`` cleanup."""
        self.close()


def packet_stream(*, queue_size: int = 1000) -> PacketStream:
    """
    Create an async iterator that yields packet dicts as they arrive.

    The returned :class:`PacketStream` registers its queue **immediately**,
    so packets injected between creation and the first ``await`` are captured.

    Usage::

        async for pkt in netcapture.packet_stream():
            print(pkt["src_ip"], "→", pkt["dst_ip"])
            if should_stop:
                break  # cleanup is automatic

    Or with explicit lifecycle::

        stream = netcapture.packet_stream()
        try:
            pkt = await stream.__anext__()
        finally:
            stream.close()

    Parameters
    ----------
    queue_size:
        Maximum number of packets buffered before new arrivals are dropped.
        Increase for bursty high-volume traffic.
    """
    return PacketStream(queue_size)


async def _inject_ws_handler(websocket: WebSocket) -> None:
    """
    Core WebSocket injection handler — shared by the router endpoint and
    :func:`start_inject_server`.
    """
    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                await websocket.send_text(json.dumps({"ok": False, "error": str(exc)}))
                continue

            packets = data if isinstance(data, list) else [data]

            if not manager.is_running:
                await websocket.send_text(json.dumps({
                    "ok": False,
                    "discarded": len([p for p in packets if isinstance(p, dict)]),
                    "error": "capture not running",
                }))
                continue

            injected = 0
            for pkt in packets:
                if not isinstance(pkt, dict):
                    continue
                _normalize_inject_packet(pkt)
                manager._emit_packet(pkt)
                injected += 1

            await websocket.send_text(json.dumps({"ok": True, "injected": injected}))

    except (WebSocketDisconnect, RuntimeError):
        pass


async def start_inject_server(host: str = "0.0.0.0", port: int = 8765) -> None:
    """
    Run a standalone WebSocket injection server on a dedicated port.

    Useful when NetCapture is embedded inside a larger FastAPI application and
    you need the injection endpoint on its own port — separate from the main
    application port.

    The server exposes a single endpoint at ``/ws/inject`` and accepts the same
    JSON packet format as the router's ``/ws/inject`` endpoint.

    Parameters
    ----------
    host:
        Interface to bind.  Defaults to ``"0.0.0.0"`` (all interfaces).
    port:
        TCP port to listen on.  Defaults to ``8765``.

    Usage
    -----
    Start from your app's lifespan (recommended)::

        import asyncio
        from contextlib import asynccontextmanager
        import netcapture

        @asynccontextmanager
        async def lifespan(app):
            task = asyncio.create_task(
                netcapture.start_inject_server(host="0.0.0.0", port=9000)
            )
            yield
            task.cancel()

        app = FastAPI(lifespan=lifespan)
        app.include_router(netcapture.create_router(), prefix="/netcapture")

    Injectors then connect to ``ws://yourhost:9000/ws/inject`` regardless of
    which port the main FastAPI application is running on.
    """
    import contextlib
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import WebSocketRoute

    class _Server(uvicorn.Server):
        """Uvicorn server that skips signal-handler installation.

        When running as an asyncio task inside an existing uvicorn process the
        default ``capture_signals`` implementation would replace the outer
        server's SIGTERM/SIGINT handlers with its own.  Returning a no-op
        context manager prevents that conflict while still allowing the outer
        process to handle shutdown normally.
        """
        def capture_signals(self):  # type: ignore[override]
            return contextlib.nullcontext()

    inject_app = Starlette(routes=[WebSocketRoute("/ws/inject", _inject_ws_handler)])
    config = uvicorn.Config(inject_app, host=host, port=port, log_level="warning")
    try:
        await _Server(config).serve()
    except OSError as exc:
        print(
            f"[netcapture] inject server could not bind to {host}:{port} — {exc}. "
            "The main application continues; WebSocket injection on this port is unavailable."
        )


def _parse_addr(addr: str) -> tuple[str, int | None]:
    """Split 'host:port' into (host, port), handling bare IPv6 addresses."""
    if not addr:
        return ("", None)
    colon_count = addr.count(":")
    if colon_count > 1:
        # Looks like IPv6 — only treat last segment as port if it's numeric ≤65535
        # and the remainder is still a plausible address (contains at least one more colon)
        last = addr.rfind(":")
        tail = addr[last + 1:]
        head = addr[:last]
        if tail.isdigit() and 1 <= int(tail) <= 65535 and ":" in head:
            return (head, int(tail))
        return (addr, None)
    if colon_count == 1:
        head, tail = addr.rsplit(":", 1)
        if tail.isdigit() and 1 <= int(tail) <= 65535:
            return (head, int(tail))
    return (addr, None)


class StartRequest(BaseModel):
    interface:  str = "any"
    filter:     str = ""
    bpf_filter: str = ""


class ProfileBody(BaseModel):
    name:        str
    description: str = ""
    interface:   str = ""
    filter:      str = ""
    bpf_filter:  str = ""
    inject:      bool = False


MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB


def create_router(
    *,
    profiles: list[dict] | None = None,
    extra_interpreters: Sequence[Interpreter] | None = None,
    address_book: list[dict] | None = None,
    watchlists: list[dict] | None = None,
    profiles_path: Path | str | None = Path.home() / ".netcapture" / "profiles.json",
    watchlists_path: Path | str | None = Path.home() / ".netcapture" / "watchlists.json",
) -> APIRouter:
    """
    Return an APIRouter with all NetCapture HTTP and WebSocket routes.

    Parameters
    ----------
    profiles:
        List of profile dicts to expose via /api/profiles.  Each dict must
        have at least ``id``, ``name``, ``interface``, and ``filter`` keys.
        If omitted, the built-in default profiles from profiles.py are used.
    extra_interpreters:
        Additional interpreter instances to register before capture starts.
        Interpreters are tried in order (built-ins first, then these) and the
        first one whose match() returns True handles the packet.
        Each interpreter must implement the Interpreter protocol:
          - name: str
          - match(pkt: dict, payload: bytes) -> bool
          - decode(payload: bytes) -> DecodedFrame
    watchlists:
        List of watchlist entry dicts to expose via /api/watchlists.  Each
        dict must have at least ``id``, ``label``, ``fieldPath``, and
        ``matcher`` keys.  If omitted, an empty default list is used.
    """
    if extra_interpreters:
        for interp in extra_interpreters:
            register(interp)

    _store = ProfileStore(
        defaults=profiles if profiles is not None else DEFAULT_PROFILES,
        path=Path(profiles_path) if profiles_path is not None else None,
    )

    _wl_store = WatchlistStore(
        defaults=watchlists if watchlists is not None else DEFAULT_WATCHLISTS,
        path=Path(watchlists_path) if watchlists_path is not None else None,
    )

    _address_book: list[dict] = list(address_book) if address_book else []

    router = APIRouter()

    @router.get("/api/capture/capabilities")
    async def capture_capabilities():
        try:
            from .capture_scapy import probe_npcap
            npcap = probe_npcap()
        except ImportError:
            npcap = False
        return {"npcap": npcap}

    @router.get("/api/interfaces")
    async def list_interfaces():
        ifaces = []
        try:
            addr_map  = psutil.net_if_addrs()
            stats_map = psutil.net_if_stats()
            for name, addr_list in addr_map.items():
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

        if ifaces:
            ifaces.insert(0, {"name": "any", "description": "Any interface", "ip": None})
            # Add loopback when Npcap is available — it can capture 127.0.0.1 traffic
            # that raw sockets and normal adapters cannot see.
            try:
                from .capture_scapy import probe_npcap
                if probe_npcap():
                    ifaces.append({"name": "loopback", "description": "Loopback  (127.0.0.1)", "ip": "127.0.0.1"})
            except ImportError:
                pass
        return {"interfaces": ifaces}

    @router.get("/api/health")
    async def health():
        return {"status": "ok"}

    @router.get("/api/profiles")
    async def list_profiles():
        return {"profiles": _store.list()}

    @router.post("/api/profiles")
    async def create_profile(body: ProfileBody):
        profile = _store.create(body.model_dump())
        return {"profile": profile}

    @router.put("/api/profiles/{profile_id}")
    async def update_profile(profile_id: str, body: ProfileBody):
        updated = _store.update(profile_id, body.model_dump())
        if updated is None:
            raise HTTPException(status_code=404, detail="Profile not found or is a built-in")
        return {"profile": updated}

    @router.delete("/api/profiles/{profile_id}")
    async def delete_profile(profile_id: str):
        if not _store.delete(profile_id):
            raise HTTPException(status_code=404, detail="Profile not found or is a built-in")
        return {"status": "ok"}

    # ── Watchlist CRUD ────────────────────────────────────────────────────────

    @router.get("/api/watchlists")
    async def list_watchlists():
        return {"watchlists": _wl_store.list()}

    @router.post("/api/watchlists")
    async def create_watchlist(body: dict):
        entry = _wl_store.create(body)
        return {"watchlist": entry}

    @router.put("/api/watchlists/{entry_id}")
    async def update_watchlist(entry_id: str, body: dict):
        updated = _wl_store.update(entry_id, body)
        if updated is None:
            raise HTTPException(status_code=404, detail="Watchlist entry not found or is a built-in")
        return {"watchlist": updated}

    @router.delete("/api/watchlists/{entry_id}")
    async def delete_watchlist(entry_id: str):
        if not _wl_store.delete(entry_id):
            raise HTTPException(status_code=404, detail="Watchlist entry not found or is a built-in")
        return {"status": "ok"}

    @router.put("/api/watchlists")
    async def replace_watchlists(payload: dict):
        entries = payload.get("entries", [])
        if not isinstance(entries, list):
            raise HTTPException(status_code=400, detail="Expected 'entries' array")
        result = _wl_store.replace_all(entries)
        return {"watchlists": result}

    # ── Address book ──────────────────────────────────────────────────────────

    @router.get("/api/address-book")
    async def get_address_book():
        return {"entries": _address_book}

    MAX_ADDRESS_BOOK_ENTRIES = 1000

    @router.put("/api/address-book")
    async def put_address_book(payload: dict):
        nonlocal _address_book
        entries = payload.get("entries", [])
        if not isinstance(entries, list) or len(entries) > MAX_ADDRESS_BOOK_ENTRIES:
            raise HTTPException(status_code=400, detail=f"entries must be a list with at most {MAX_ADDRESS_BOOK_ENTRIES} items")
        _address_book = entries
        return {"status": "ok"}

    @router.get("/api/capture/status")
    async def capture_status():
        return manager.status()

    @router.post("/api/capture/start")
    async def start_capture(req: StartRequest):
        try:
            mode = await manager.start(req.interface, req.filter, bpf_filter=req.bpf_filter)
            return {"status": "ok", "mode": mode}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.post("/api/capture/stop")
    async def stop_capture():
        await manager.stop()
        return {"status": "ok"}

    @router.post("/api/reset-session")
    async def reset_session():
        reset_session_start()
        manager.reset()
        return {"status": "ok"}

    @router.get("/api/capture/export/pcap")
    async def export_pcap():
        from .pcap_io import write_pcap
        buf = manager.get_buffer()
        if not buf:
            return {"status": "error", "message": "No packets to export"}
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(None, write_pcap, buf, None)
        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": 'attachment; filename="capture.pcap"'},
        )

    @router.post("/api/capture/import/pcap")
    async def import_pcap(file: UploadFile = File(...)):
        try:
            raw = await file.read(MAX_UPLOAD_BYTES + 1)
            if len(raw) > MAX_UPLOAD_BYTES:
                return {"status": "error", "message": f"File too large (max {MAX_UPLOAD_BYTES // (1024*1024)} MB)"}
            loop = asyncio.get_running_loop()
            imported = await loop.run_in_executor(None, _parse_pcap_bytes, raw)

            # Strip _payload (bytes) and run interpreters — mirrors _emit_packet
            from .interpreters import find_interpreter
            for p in imported:
                payload = p.pop("_payload", None)
                # _header_bytes/_payload_offset stay in p during interpreter call
                if payload:
                    frame = find_interpreter(p, payload)
                    if frame is not None:
                        decoded = frame.to_dict()
                        if p.get("_payload_offset"):
                            decoded["payloadOffset"] = p["_payload_offset"]
                        p["decoded"] = decoded
                p.pop("_header_bytes",   None)
                p.pop("_payload_offset", None)

            count = await manager.import_packets(imported)
            return {"status": "ok", "count": count}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.post("/api/capture/import/csv")
    async def import_csv(file: UploadFile = File(...)):
        try:
            raw = await file.read(MAX_UPLOAD_BYTES + 1)
            if len(raw) > MAX_UPLOAD_BYTES:
                return {"status": "error", "message": f"File too large (max {MAX_UPLOAD_BYTES // (1024*1024)} MB)"}
            text = raw.decode("utf-8-sig")  # strip BOM if present
            reader = _csv.DictReader(io.StringIO(text))
            imported: list[dict] = []
            for row in reader:
                src_ip, src_port = _parse_addr(row.get("Source", ""))
                dst_ip, dst_port = _parse_addr(row.get("Destination", ""))
                try:
                    length = int(row.get("Length", 0) or 0)
                except ValueError:
                    length = 0
                imported.append({
                    "timestamp": row.get("Time", ""),
                    "abs_time":  row.get("Time", ""),
                    "src_ip":    src_ip,
                    "src_port":  src_port,
                    "dst_ip":    dst_ip,
                    "dst_port":  dst_port,
                    "protocol":  row.get("Protocol", ""),
                    "length":    length,
                    "info":      row.get("Info", ""),
                    "raw_hex":   "",
                    "_epoch_ts": 0.0,
                })

            count = await manager.import_packets(imported)
            return {"status": "ok", "count": count}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.get("/api/dns/resolve")
    async def dns_resolve(ip: str):
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _dns_socket.gethostbyaddr, ip),
                timeout=2.0,
            )
            hostname = result[0]
            # Strip trailing dot and skip raw-IP results
            if hostname and hostname != ip:
                return {"ip": ip, "hostname": hostname}
        except Exception:
            pass
        return {"ip": ip, "hostname": None}

    @router.websocket("/ws/inject")
    async def ws_inject(websocket: WebSocket):
        """
        Inject packets from an external program into the live stream.

        Each WebSocket message must be a JSON object (single packet) or a JSON
        array (batch).  The server runs every packet through the full pipeline:
        display-filter matching, protocol interpreter (NC-Frame, etc.), ID
        assignment, stats counters, and live broadcast to all frontend clients.

        Packet fields
        -------------
        Required:
          protocol   str   e.g. "UDP", "TCP", "NC-Frame"
          length     int   wire-length in bytes

        Recommended:
          src_ip     str   source address
          dst_ip     str   destination address
          src_port   int
          dst_port   int
          info       str   one-line summary shown in the packet table
          raw_hex    str   full packet bytes as a hex string (enables hex viewer)

        Optional (auto-generated if omitted):
          abs_time   str   "HH:MM:SS.mmm"
          timestamp  str   "MM:SS.mmm" relative to session start

        Interpreter support:
          payload_hex  str  hex string of the application-layer payload passed
                            to registered interpreters (e.g. NC-Frame decoder).
                            If omitted, no interpreter is attempted.

        Responses
        ---------
        After each message the server sends:
          {"ok": true,  "injected": N}   — N packets accepted and emitted
          {"ok": false, "error": "..."}  — JSON parse failure
        """
        await _inject_ws_handler(websocket)

    @router.websocket("/ws/capture")
    async def ws_capture(websocket: WebSocket):
        await websocket.accept()

        await websocket.send_text(json.dumps({"type": "status", "data": manager.status()}))

        buf = manager.get_buffer()
        if buf:
            await websocket.send_text(json.dumps({"type": "batch", "data": buf}))

        q = manager.subscribe()

        async def _send() -> None:
            while True:
                msg = await q.get()
                await websocket.send_text(msg)

        async def _recv() -> None:
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

    return router
