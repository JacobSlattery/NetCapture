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
from typing import Sequence

import psutil
from fastapi import APIRouter, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ._manager import manager, reset_session_start, _get_session_start
from .interpreters import Interpreter, register


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
        from scapy.utils import rdpcap as _rdpcap
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


def create_router(
    *,
    profiles: list[dict] | None = None,
    extra_interpreters: Sequence[Interpreter] | None = None,
    address_book: list[dict] | None = None,
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
    """
    if extra_interpreters:
        for interp in extra_interpreters:
            register(interp)

    if profiles is None:
        from .profiles import DEFAULT_PROFILES
        profiles = DEFAULT_PROFILES

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
        ifaces.append({"name": "injected", "description": "WS Inject  (/ws/inject)", "ip": None})
        return {"interfaces": ifaces}

    @router.get("/api/health")
    async def health():
        return {"status": "ok"}

    @router.get("/api/profiles")
    async def list_profiles():
        return {"profiles": profiles}

    @router.get("/api/address-book")
    async def get_address_book():
        return {"entries": _address_book}

    @router.put("/api/address-book")
    async def put_address_book(payload: dict):
        nonlocal _address_book
        _address_book = payload.get("entries", [])
        return {"status": "ok"}

    @router.get("/api/capture/status")
    async def capture_status():
        return manager.status()

    @router.post("/api/capture/start")
    async def start_capture(req: StartRequest):
        try:
            mode = await manager.start(req.interface, req.filter, bpf_filter=req.bpf_filter)
            return {"status": "ok", "mode": mode}
        except RuntimeError as exc:
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
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, write_pcap, buf, None)
        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": 'attachment; filename="capture.pcap"'},
        )

    @router.post("/api/capture/import/pcap")
    async def import_pcap(file: UploadFile = File(...)):
        try:
            raw = await file.read()
            loop = asyncio.get_event_loop()
            imported = await loop.run_in_executor(None, _parse_pcap_bytes, raw)

            # Strip _payload (bytes) and run interpreters — mirrors _emit_packet
            from .interpreters import find_interpreter
            for p in imported:
                payload = p.pop("_payload", None)
                if payload:
                    frame = find_interpreter(p, payload)
                    if frame is not None:
                        p["decoded"] = frame.to_dict()

            manager.reset()
            for i, p in enumerate(imported, start=1):
                p["id"] = i
            manager._seq = len(imported)
            manager._buffer.extend(imported)

            msg = json.dumps({"type": "batch", "data": list(manager._buffer)})
            for q in list(manager._subs):
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    pass

            return {"status": "ok", "count": len(imported)}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.post("/api/capture/import/csv")
    async def import_csv(file: UploadFile = File(...)):
        try:
            raw = await file.read()
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

            manager.reset()
            for i, p in enumerate(imported, start=1):
                p["id"] = i
            manager._seq = len(imported)
            manager._buffer.extend(imported)

            msg = json.dumps({"type": "batch", "data": list(manager._buffer)})
            for q in list(manager._subs):
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    pass

            return {"status": "ok", "count": len(imported)}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    @router.get("/api/dns/resolve")
    async def dns_resolve(ip: str):
        loop = asyncio.get_event_loop()
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

                now     = _datetime.now()
                rel     = _time.time() - _get_session_start()
                ts_str  = f"{int(rel // 60):02d}:{rel % 60:06.3f}"
                abs_str = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"

                if not manager._running:
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
                    if payload_hex:
                        try:
                            pkt["_payload"] = bytes.fromhex(payload_hex)
                        except ValueError:
                            pass

                    manager._emit_packet(pkt)
                    injected += 1

                await websocket.send_text(json.dumps({"ok": True, "injected": injected}))

        except (WebSocketDisconnect, RuntimeError):
            pass

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
