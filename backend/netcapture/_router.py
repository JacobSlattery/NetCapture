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
import json
from typing import Sequence

import psutil
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .capture import UDP_SINK_PORT
from ._manager import manager, reset_session_start
from .interpreters import Interpreter, register


class StartRequest(BaseModel):
    interface: str = "any"
    filter:    str = ""


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
        return {"interfaces": ifaces}

    @router.get("/api/health")
    async def health():
        return {"status": "ok"}

    @router.get("/api/config")
    async def config():
        return {"udp_sink_port": UDP_SINK_PORT}

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
            mode = await manager.start(req.interface, req.filter)
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
