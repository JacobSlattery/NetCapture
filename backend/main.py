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

Capture modes (selected automatically at start, highest priority first):
  scapy  — Npcap + scapy full L2 capture (requires npcap pixi env + Npcap installed)
  real   — Windows raw sockets + SIO_RCVALL (needs Administrator, IP-only)
  listen — UDP sink on UDP_SINK_PORT; feed with: pixi run mock-device --mode feed
"""

from __future__ import annotations

import asyncio
import json
import re
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


# ── Wireshark-style filter parser (server-side) ───────────────────────────────
#
# Mirrors the TypeScript implementation in frontend/src/lib/filter.ts.
# Supports the same grammar so profile filters and user-typed filters are
# interpreted identically on both sides.

_KNOWN_FILTER_FIELDS = {
    'ip.src', 'ip.dst', 'ip.addr',
    'port', 'src.port', 'dst.port',
    'tcp.port', 'udp.port',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
    'proto', 'ip.proto', 'protocol',
    'info', 'frame.info',
    'interpreter',
}

def _flatten_decoded(v) -> list[str]:
    """Recursively collect all leaf values from a DecodedValue as lowercase strings."""
    if v is None:
        return []
    if isinstance(v, bool):
        return [str(v).lower()]
    if isinstance(v, (int, float)):
        return [str(v)]
    if isinstance(v, str):
        return [v.lower()]
    if isinstance(v, list):
        out: list[str] = []
        for item in v:
            out.extend(_flatten_decoded(item))
        return out
    if isinstance(v, dict):
        out = []
        for item in v.values():
            out.extend(_flatten_decoded(item))
        return out
    return [str(v).lower()]


def _resolve_decoded_path(v, path: list[str]) -> list[str]:
    """Navigate a decoded value along path segments, then flatten the result.
    e.g. path=['fw'] on {'fw': '1.2.3'} → ['1.2.3']
    Lists are searched element-by-element at each step.
    """
    if not path:
        return _flatten_decoded(v)
    head, *rest = path
    if isinstance(v, list):
        out: list[str] = []
        for item in v:
            out.extend(_resolve_decoded_path(item, path))
        return out
    if isinstance(v, dict):
        key = next((k for k in v if k.lower() == head), None)
        if key is None:
            return []
        return _resolve_decoded_path(v[key], rest)
    return []  # primitive with remaining path — no match


_PORT_FILTER_FIELDS = {
    'port', 'src.port', 'dst.port',
    'tcp.port', 'udp.port',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
}


def _filter_tokenize(src: str) -> list[tuple[str, str]]:
    """Return list of (kind, value) tokens."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(src):
        if src[i].isspace():
            i += 1
            continue
        # Quoted string
        if src[i] in ('"', "'"):
            q = src[i]; i += 1; s = ''
            while i < len(src) and src[i] != q:
                if src[i] == '\\':
                    i += 1
                s += src[i]; i += 1
            if i >= len(src):
                raise ValueError('Unterminated string literal')
            i += 1
            tokens.append(('word', s))
            continue
        two = src[i:i+2]
        if two == '==': tokens.append(('eq',  '==')); i += 2; continue
        if two == '!=': tokens.append(('neq', '!=')); i += 2; continue
        if two == '&&': tokens.append(('and', '&&')); i += 2; continue
        if two == '||': tokens.append(('or',  '||')); i += 2; continue
        if src[i] == '!': tokens.append(('not', '!')); i += 1; continue
        if src[i] == '(': tokens.append(('lp',  '(')); i += 1; continue
        if src[i] == ')': tokens.append(('rp',  ')')); i += 1; continue
        if src[i].isalnum() or src[i] in '._':
            w = ''
            while i < len(src) and (src[i].isalnum() or src[i] in '._-:/'):
                w += src[i]; i += 1
            lower = w.lower()
            if   lower == 'and':      tokens.append(('and',      w))
            elif lower == 'or':       tokens.append(('or',       w))
            elif lower == 'not':      tokens.append(('not',      w))
            elif lower == 'contains': tokens.append(('contains', w))
            else:                     tokens.append(('word',     w))
            continue
        raise ValueError(f"Unexpected character '{src[i]}' at position {i}")
    return tokens


class _FilterParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self._tokens = tokens
        self._i      = 0

    def _peek(self) -> tuple[str, str] | None:
        return self._tokens[self._i] if self._i < len(self._tokens) else None

    def _next(self) -> tuple[str, str]:
        t = self._tokens[self._i]; self._i += 1; return t

    def _eat(self, kind: str) -> tuple[str, str]:
        t = self._next()
        if t[0] != kind:
            raise ValueError(f"Expected {kind}, got '{t[1]}'")
        return t

    def parse(self):  # type: ignore[return]
        if not self._tokens:
            raise ValueError('Empty filter')
        e = self._parse_or()
        if self._peek():
            raise ValueError(f"Unexpected '{self._peek()[1]}'")  # type: ignore[index]
        return e

    def _parse_or(self):
        e = self._parse_and()
        while self._peek() and self._peek()[0] == 'or':
            self._next()
            e = ('or', e, self._parse_and())
        return e

    def _parse_and(self):
        e = self._parse_not()
        while self._peek() and self._peek()[0] == 'and':
            self._next()
            e = ('and', e, self._parse_not())
        return e

    def _parse_not(self):
        if self._peek() and self._peek()[0] == 'not':
            self._next()
            return ('not', self._parse_not())
        return self._parse_atom()

    def _parse_atom(self):
        t = self._peek()
        if not t:
            raise ValueError('Expected an expression')
        if t[0] == 'lp':
            self._next()
            e = self._parse_or()
            self._eat('rp')
            return e
        if t[0] == 'word':
            word_tok = self._next()
            field    = word_tok[1].lower()
            op_tok   = self._peek()
            if op_tok and op_tok[0] in ('eq', 'neq', 'contains'):
                if field not in _KNOWN_FILTER_FIELDS and not field.startswith('decoded.'):
                    raise ValueError(f"Unknown field '{word_tok[1]}'")
                self._next()  # consume op
                val_tok = self._peek()
                if not val_tok or val_tok[0] != 'word':
                    raise ValueError(f"Expected a value after '{op_tok[1]}'")
                self._next()  # consume value
                return ('cmp', field, op_tok[1], val_tok[1])
            return ('bare', field)
        raise ValueError(f"Unexpected '{t[1]}'")


def _filter_eval(node, pkt: dict) -> bool:
    kind = node[0]
    if kind == 'and':  return _filter_eval(node[1], pkt) and _filter_eval(node[2], pkt)
    if kind == 'or':   return _filter_eval(node[1], pkt) or  _filter_eval(node[2], pkt)
    if kind == 'not':  return not _filter_eval(node[1], pkt)
    if kind == 'bare': return (pkt.get('protocol') or '').lower() == node[1]
    if kind == 'cmp':
        _, field, op, raw_val = node
        v        = raw_val.lower()
        src_port = str(pkt.get('src_port') or '')
        dst_port = str(pkt.get('dst_port') or '')
        src_ip   = (pkt.get('src_ip')  or '').lower()
        dst_ip   = (pkt.get('dst_ip')  or '').lower()
        proto    = (pkt.get('protocol') or '').lower()
        info     = (pkt.get('info')    or '').lower()

        if   field == 'ip.src':                               candidates = [src_ip]
        elif field == 'ip.dst':                               candidates = [dst_ip]
        elif field == 'ip.addr':                              candidates = [src_ip, dst_ip]
        elif field in ('port', 'tcp.port', 'udp.port'):       candidates = [src_port, dst_port]
        elif field in ('src.port', 'tcp.srcport', 'udp.srcport'): candidates = [src_port]
        elif field in ('dst.port', 'tcp.dstport', 'udp.dstport'): candidates = [dst_port]
        elif field in ('proto', 'ip.proto', 'protocol'):      candidates = [proto]
        elif field in ('info', 'frame.info'):                 candidates = [info]
        elif field == 'interpreter':
            decoded = pkt.get('decoded') or {}
            candidates = [(decoded.get('interpreterName') or '').lower()]
        elif field.startswith('decoded.'):
            key     = field[len('decoded.'):]
            decoded = pkt.get('decoded') or {}
            fields  = decoded.get('fields') or []
            parts     = key.split('.')
            field_key = parts[0]
            nested    = parts[1:]
            match     = next((f for f in fields if (f.get('key') or '').lower() == field_key), None)
            candidates = _resolve_decoded_path(match['value'], nested) if match is not None else []
        else:                                                  return False

        is_port = field in _PORT_FILTER_FIELDS
        is_info = field in ('info', 'frame.info')

        if op in ('==', 'contains'):
            if op == 'contains':
                return any(v in c for c in candidates)
            if is_port:
                return any(c == v for c in candidates)
            if is_info:
                return any(v in c for c in candidates)
            return any(c == v for c in candidates)
        if op == '!=':
            if is_port: return all(c != v for c in candidates)
            if is_info: return all(v not in c for c in candidates)
            return all(c != v for c in candidates)
    return False
from interpreters import find_interpreter
from profiles import PROFILES

# Optional scapy/Npcap backend — only available in the npcap pixi environment
try:
    from capture_scapy import ScapyCapture, SCAPY_AVAILABLE, probe_npcap
except ImportError:
    SCAPY_AVAILABLE = False
    ScapyCapture    = None  # type: ignore[assignment,misc]
    def probe_npcap() -> bool: return False  # noqa: E704

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
    Returns 'scapy', 'real', 'listen', or 'unavailable'.

    Priority:
      scapy  — npcap installed + scapy package available (full L2 capture)
      real   — Windows raw sockets + SIO_RCVALL (needs Administrator, IP-only)
      listen — UDP sink on UDP_SINK_PORT (no admin required)
    """
    # Prefer scapy/npcap: captures ARP, full Ethernet frames, all interfaces
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

        # Active server-side filter (empty = pass all)
        self._filter_terms: list[str] = []
        self._filter_ast = None   # parsed AST, built once at start()

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
        self._filter_terms = filter_str.split() if filter_str.strip() else []
        self._filter_ast   = None
        if self._filter_terms:
            try:
                tokens = _filter_tokenize(filter_str.strip())
                self._filter_ast = _FilterParser(tokens).parse()
            except ValueError as exc:
                print(f"[filter] parse error — treating as pass-all: {exc}")
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

        if mode == "scapy":
            scapy_iface = None if iface == "any" else iface
            self._task = asyncio.create_task(self._scapy_loop(scapy_iface))
        elif mode == "real":
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
        """Return True if pkt passes the server-side filter (empty = pass all).

        Uses the same Wireshark-style parser as the frontend display filter
        so profile filters and user-typed filters behave identically on both sides.
        An unparseable filter is treated as pass-all to avoid dropping all traffic.
        """
        if not self._filter_terms:
            return True
        node = self._filter_ast
        if node is None:
            return True   # parse failed at start() time — pass all
        try:
            return _filter_eval(node, pkt)
        except Exception:
            return True   # evaluation error → pass all

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

    async def _scapy_loop(self, iface: str | None) -> None:
        """Full L2 capture using scapy + Npcap.  Same structure as _real_loop."""
        cap = ScapyCapture(iface)
        cap.start(session_start=_get_session_start())
        loop       = asyncio.get_event_loop()
        last_tick  = loop.time()
        last_flush = loop.time()
        batch: list[dict] = []
        FLUSH_INTERVAL = 0.05

        # Supplement with UDP sink so loopback device traffic is captured
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
