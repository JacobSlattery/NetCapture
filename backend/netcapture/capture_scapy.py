"""
Scapy/Npcap packet capture backend.

Requirements:
  - Npcap installed (https://npcap.com)
  - scapy Python package  (install via: pixi run --environment npcap ...)

SCAPY_AVAILABLE is exported so callers can gate import errors gracefully.
probe_npcap() does a lightweight check that npcap is actually usable at
runtime (scapy importable does NOT imply npcap is installed).

ScapyCapture has the same interface as RawCapture:
  cap = ScapyCapture(iface)   # iface=None → scapy default
  cap.start(session_start=…)
  pkt = cap.get_packet(timeout=0.1)   # returns dict or None
  cap.stop()

Captures full Ethernet frames so raw_hex includes the L2 header;
the frontend hex parser handles this correctly.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from datetime import datetime

# Silence scapy's noisy startup / deprecation messages before importing
logging.getLogger("scapy").setLevel(logging.CRITICAL)

try:
    import scapy.config as _scapy_cfg     # noqa: F401  triggers early init
    _scapy_cfg.conf.verb = 0              # suppress runtime chatter

    from scapy.all import (               # noqa: F401
        sniff as _sniff,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── Helpers shared with capture.py ────────────────────────────────────────────

from .capture import _PORT_LABEL, _label, _tcp_flags


# ── Npcap probe ───────────────────────────────────────────────────────────────

def probe_npcap() -> bool:
    """
    Return True if Npcap is installed and scapy can enumerate interfaces.
    Fast (~1 ms): just checks conf.ifaces; no actual packet capture.
    """
    if not SCAPY_AVAILABLE:
        return False
    try:
        from scapy.all import conf as _conf
        return len(_conf.ifaces) > 0
    except Exception:
        return False


# ── Packet parser ─────────────────────────────────────────────────────────────

def _parse_scapy(pkt, start_time: float, seq: int) -> dict | None:  # type: ignore[no-untyped-def]
    """Convert a scapy packet object to the frontend-compatible dict format."""
    try:
        raw_bytes = bytes(pkt)
    except Exception:
        return None

    raw_hex = raw_bytes.hex()
    length  = len(raw_bytes)

    now = datetime.now()
    rel = time.time() - start_time

    src_ip:   str | None  = None
    dst_ip:   str | None  = None
    src_port: int | None  = None
    dst_port: int | None  = None
    ttl:      int | None  = None
    flags:    str | None  = None
    protocol: str         = "Unknown"
    info:     str         = ""
    payload:  bytes | None = None

    if pkt.haslayer(ARP):
        arp      = pkt[ARP]
        src_ip   = arp.psrc
        dst_ip   = arp.pdst
        protocol = "ARP"
        op       = {1: "Who has", 2: "is at"}.get(arp.op, str(arp.op))
        info     = f"{op}  {dst_ip}  tell {src_ip}"

    elif pkt.haslayer(IP):
        ip     = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        ttl    = ip.ttl

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags    = _tcp_flags(int(tcp.flags))
            payload  = bytes(tcp.payload) if tcp.payload else b""
            protocol = _label("TCP", src_port, dst_port)
            info = (
                f"[{flags}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  "
                f"Seq={tcp.seq}  Len={len(payload)}"
            )

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            payload  = bytes(udp.payload) if udp.payload else b""
            protocol = _label("UDP", src_port, dst_port)
            info = (
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  "
                f"Len={max(0, (udp.len or 8) - 8)}"
            )

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            _names = {
                0: "Echo reply",    3: "Dest unreachable",
                8: "Echo request",  11: "Time exceeded",
            }
            protocol = "ICMP"
            info = (
                f"{_names.get(icmp.type, f'Type {icmp.type}')}  "
                f"code={icmp.code}  {src_ip} → {dst_ip}"
            )

        else:
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, f"IP/{ip.proto}")
            info     = f"{src_ip} → {dst_ip}"

    elif pkt.haslayer(IPv6):
        ip6      = pkt[IPv6]
        src_ip   = ip6.src
        dst_ip   = ip6.dst
        protocol = "IPv6"
        info     = f"{src_ip} → {dst_ip}"

    else:
        return None  # skip non-IP / non-ARP frames

    return {
        "id":        seq,
        "timestamp": f"{int(rel // 60):02d}:{rel % 60:06.3f}",
        "abs_time":  now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}",
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  protocol,
        "length":    length,
        "ttl":       ttl,
        "flags":     flags,
        "info":      info,
        "raw_hex":   raw_hex,
        "_payload":  payload or None,
    }


# ── ScapyCapture ──────────────────────────────────────────────────────────────

class ScapyCapture:
    """
    Captures all traffic on an interface using scapy + Npcap.

    iface=None uses scapy's default (primary) interface.
    For "any", pass iface=None — Windows has no true "any" device.

    Raises RuntimeError at start() time if scapy is not available.
    """

    def __init__(self, iface: str | None = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed — run with the npcap environment")
        self._iface  = iface
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=10_000)
        self._stop   = threading.Event()
        self._thread: threading.Thread | None = None
        self._seq    = 0
        self._start  = 0.0

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, session_start: float | None = None) -> None:
        self._stop.clear()
        self._seq   = 0
        self._start = session_start if session_start is not None else time.time()
        self._thread = threading.Thread(
            target=self._capture_loop, name="scapy-capture", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def get_packet(self, timeout: float = 0.1) -> dict | None:
        """Dequeue the next parsed packet. Returns None on timeout."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def iface(self) -> str | None:
        return self._iface

    # ── Internal ───────────────────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        def _on_packet(pkt) -> None:  # type: ignore[no-untyped-def]
            if self._stop.is_set():
                return
            self._seq += 1
            parsed = _parse_scapy(pkt, self._start, self._seq)
            if parsed and not self._queue.full():
                self._queue.put_nowait(parsed)

        iface_kwarg: dict = {} if self._iface is None else {"iface": self._iface}
        try:
            _sniff(
                prn=_on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                **iface_kwarg,
            )
        except Exception as exc:
            print(f"[scapy] capture error: {exc}")
