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

from .capture import _PORT_LABEL, _label, _tcp_flags, _tcp_label


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


def _resolve_loopback() -> str:
    """
    Return the Npcap loopback interface name for use with scapy.
    Searches conf.ifaces for the interface whose IP is 127.0.0.1.
    Falls back to the standard Npcap device name if not found.
    """
    try:
        from scapy.all import conf as _conf
        for iface in _conf.ifaces.values():
            ip = getattr(iface, "ip", None)
            if ip == "127.0.0.1":
                return iface.name
    except Exception:
        pass
    return r"\Device\NPF_Loopback"


# ── Packet parser ─────────────────────────────────────────────────────────────

def _parse_scapy(pkt, start_time: float, seq: int) -> dict | None:  # type: ignore[no-untyped-def]
    """Convert a scapy packet object to the frontend-compatible dict format."""
    try:
        full_bytes = bytes(pkt)
    except Exception:
        return None

    # For non-Ethernet links (loopback DLT_NULL, etc.) the frame starts with
    # a link-layer header the frontend hex viewer doesn't know about.  Strip
    # down to the IP layer so the viewer sees a raw-IP packet (first nibble
    # 4 or 6), which it already handles correctly.
    if pkt.haslayer(Ether):
        raw_bytes = full_bytes
    elif pkt.haslayer(IP):
        raw_bytes = bytes(pkt[IP])
    elif pkt.haslayer(IPv6):
        raw_bytes = bytes(pkt[IPv6])
    else:
        raw_bytes = full_bytes

    raw_hex = raw_bytes.hex()
    length  = len(full_bytes)  # report true wire length, not stripped length

    now = datetime.now()
    rel = time.time() - start_time

    src_ip:       str | None   = None
    dst_ip:       str | None   = None
    src_port:     int | None   = None
    dst_port:     int | None   = None
    ttl:          int | None   = None
    flags:        str | None   = None
    protocol:     str          = "Unknown"
    info:         str          = ""
    payload:      bytes | None = None
    header_bytes: bytes        = b''   # raw transport header (before application payload)
    payload_offset: int        = 0     # byte offset of payload within raw_hex

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

        # Ethernet header offset: 14 bytes if present, 0 for raw-IP frames
        _eth_off = 14 if pkt.haslayer(Ether) else 0

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags    = _tcp_flags(int(tcp.flags))
            # Extract payload and header bytes from raw IP bytes
            _ip_bytes     = bytes(pkt[IP])
            _ihl          = (_ip_bytes[0] & 0x0F) * 4
            _tcp_bytes    = _ip_bytes[_ihl:]
            _tcp_data_off = ((_tcp_bytes[12] >> 4) * 4) if len(_tcp_bytes) >= 13 else 20
            payload      = _tcp_bytes[_tcp_data_off:] if len(_tcp_bytes) > _tcp_data_off else b""
            header_bytes = _tcp_bytes[:_tcp_data_off]   # TCP header incl. options
            payload_offset = _eth_off + _ihl + _tcp_data_off
            protocol = _tcp_label(src_port, dst_port, payload)
            info = (
                f"[{flags}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  "
                f"Seq={tcp.seq}  Len={len(payload)}"
            )

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            _ip_bytes = bytes(pkt[IP])
            _ihl      = (_ip_bytes[0] & 0x0F) * 4
            payload      = _ip_bytes[_ihl + 8:] if len(_ip_bytes) > _ihl + 8 else b""
            header_bytes = _ip_bytes[_ihl : _ihl + 8]  # 8-byte UDP header
            payload_offset = _eth_off + _ihl + 8
            protocol = _label("UDP", src_port, dst_port) if payload else "UDP"
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
            _ip_bytes    = bytes(pkt[IP])
            _ihl         = (_ip_bytes[0] & 0x0F) * 4
            _icmp_bytes  = _ip_bytes[_ihl:]
            header_bytes = _icmp_bytes[:8] if len(_icmp_bytes) >= 8 else _icmp_bytes[:4]
            payload_offset = _eth_off + _ihl + len(header_bytes)
            protocol = "ICMP"
            info = (
                f"{_names.get(icmp.type, f'Type {icmp.type}')}  "
                f"code={icmp.code}  {src_ip} → {dst_ip}"
            )

        else:
            _ip_bytes = bytes(pkt[IP])
            _ihl      = (_ip_bytes[0] & 0x0F) * 4
            payload_offset = _eth_off + _ihl
            protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, f"IP/{ip.proto}")
            info     = f"{src_ip} → {dst_ip}"

    elif pkt.haslayer(IPv6):
        ip6      = pkt[IPv6]
        src_ip   = ip6.src
        dst_ip   = ip6.dst
        _eth_off = 14 if pkt.haslayer(Ether) else 0
        _ip6_hdr = 40  # fixed IPv6 header length

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags    = _tcp_flags(int(tcp.flags))
            _tcp_raw      = bytes(pkt[TCP])
            _tcp_data_off = ((_tcp_raw[12] >> 4) * 4) if len(_tcp_raw) >= 13 else 20
            payload      = bytes(tcp.payload) if tcp.payload else b""
            header_bytes = _tcp_raw[:_tcp_data_off]
            payload_offset = _eth_off + _ip6_hdr + _tcp_data_off
            protocol = _tcp_label(src_port, dst_port, payload)
            info = (
                f"[{flags}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  "
                f"Seq={tcp.seq}  Len={len(payload)}"
            )

        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            _udp_raw     = bytes(pkt[UDP])
            payload      = _udp_raw[8:]
            header_bytes = _udp_raw[:8]
            payload_offset = _eth_off + _ip6_hdr + 8
            protocol = _label("UDP", src_port, dst_port) if payload else "UDP"
            info = (
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  "
                f"Len={max(0, (udp.len or 8) - 8)}"
            )

        else:
            payload_offset = _eth_off + _ip6_hdr
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
        # Internal — consumed by _emit_packet, never serialised to the frontend.
        "_payload":        payload or None,
        "_header_bytes":   header_bytes,
        "_payload_offset": payload_offset,
    }


# ── ScapyCapture ──────────────────────────────────────────────────────────────

class ScapyCapture:
    """
    Captures all traffic on an interface using scapy + Npcap.

    iface=None uses scapy's default (primary) interface.
    For "any", pass iface=None — Windows has no true "any" device.

    Raises RuntimeError at start() time if scapy is not available.
    """

    def __init__(self, iface: str | None = None, bpf_filter: str = ""):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed — run with the npcap environment")
        self._iface      = _resolve_loopback() if iface == "loopback" else iface
        self._bpf_filter = bpf_filter
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=50_000)
        self._stop      = threading.Event()
        self._thread: threading.Thread | None = None
        self._seq       = 0
        self._start     = 0.0
        self._dropped   = 0
        self._filter_fn = None   # optional pre-filter set by the capture manager

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

    def drain(self, timeout: float = 0.05) -> list[dict]:
        """
        Dequeue all currently available packets in one call.

        Blocks up to `timeout` seconds waiting for the first packet, then
        immediately drains the rest of the queue without blocking.  Returning
        a batch instead of one packet at a time prevents the queue from
        filling up when background traffic arrives faster than one packet per
        asyncio iteration.
        """
        result: list[dict] = []
        try:
            result.append(self._queue.get(timeout=timeout))
        except queue.Empty:
            return result
        while True:
            try:
                result.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return result

    def set_filter(self, fn) -> None:  # type: ignore[no-untyped-def]
        """
        Optionally pre-filter packets in the capture thread before they are
        queued.  ``fn(pkt: dict) -> bool`` — packets for which fn returns
        False are discarded immediately, before entering the queue.

        Only set this when the filter does not depend on decoded/interpreter
        fields (those are populated later, in the asyncio loop).
        """
        self._filter_fn = fn

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
            if not parsed:
                return
            # Pre-filter: discard non-matching packets before they consume
            # queue space.  Only active when the filter has no decoded/
            # interpreter terms (those are populated later in the async loop).
            if self._filter_fn and not self._filter_fn(parsed):
                return
            if not self._queue.full():
                self._queue.put_nowait(parsed)
            else:
                self._dropped += 1
                if self._dropped == 1 or self._dropped % 1000 == 0:
                    print(f"[scapy] capture queue full — {self._dropped} packet(s) dropped"
                          " (consider using a BPF filter to reduce capture volume)")

        iface_kwarg: dict = {} if self._iface is None else {"iface": self._iface}
        filter_kwarg: dict = {} if not self._bpf_filter else {"filter": self._bpf_filter}
        try:
            _sniff(
                prn=_on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                **iface_kwarg,
                **filter_kwarg,
            )
        except Exception as exc:
            print(f"[scapy] capture error: {exc}")
