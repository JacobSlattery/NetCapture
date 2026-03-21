"""
Raw-socket packet capture for Windows — no npcap/WinPcap required.

Technique: AF_INET / SOCK_RAW / IPPROTO_IP  +  SIO_RCVALL ioctl
Requirement: process must be running as Administrator.
Limitation: captures IP-layer and above only (no Ethernet / ARP frames).
            A dummy Ethernet header is prepended to raw_hex so the frontend
            hex-parser continues to work unchanged.
"""

from __future__ import annotations

import os
import queue
import socket
import struct
import threading
import time
from datetime import datetime

# ── Protocol tables ───────────────────────────────────────────────────────────

_IP_PROTO: dict[int, str] = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Well-known port → application-layer label (checked on both src and dst)
_PORT_LABEL: dict[int, str] = {
    20: "FTP",  21: "FTP",  22: "SSH",   23: "Telnet",
    25: "SMTP", 53: "DNS",  67: "DHCP",  68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "TLS",
    465: "SMTP", 587: "SMTP", 993: "IMAP", 995: "POP3",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP", 8443: "TLS",
}

# ── Packet parsing ────────────────────────────────────────────────────────────

# ── Checksum validation ───────────────────────────────────────────────────────
# NOTE: Windows TCP/IP offloads checksum computation to the NIC for locally
# generated packets, so outgoing frames captured via SIO_RCVALL may show bad
# checksums that are actually filled in correctly by hardware before they leave
# the wire.  Incoming packets received from the network have already been
# validated by the NIC and will only show bad checksums if they were corrupted
# in transit or are malformed/injected.  This is the same caveat Wireshark
# documents for Windows.

def _ones_complement_sum(data: bytes) -> int:
    """Sum all 16-bit words using one's complement arithmetic."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _ip_checksum_ok(raw: bytes, ihl: int) -> bool:
    """Return True when the IP header checksum is valid (sum of header == 0xFFFF)."""
    return _ones_complement_sum(raw[:ihl]) == 0xFFFF


def _tcp_checksum_ok(raw: bytes, ihl: int, src_bytes: bytes, dst_bytes: bytes) -> bool:
    """Return True when the TCP segment checksum is valid."""
    tcp_seg = raw[ihl:]
    pseudo  = src_bytes + dst_bytes + bytes([0, 6]) + struct.pack("!H", len(tcp_seg))
    return _ones_complement_sum(pseudo + tcp_seg) == 0xFFFF


def _udp_checksum_ok(raw: bytes, ihl: int, src_bytes: bytes, dst_bytes: bytes) -> bool:
    """Return True when the UDP checksum is valid.  Zero means not computed (optional)."""
    udp_seg = raw[ihl:]
    if struct.unpack_from("!H", udp_seg, 6)[0] == 0:
        return True  # checksum field is optional; 0 = sender chose not to compute
    udp_len = struct.unpack_from("!H", udp_seg, 4)[0]
    pseudo  = src_bytes + dst_bytes + bytes([0, 17]) + struct.pack("!H", udp_len)
    return _ones_complement_sum(pseudo + udp_seg) == 0xFFFF


def compute_warnings(raw: bytes) -> list[str]:
    """
    Run all network-level validations on a raw IPv4 packet and return a list
    of human-readable warning strings.  An empty list means no issues found.

    This is intentionally kept cheap: one pass over the IP header + one pseudo-
    header checksum for the transport layer.  It is safe to call on every packet.

    Public so that _manager.py can call it for injected packets (which bypass
    the parse_packet() path) without duplicating the logic.
    """
    warnings: list[str] = []
    if len(raw) < 20:
        return warnings
    version_ihl = raw[0]
    if (version_ihl >> 4) != 4:
        return warnings  # not IPv4
    ihl       = (version_ihl & 0x0F) * 4
    proto_num = raw[9]
    src_bytes = raw[12:16]
    dst_bytes = raw[16:20]
    payload   = raw[ihl:]
    if not _ip_checksum_ok(raw, ihl):
        warnings.append("Bad IP checksum")
    if proto_num == 6 and len(payload) >= 20:
        if not _tcp_checksum_ok(raw, ihl, src_bytes, dst_bytes):
            warnings.append("Bad TCP checksum")
    elif proto_num == 17 and len(payload) >= 8:
        if not _udp_checksum_ok(raw, ihl, src_bytes, dst_bytes):
            warnings.append("Bad UDP checksum")
    return warnings


def _label(transport: str, src_port: int | None, dst_port: int | None) -> str:
    for p in (dst_port, src_port):
        if p and p in _PORT_LABEL:
            return _PORT_LABEL[p]
    return transport


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                 b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ", b"HTTP/")


def _tcp_label(src_port: int | None, dst_port: int | None, payload: bytes) -> str:
    """
    Like _label("TCP", ...) but verifies the payload structure before committing
    to an application-layer name.  Returns "TCP" when the payload is absent,
    too small, or doesn't look like the expected protocol.
    """
    if not payload:
        return "TCP"

    candidate = _label("TCP", src_port, dst_port)
    if candidate == "TCP":
        return "TCP"

    if candidate == "TLS":
        # TLS record: type 20–23, version 03.00–04, then 2-byte length
        if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) \
                and payload[1] == 3 and payload[2] <= 4:
            return "TLS"
        return "TCP"

    if candidate == "HTTP":
        if any(payload.startswith(m) for m in _HTTP_METHODS):
            return "HTTP"
        return "TCP"

    if candidate == "SSH":
        if payload.startswith(b"SSH-"):
            return "SSH"
        # Post-handshake SSH is binary; keep label if payload is substantial
        return "SSH" if len(payload) >= 6 else "TCP"

    if candidate == "DNS":
        # DNS-over-TCP: 2-byte length prefix, then ≥12-byte DNS header
        if len(payload) >= 14 and struct.unpack_from("!H", payload)[0] >= 12:
            return "DNS"
        return "TCP"

    if candidate in ("SMTP", "POP3", "IMAP"):
        # Text-based; first byte must be printable ASCII
        if 32 <= payload[0] < 127:
            return candidate
        return "TCP"

    # Generic fallback: require at least 4 bytes before labelling
    return candidate if len(payload) >= 4 else "TCP"


def _tcp_flags(flag_byte: int) -> str:
    parts = []
    if flag_byte & 0x02: 
        parts.append("SYN")
    if flag_byte & 0x10: 
        parts.append("ACK")
    if flag_byte & 0x08: 
        parts.append("PSH")
    if flag_byte & 0x01: 
        parts.append("FIN")
    if flag_byte & 0x04: 
        parts.append("RST")
    if flag_byte & 0x20: 
        parts.append("URG")
    return ", ".join(parts) or "ACK"


def parse_packet(raw: bytes, start_time: float, seq: int) -> dict | None:
    """Parse a raw IP packet (no Ethernet header) into a frontend-compatible dict."""
    if len(raw) < 20:
        return None

    # IP header
    version_ihl = raw[0]
    if (version_ihl >> 4) != 4:
        return None  # skip non-IPv4
    ihl          = (version_ihl & 0x0F) * 4
    total_len    = struct.unpack_from("!H", raw, 2)[0]
    ttl          = raw[8]
    proto_num    = raw[9]
    src_ip       = socket.inet_ntoa(raw[12:16])
    dst_ip       = socket.inet_ntoa(raw[16:20])
    transport    = _IP_PROTO.get(proto_num, f"IP/{proto_num}")
    payload      = raw[ihl:]

    src_port: int | None      = None
    dst_port: int | None      = None
    flags: str | None         = None
    app_payload: bytes | None = None
    header_bytes: bytes       = b''   # raw transport header (before application payload)
    info                      = f"{src_ip} → {dst_ip}"

    if proto_num == 6 and len(payload) >= 20:          # TCP
        src_port, dst_port = struct.unpack_from("!HH", payload)
        data_off = (payload[12] >> 4) * 4
        flags    = _tcp_flags(payload[13])
        seq_num  = struct.unpack_from("!I", payload, 4)[0]
        app_payload  = payload[data_off:]
        header_bytes = payload[:data_off]              # TCP header (incl. options)
        app_len  = len(app_payload)
        transport = _tcp_label(src_port, dst_port, app_payload)
        info = (
            f"[{flags}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  "
            f"Seq={seq_num}  Len={app_len}"
        )

    elif proto_num == 17 and len(payload) >= 8:        # UDP
        src_port, dst_port = struct.unpack_from("!HH", payload)
        udp_len = struct.unpack_from("!H", payload, 4)[0]
        app_payload  = payload[8:]
        header_bytes = payload[:8]                     # 8-byte UDP header
        transport = _label("UDP", src_port, dst_port) if app_payload else "UDP"
        info = (
            f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  "
            f"Len={udp_len - 8}"
        )

    elif proto_num == 1 and len(payload) >= 4:         # ICMP
        icmp_type, code = payload[0], payload[1]
        _names = {
            0: "Echo reply", 3: "Dest unreachable",
            8: "Echo request", 11: "Time exceeded",
        }
        header_bytes = payload[:8] if len(payload) >= 8 else payload[:4]
        info = (
            f"{_names.get(icmp_type, f'Type {icmp_type}')}  "
            f"code={code}  {src_ip} → {dst_ip}"
        )

    # ── Checksum validation ───────────────────────────────────────────────────
    warnings = compute_warnings(raw)

    # Raw sockets on Windows give us the IP packet without an Ethernet header.
    # We send only what we actually have — the frontend detects IP-only frames.
    raw_hex = raw[:total_len].hex()

    # Payload byte offset within raw_hex (no Ethernet header for raw sockets).
    # ihl = IP header length in bytes; add transport header length for TCP/UDP.
    payload_offset = ihl + len(header_bytes)

    now = datetime.now()
    rel = time.time() - start_time
    return {
        "id":        seq,
        "timestamp": f"{int(rel // 60):02d}:{rel % 60:06.3f}",
        "abs_time":  now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}",
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  transport,
        "length":    total_len,
        "ttl":       ttl,
        "flags":     flags,
        "info":      info,
        "raw_hex":   raw_hex,
        "warnings":  warnings if warnings else None,
        # Internal — consumed by _emit_packet, never serialised to the frontend.
        "_payload":       app_payload,
        "_header_bytes":  header_bytes,
        "_payload_offset": payload_offset,
    }


# ── Capture class ─────────────────────────────────────────────────────────────

class RawCapture:
    """
    Captures all IP traffic on a bound interface using SIO_RCVALL.

    A background thread does the blocking recv() and feeds a thread-safe queue.
    Callers consume via the synchronous `get_packet()` method (safe to wrap
    in asyncio.get_event_loop().run_in_executor).

    Usage:
        cap = RawCapture(bind_ip="192.168.1.100")
        cap.start()
        try:
            while running:
                pkt = cap.get_packet(timeout=0.1)  # returns dict or None
                if pkt:
                    ...
        finally:
            cap.stop()
    """

    def __init__(self, bind_ip: str, buf_size: int = 65_536):
        self._bind_ip   = bind_ip
        self._buf_size  = buf_size
        self._sock: socket.socket | None = None
        # Queue holds parsed dicts (parsing happens in the capture thread so
        # non-matching packets can be discarded before consuming queue space).
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=50_000)
        self._stop      = threading.Event()
        self._thread: threading.Thread | None = None
        self._seq       = 0
        self._start     = 0.0
        self._dropped   = 0
        self._filter_fn = None   # optional pre-filter set by the capture manager

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, session_start: float | None = None) -> None:
        """Open the raw socket and start the capture thread. Raises OSError if not admin."""
        self._stop.clear()
        self._seq   = 0
        self._start = session_start if session_start is not None else time.time()
        self._sock  = self._open_socket()
        self._thread = threading.Thread(
            target=self._capture_loop, name="raw-capture", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to exit and clean up the socket."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def set_filter(self, fn) -> None:  # type: ignore[no-untyped-def]
        """
        Optionally pre-filter packets in the capture thread before they are
        queued.  ``fn(pkt: dict) -> bool`` — packets for which fn returns
        False are discarded immediately, before entering the queue.

        Only set this when the filter does not depend on decoded/interpreter
        fields (those are populated later, in the asyncio loop).
        """
        self._filter_fn = fn

    def get_packet(self, timeout: float = 0.1) -> dict | None:
        """
        Dequeue the next captured packet.
        Returns None on timeout.
        Safe to call from a thread-pool executor.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self, timeout: float = 0.05) -> list[dict]:
        """
        Dequeue all currently available packets in one call.

        Blocks up to `timeout` seconds waiting for the first packet, then
        immediately drains the rest of the queue without blocking.
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

    @property
    def bind_ip(self) -> str:
        return self._bind_ip

    # ── Internal ───────────────────────────────────────────────────────────────

    def _open_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((self._bind_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(0.2)               # lets the thread notice stop() promptly
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return s

    def _capture_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self._sock is None:
                    break
                raw = self._sock.recv(self._buf_size)
                self._seq += 1
                parsed = parse_packet(raw, self._start, self._seq)
                if not parsed:
                    continue
                # Pre-filter: discard non-matching packets before they consume
                # queue space.  Only active when the filter has no decoded/
                # interpreter terms (those are populated later in the async loop).
                if self._filter_fn and not self._filter_fn(parsed):
                    continue
                if not self._queue.full():
                    self._queue.put_nowait(parsed)
                else:
                    self._dropped += 1
                    if self._dropped == 1 or self._dropped % 1000 == 0:
                        print(f"[raw] capture queue full — {self._dropped} packet(s) dropped"
                              " (consider using a BPF filter to reduce capture volume)")
            except socket.timeout:
                pass
            except OSError:
                break


# ── Interface helpers ─────────────────────────────────────────────────────────

def get_capture_ip(iface_name: str) -> str | None:
    """
    Return the IPv4 address to bind to for the given interface name.
    Returns None if the interface has no IPv4 address.

    If iface_name is 'any', return the IP of the default outbound interface —
    the one the OS would use to reach the internet.  This is determined by
    opening a UDP socket toward 8.8.8.8 (no data is sent) and reading the
    local address the OS assigned.  Falls back to the first non-loopback IPv4
    if that probe fails.
    """
    import psutil

    addrs = psutil.net_if_addrs()

    if iface_name != "any":
        for addr in addrs.get(iface_name, []):
            if addr.family.name == "AF_INET" and addr.address != "127.0.0.1":
                return addr.address
        return None

    # "any" — find the default outbound interface via a dummy UDP connect.
    # No data is sent; the OS just resolves which local IP would be used.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except OSError:
        pass

    # Fallback: first non-loopback IPv4
    for addr_list in addrs.values():
        for addr in addr_list:
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                return addr.address
    return None
