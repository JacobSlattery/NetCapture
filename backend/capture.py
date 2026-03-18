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

# UDP port the backend listens on for direct device feeds (no admin required).
# Override with NETCAPTURE_SINK_PORT env var.
UDP_SINK_PORT: int = int(os.environ.get("NETCAPTURE_SINK_PORT", "9001"))


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

def build_udp_raw_hex(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
) -> str:
    """
    Construct a minimal IPv4 + UDP frame around raw payload bytes and return it
    as a hex string.  No Ethernet header is prepended — we don't have real MAC
    addresses in this path, so the frontend will parse from the IP layer up.
    """
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, 0x4000,
        64, 17, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return (ip + udp).hex()


# ── Packet parsing ────────────────────────────────────────────────────────────

def _label(transport: str, src_port: int | None, dst_port: int | None) -> str:
    for p in (dst_port, src_port):
        if p and p in _PORT_LABEL:
            return _PORT_LABEL[p]
    return transport


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

    src_port: int | None    = None
    dst_port: int | None    = None
    flags: str | None       = None
    app_payload: bytes | None = None
    info                    = f"{src_ip} → {dst_ip}"

    if proto_num == 6 and len(payload) >= 20:          # TCP
        src_port, dst_port = struct.unpack_from("!HH", payload)
        data_off = (payload[12] >> 4) * 4
        flags    = _tcp_flags(payload[13])
        seq_num  = struct.unpack_from("!I", payload, 4)[0]
        app_payload = payload[data_off:]
        app_len  = len(app_payload)
        transport = _label("TCP", src_port, dst_port)
        info = (
            f"[{flags}] {src_ip}:{src_port} → {dst_ip}:{dst_port}  "
            f"Seq={seq_num}  Len={app_len}"
        )

    elif proto_num == 17 and len(payload) >= 8:        # UDP
        src_port, dst_port = struct.unpack_from("!HH", payload)
        udp_len = struct.unpack_from("!H", payload, 4)[0]
        app_payload = payload[8:]
        transport = _label("UDP", src_port, dst_port)
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
        info = (
            f"{_names.get(icmp_type, f'Type {icmp_type}')}  "
            f"code={code}  {src_ip} → {dst_ip}"
        )

    # Raw sockets on Windows give us the IP packet without an Ethernet header.
    # We send only what we actually have — the frontend detects IP-only frames.
    raw_hex = raw[:total_len].hex()

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
        # Internal — consumed by _emit_packet, never serialised to the frontend.
        "_payload":  app_payload,
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
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=10_000)
        self._stop      = threading.Event()
        self._thread: threading.Thread | None = None
        self._seq       = 0
        self._start     = 0.0

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

    def get_packet(self, timeout: float = 0.1) -> dict | None:
        """
        Dequeue and parse the next captured packet.
        Returns None on timeout or parse failure.
        Safe to call from a thread-pool executor.
        """
        try:
            raw = self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
        self._seq += 1
        return parse_packet(raw, self._start, self._seq)

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
                if not self._queue.full():
                    self._queue.put_nowait(raw)
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
