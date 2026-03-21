"""
tools/fault_injector.py — Fault-scenario generator for NetCapture warning features.

Sends a repeating sequence of deliberately broken packets so you can verify that
warning indicators, row highlighting, and the detail-panel banner all work correctly.

Scenarios (one full cycle per iteration)
─────────────────────────────────────────
  1. healthy-udp      Valid UDP + valid NC-Frame payload      → no indicators
  2. bad-ip-cksum     Bad IP checksum, good UDP + NC-Frame    → amber row, "Bad IP checksum"
  3. bad-udp-cksum    Good IP, bad UDP checksum, good NC-Frame→ amber row, "Bad UDP checksum"
  4. bad-tcp-cksum    TCP packet with bad TCP checksum        → amber row, "Bad TCP checksum"
  5. decoder-err      Valid UDP, truncated NC-Frame payload   → red row, "Decoder: ..." banner
  6. both             Bad IP checksum + truncated NC-Frame    → red row (decoder wins) + amber
  7. healthy-tcp      Valid TCP + text payload                → no indicators

Usage
─────
  pixi run python tools/fault_injector.py
  pixi run python tools/fault_injector.py --rate 0.5    # slower, easier to inspect
  pixi run python tools/fault_injector.py --cycles 3    # stop after 3 full cycles
  pixi run python tools/fault_injector.py --scenario bad-ip-cksum  # one scenario only
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import socket
import struct
import time

# ── Checksum helpers ──────────────────────────────────────────────────────────

def _cksum(data: bytes) -> int:
    """One's complement 16-bit checksum."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total ^ 0xFFFF


# ── Datagram builders (all checksums computed correctly, then selectively broken) ──

def _build_udp(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    payload: bytes,
) -> bytes:
    """Build a well-formed IPv4/UDP datagram with correct checksums."""
    src_b   = socket.inet_aton(src_ip)
    dst_b   = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)

    # UDP checksum (pseudo-header + UDP header + data)
    pseudo      = src_b + dst_b + bytes([0, 17]) + struct.pack("!H", udp_len)
    udp_no_ck   = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    udp_ck      = _cksum(pseudo + udp_no_ck + payload)
    udp_hdr     = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_ck)

    # IP header checksum
    ip_total    = 20 + udp_len
    ip_no_ck    = struct.pack("!BBHHHBBH4s4s",
                              0x45, 0, ip_total, 0, 0, 64, 17, 0, src_b, dst_b)
    ip_ck       = _cksum(ip_no_ck)
    ip_hdr      = struct.pack("!BBHHHBBH4s4s",
                              0x45, 0, ip_total, 0, 0, 64, 17, ip_ck, src_b, dst_b)
    return ip_hdr + udp_hdr + payload


def _build_tcp(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    payload: bytes,
    flags: int = 0x18,   # PSH + ACK
) -> bytes:
    """Build a well-formed IPv4/TCP segment with correct checksums."""
    src_b    = socket.inet_aton(src_ip)
    dst_b    = socket.inet_aton(dst_ip)
    tcp_len  = 20 + len(payload)

    # TCP checksum (pseudo-header + TCP header + data)
    pseudo      = src_b + dst_b + bytes([0, 6]) + struct.pack("!H", tcp_len)
    tcp_no_ck   = struct.pack("!HHIIBBHHH",
                              src_port, dst_port,
                              1, 0,           # seq=1, ack=0
                              0x50, flags,    # data offset=5, flags
                              65535, 0, 0)    # window, cksum=0, urgent
    tcp_ck      = _cksum(pseudo + tcp_no_ck + payload)
    tcp_hdr     = struct.pack("!HHIIBBHHH",
                              src_port, dst_port,
                              1, 0,
                              0x50, flags,
                              65535, tcp_ck, 0)

    # IP header checksum
    ip_total    = 20 + tcp_len
    ip_no_ck    = struct.pack("!BBHHHBBH4s4s",
                              0x45, 0, ip_total, 0, 0, 64, 6, 0, src_b, dst_b)
    ip_ck       = _cksum(ip_no_ck)
    ip_hdr      = struct.pack("!BBHHHBBH4s4s",
                              0x45, 0, ip_total, 0, 0, 64, 6, ip_ck, src_b, dst_b)
    return ip_hdr + tcp_hdr + payload


def _corrupt_ip_cksum(datagram: bytes) -> bytes:
    """Flip the IP header checksum bytes (offset 10–11)."""
    ba = bytearray(datagram)
    ba[10] ^= 0xFF
    ba[11] ^= 0xFF
    return bytes(ba)


def _corrupt_udp_cksum(datagram: bytes) -> bytes:
    """Flip the UDP checksum bytes (offset 26–27 for standard 20-byte IP header)."""
    ba = bytearray(datagram)
    ba[26] ^= 0xFF
    ba[27] ^= 0xFF
    return bytes(ba)


def _corrupt_tcp_cksum(datagram: bytes) -> bytes:
    """Flip the TCP checksum bytes (offset 36–37 for standard 20-byte IP header)."""
    ba = bytearray(datagram)
    ba[36] ^= 0xFF
    ba[37] ^= 0xFF
    return bytes(ba)


# ── NC-Frame payload builders ─────────────────────────────────────────────────

def _nc_field(key: str, tag: int, value: bytes) -> bytes:
    k = key.encode()
    return bytes([len(k)]) + k + bytes([tag]) + value


def _make_valid_nc_frame(seq: int) -> bytes:
    """Build a minimal but valid NC-Frame payload."""
    fields = [
        _nc_field("seq",    0x03, struct.pack("!I", seq & 0xFFFFFFFF)),
        _nc_field("status", 0x05, b"\x02ok"),
        _nc_field("active", 0x06, b"\x01"),
    ]
    return bytes([0x4E, 0x43, 0x01, len(fields)]) + b"".join(fields)


def _make_truncated_nc_frame() -> bytes:
    """
    NC-Frame with correct magic + version but claims 5 fields with no data.
    The decoder will try to read past the end of the buffer → IndexError.
    """
    return bytes([0x4E, 0x43, 0x01, 5])   # header only, no field data


# ── Scenario definitions ──────────────────────────────────────────────────────

SCENARIOS = [
    "healthy-udp",
    "bad-ip-cksum",
    "bad-udp-cksum",
    "bad-tcp-cksum",
    "decoder-err",
    "both",
    "healthy-tcp",
]

_DESCRIPTIONS = {
    "healthy-udp":   "Valid UDP + valid NC-Frame             → no indicators",
    "bad-ip-cksum":  "Bad IP checksum, valid NC-Frame        → amber row, 'Bad IP checksum'",
    "bad-udp-cksum": "Good IP, bad UDP checksum, valid frame → amber row, 'Bad UDP checksum'",
    "bad-tcp-cksum": "TCP packet, bad TCP checksum           → amber row, 'Bad TCP checksum'",
    "decoder-err":   "Valid UDP, truncated NC-Frame payload  → red row, decoder error",
    "both":          "Bad IP checksum + truncated NC-Frame   → red row + amber warning",
    "healthy-tcp":   "Valid TCP + text payload               → no indicators",
}


def build_packet(scenario: str, seq: int, src_ip: str) -> dict:
    """Return an inject-endpoint packet dict for the given scenario."""

    if scenario == "healthy-udp":
        payload  = _make_valid_nc_frame(seq)
        dgram    = _build_udp(src_ip, "127.0.0.1", 9101, 9101, payload)
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9101, "dst_port": 9101,
            "protocol": "UDP", "length": len(dgram),
            "info": f"[fault-test] healthy-udp  seq={seq}",
            "raw_hex": dgram.hex(), "payload_hex": payload.hex(),
        }

    if scenario == "bad-ip-cksum":
        payload  = _make_valid_nc_frame(seq)
        dgram    = _corrupt_ip_cksum(_build_udp(src_ip, "127.0.0.1", 9102, 9102, payload))
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9102, "dst_port": 9102,
            "protocol": "UDP", "length": len(dgram),
            "info": f"[fault-test] bad-ip-cksum  seq={seq}",
            "raw_hex": dgram.hex(), "payload_hex": payload.hex(),
        }

    if scenario == "bad-udp-cksum":
        payload  = _make_valid_nc_frame(seq)
        dgram    = _corrupt_udp_cksum(_build_udp(src_ip, "127.0.0.1", 9103, 9103, payload))
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9103, "dst_port": 9103,
            "protocol": "UDP", "length": len(dgram),
            "info": f"[fault-test] bad-udp-cksum  seq={seq}",
            "raw_hex": dgram.hex(), "payload_hex": payload.hex(),
        }

    if scenario == "bad-tcp-cksum":
        payload  = b"GET /status HTTP/1.1\r\nHost: testdevice\r\n\r\n"
        dgram    = _corrupt_tcp_cksum(_build_tcp(src_ip, "127.0.0.1", 9104, 9104, payload))
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9104, "dst_port": 9104,
            "protocol": "TCP", "length": len(dgram),
            "info": f"[fault-test] bad-tcp-cksum  seq={seq}",
            "raw_hex": dgram.hex(),
        }

    if scenario == "decoder-err":
        payload  = _make_truncated_nc_frame()
        dgram    = _build_udp(src_ip, "127.0.0.1", 9105, 9105, payload)
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9105, "dst_port": 9105,
            "protocol": "UDP", "length": len(dgram),
            "info": f"[fault-test] decoder-err  seq={seq}",
            "raw_hex": dgram.hex(), "payload_hex": payload.hex(),
        }

    if scenario == "both":
        payload  = _make_truncated_nc_frame()
        dgram    = _corrupt_ip_cksum(_build_udp(src_ip, "127.0.0.1", 9106, 9106, payload))
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9106, "dst_port": 9106,
            "protocol": "UDP", "length": len(dgram),
            "info": f"[fault-test] both  seq={seq}",
            "raw_hex": dgram.hex(), "payload_hex": payload.hex(),
        }

    if scenario == "healthy-tcp":
        payload  = f"status=ok,seq={seq},ts={int(time.time())}".encode()
        dgram    = _build_tcp(src_ip, "127.0.0.1", 9107, 9107, payload)
        return {
            "src_ip": src_ip, "dst_ip": "127.0.0.1",
            "src_port": 9107, "dst_port": 9107,
            "protocol": "TCP", "length": len(dgram),
            "info": f"[fault-test] healthy-tcp  seq={seq}",
            "raw_hex": dgram.hex(),
        }

    raise ValueError(f"Unknown scenario: {scenario}")


# ── Minimal WebSocket client (stdlib only) ────────────────────────────────────

class _WS:
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url: str) -> None:
        assert url.startswith("ws://"), "Only ws:// is supported"
        rest = url[5:]
        host_part, _, path = rest.partition("/")
        self._url  = url
        self._path = "/" + path
        host, _, port_str = host_part.partition(":")
        self._host = host
        self._port = int(port_str) if port_str else 80
        self._sock: socket.socket | None = None
        self._connect()

    def _connect(self) -> None:
        self._sock = socket.create_connection((self._host, self._port), timeout=5)
        self._sock.settimeout(None)
        self._handshake()

    def reconnect(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._sock = None
        self._connect()

    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        expected = base64.b64encode(
            hashlib.sha1((key + self.GUID).encode()).digest()
        ).decode()
        req = (f"GET {self._path} HTTP/1.1\r\nHost: {self._host}:{self._port}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self._sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self._sock.recv(1024)
        if b"101" not in buf.split(b"\r\n")[0]:
            raise ConnectionError(f"WS upgrade failed: {buf[:200]}")
        for line in buf.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-accept:"):
                if line.split(b":", 1)[1].strip().decode() != expected:
                    raise ConnectionError("Sec-WebSocket-Accept mismatch")

    @staticmethod
    def _frame(opcode: int, data: bytes) -> bytes:
        """Build a masked client frame (masking is mandatory per RFC 6455)."""
        key    = os.urandom(4)
        masked = bytes(b ^ key[i % 4] for i, b in enumerate(data))
        n      = len(data)
        if n < 126:
            hdr = bytes([0x80 | opcode, 0x80 | n]) + key
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", n) + key
        else:
            hdr = bytes([0x80 | opcode, 0xFF]) + struct.pack("!Q", n) + key
        return hdr + masked

    def send(self, text: str) -> None:
        self._sock.sendall(self._frame(0x1, text.encode()))

    def recv(self, timeout: float = 2.0) -> str | None:
        if not select.select([self._sock], [], [], timeout)[0]:
            return None

        def exact(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                c = self._sock.recv(n - len(buf))
                if not c:
                    raise ConnectionError("closed")
                buf += c
            return buf

        while True:
            b0, b1 = exact(2)
            op  = b0 & 0x0F
            n   = b1 & 0x7F
            if n == 126: n = struct.unpack("!H", exact(2))[0]
            elif n == 127: n = struct.unpack("!Q", exact(8))[0]
            mask = exact(4) if b1 & 0x80 else b""
            data = exact(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x1:  # text
                return data.decode()
            if op == 0x8:  # close — echo the frame back then signal reconnect needed
                try:
                    self._sock.sendall(self._frame(0x8, data[:2] if len(data) >= 2 else b""))
                except OSError:
                    pass
                raise ConnectionError("server closed")
            if op == 0x9:  # ping — must respond with masked pong
                self._sock.sendall(self._frame(0xA, data))

    def close(self) -> None:
        try:
            self._sock.sendall(self._frame(0x8, b""))
            self._sock.close()
        except OSError:
            pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"

    parser = argparse.ArgumentParser(
        description="Fault-scenario injector for NetCapture warning/error features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url", default="ws://localhost:8000/ws/inject",
                        help="Backend WebSocket URL (default: ws://localhost:8000/ws/inject)")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="Packets per second (default: 1.0)")
    parser.add_argument("--cycles", type=int, default=None,
                        help="Stop after N full cycles (default: unlimited)")
    parser.add_argument("--scenario", choices=SCENARIOS, default=None,
                        help="Send only this scenario type on repeat")
    parser.add_argument("--src-ip", default=local_ip,
                        help=f"Source IP for injected packets (default: {local_ip})")
    parser.add_argument("--list", action="store_true",
                        help="List all scenarios and exit")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:\n")
        for name in SCENARIOS:
            print(f"  {name:<18}  {_DESCRIPTIONS[name]}")
        return

    print(f"Connecting to {args.url} ...")
    try:
        ws = _WS(args.url)
    except (ConnectionRefusedError, OSError) as exc:
        print(f"ERROR: could not connect — {exc}")
        print("       Is the backend running?  pixi run dev-api")
        return
    except ConnectionError as exc:
        print(f"ERROR: WebSocket handshake failed — {exc}")
        return

    print("Connected.\n")
    print("Scenarios this run:")
    active = [args.scenario] if args.scenario else SCENARIOS
    for name in active:
        print(f"  {name:<18}  {_DESCRIPTIONS[name]}")
    print()

    interval  = 1.0 / max(args.rate, 0.01)
    seq       = 0
    cycle     = 0

    try:
        while args.cycles is None or cycle < args.cycles:
            for scenario in active:
                pkt = build_packet(scenario, seq, args.src_ip)

                # Attempt send/recv; reconnect once on any connection error.
                for attempt in range(2):
                    try:
                        ws.send(json.dumps(pkt))
                        ack    = ws.recv(timeout=2.0)
                        status = json.loads(ack) if ack else {}
                        break
                    except (ConnectionError, OSError) as exc:
                        if attempt == 0:
                            print(f"  ↺  connection lost ({exc}) — reconnecting ...")
                            try:
                                ws.reconnect()
                                print("  ↺  reconnected\n")
                            except (ConnectionError, OSError) as e2:
                                print(f"  ✗  reconnect failed: {e2}")
                                raise KeyboardInterrupt from e2
                        else:
                            raise
                else:
                    status = {}

                if status.get("error") == "capture not running":
                    print(f"  ⏸  seq={seq:>4}  {scenario:<18}  "
                          "discarded — click Start in NetCapture first")
                else:
                    ok = "✓" if status.get("ok") else "✗"
                    print(f"  {ok}  seq={seq:>4}  {scenario}")

                seq += 1
                time.sleep(interval)

            cycle += 1
            if args.cycles is None:
                print(f"  — cycle {cycle} complete —")

    except KeyboardInterrupt:
        print(f"\nStopped after {seq} packets ({cycle} complete cycles).")
    finally:
        ws.close()


if __name__ == "__main__":
    main()
