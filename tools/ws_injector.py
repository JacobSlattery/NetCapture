"""
tools/ws_injector.py — Test tool for the NetCapture /ws/inject WebSocket endpoint.

Connects to the backend injection WebSocket and streams packets directly into the
live display — no capture interface, no admin rights, no Npcap required.

Modes
─────
  nc-frame   Streams NC-Frame binary packets (decoded in the detail panel).
             This is the richest mode — shows all interpreter fields live.

  random     Cycles through plaintext, JSON, and binary payload templates.
             Tests that non-NC-Frame packets display correctly.

  replay     Replays a local .pcap file at its original inter-packet timing.
             Requires scapy (pixi run --environment npcap ...).

Usage examples
──────────────
  # NC-Frame stream at 2 Hz (default)
  python tools/ws_injector.py

  # Faster, random payloads
  python tools/ws_injector.py --mode random --rate 10

  # Replay a pcap at original speed
  python tools/ws_injector.py --mode replay --file capture.pcap

  # Point at a non-default backend
  python tools/ws_injector.py --url ws://localhost:8000/ws/inject

Run from the repo root:
  pixi run python tools/ws_injector.py --mode nc-frame
"""

from __future__ import annotations

import argparse
import json
import math
import socket
import struct
import time
import urllib.request
import urllib.error

# ── NC-Frame builder (mirrors udp_device.py) ──────────────────────────────────

_NC_STATUSES = [b"idle", b"running", b"warning", b"ok"]


def _nc_field(key: str, tag: int, value: bytes) -> bytes:
    k = key.encode()
    return bytes([len(k)]) + k + bytes([tag]) + value


def _nc_json_field(key: str, obj: object) -> bytes:
    payload = json.dumps(obj).encode()
    return _nc_field(key, 0x07, struct.pack("!H", len(payload)) + payload)


def _make_nc_frame(seq: int) -> bytes:
    ts_ms   = int(time.time() * 1000) & 0xFFFFFFFF
    temp    = 20.0 + 5.0 * math.sin(seq * 0.3)
    status  = _NC_STATUSES[seq % len(_NC_STATUSES)]
    rssi    = 80 + (seq % 40)
    history = [round(20.0 + 5.0 * math.sin((seq - i) * 0.3), 2) for i in range(3)]
    meta    = {"fw": "1.2.3", "sensor": "BME280", "channel": seq % 4}

    fields = [
        _nc_field("seq",     0x03, struct.pack("!I", seq & 0xFFFFFFFF)),
        _nc_field("ts_ms",   0x03, struct.pack("!I", ts_ms)),
        _nc_field("temp",    0x04, struct.pack("!f", temp)),
        _nc_field("status",  0x05, bytes([len(status)]) + status),
        _nc_field("active",  0x06, bytes([0 if seq % 5 == 0 else 1])),
        _nc_field("rssi",    0x02, struct.pack("!H", rssi)),
        _nc_json_field("history", history),
        _nc_json_field("meta",    meta),
    ]
    return bytes([0x4E, 0x43, 0x01, len(fields)]) + b"".join(fields)


# ── Random payload templates (mirrors udp_device.py) ──────────────────────────

_MESSAGES: list[bytes] = [
    b'{"type":"ping","seq":%d,"ts":%d}',
    b"HELLO seq=%d time=%d",
    b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
    b"NetCapture test packet seq=%d ts=%d",
    b"MEASURE,seq=%d,ts=%d,unit=ms",
]


def _make_random(seq: int) -> bytes:
    template = _MESSAGES[seq % len(_MESSAGES)]
    t = int(time.time() * 1000)
    try:
        return template % (seq, t)
    except TypeError:
        return template


# ── Minimal IPv4+UDP datagram builder ────────────────────────────────────────

def _build_udp_datagram(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Build a minimal IPv4+UDP datagram (checksum fields zeroed — valid for display)."""
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    ip_total = 20 + udp_len
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,        # version+IHL, DSCP/ECN
        ip_total,
        0, 0,           # identification, flags+fragment offset
        64, 17,         # TTL, protocol=UDP
        0,              # header checksum (0 = not computed)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ip_hdr + udp_hdr + payload


# ── Packet builders ───────────────────────────────────────────────────────────

def _build_nc_frame_packet(seq: int, src_ip: str) -> dict:
    payload  = _make_nc_frame(seq)
    datagram = _build_udp_datagram(src_ip, "127.0.0.1", 9001, 9001, payload)
    return {
        "src_ip":      src_ip,
        "dst_ip":      "127.0.0.1",
        "src_port":    9001,
        "dst_port":    9001,
        "protocol":    "UDP",
        "length":      len(datagram),
        "info":        f"{src_ip}:9001 → 127.0.0.1:9001  Len={len(payload)} [injected]",
        "raw_hex":     datagram.hex(),
        "payload_hex": payload.hex(),
    }


def _build_random_packet(seq: int, src_ip: str) -> dict:
    payload  = _make_random(seq)
    datagram = _build_udp_datagram(src_ip, "127.0.0.1", 9002, 9002, payload)
    return {
        "src_ip":      src_ip,
        "dst_ip":      "127.0.0.1",
        "src_port":    9002,
        "dst_port":    9002,
        "protocol":    "UDP",
        "length":      len(datagram),
        "info":        f"{src_ip}:9002 → 127.0.0.1:9002  Len={len(payload)} [injected]",
        "raw_hex":     datagram.hex(),
        "payload_hex": payload.hex(),
    }


# ── WebSocket client (stdlib — no extra deps) ─────────────────────────────────
#
# Python's stdlib has no WebSocket client, so we implement the handshake and
# framing manually over a raw TCP socket.  This keeps the tool dependency-free.

import base64
import hashlib
import os
import select


class _WS:
    """Minimal WebSocket client (text frames only, no compression)."""

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url: str) -> None:
        # Parse ws://host:port/path
        assert url.startswith("ws://"), "Only ws:// is supported"
        rest = url[5:]
        host_part, _, path = rest.partition("/")
        path = "/" + path
        host, _, port_str = host_part.partition(":")
        port = int(port_str) if port_str else 80

        self._sock = socket.create_connection((host, port), timeout=5)
        self._sock.settimeout(None)
        self._do_handshake(host, port, path)

    def _do_handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        expected = base64.b64encode(
            hashlib.sha1((key + self.GUID).encode()).digest()
        ).decode()

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        self._sock.sendall(request.encode())

        # Read response headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self._sock.recv(1024)

        if b"101" not in buf.split(b"\r\n")[0]:
            raise ConnectionError(f"WebSocket upgrade failed:\n{buf.decode(errors='replace')}")

        # Verify accept key
        for line in buf.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-accept:"):
                got = line.split(b":", 1)[1].strip().decode()
                if got != expected:
                    raise ConnectionError("Sec-WebSocket-Accept mismatch")

    def send_text(self, text: str) -> None:
        data = text.encode()
        frame = self._make_frame(0x1, data)
        self._sock.sendall(frame)

    def recv_text(self, timeout: float = 2.0) -> str | None:
        ready, _, _ = select.select([self._sock], [], [], timeout)
        if not ready:
            return None
        return self._read_frame()

    def close(self) -> None:
        try:
            self._sock.sendall(self._make_frame(0x8, b""))
            self._sock.close()
        except OSError:
            pass

    @staticmethod
    def _make_frame(opcode: int, data: bytes) -> bytes:
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
        length = len(data)
        if length < 126:
            header = bytes([0x80 | opcode, 0x80 | length]) + mask_key
        elif length < 65536:
            header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", length) + mask_key
        else:
            header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", length) + mask_key
        return header + masked

    def _read_frame(self) -> str:
        def recv_exact(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("Connection closed")
                buf += chunk
            return buf

        while True:
            b0, b1 = recv_exact(2)
            opcode = b0 & 0x0F
            is_masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", recv_exact(8))[0]

            if is_masked:
                mask = recv_exact(4)
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(recv_exact(length)))
            else:
                data = recv_exact(length)

            if opcode == 0x1:    # text
                return data.decode()
            elif opcode == 0x2:  # binary — treat as latin-1 so no decode errors
                return data.decode("latin-1")
            elif opcode == 0x8:  # close
                raise ConnectionError("Server closed the WebSocket connection")
            elif opcode == 0x9:  # ping — must reply with pong or server will disconnect
                self._sock.sendall(self._make_frame(0xA, data))
            # 0xA pong, 0x0 continuation — skip and read next frame


# ── Replay mode ───────────────────────────────────────────────────────────────

def _replay(ws: _WS, pcap_path: str, rate_multiplier: float) -> None:
    try:
        from scapy.utils import rdpcap
        from scapy.all import IP, IPv6, TCP, UDP, Ether
    except ImportError:
        print("ERROR: scapy is required for replay mode.")
        print("       Run with:  pixi run --environment npcap python tools/ws_injector.py --mode replay ...")
        return

    print(f"[replay] loading {pcap_path} ...")
    try:
        pkts = rdpcap(pcap_path)
    except Exception as exc:
        print(f"ERROR: could not read pcap: {exc}")
        return

    if not pkts:
        print("ERROR: pcap is empty")
        return

    print(f"[replay] {len(pkts)} packets  ×{rate_multiplier:.1f} speed")
    print("Press Ctrl+C to stop.\n")

    first_ts = float(pkts[0].time)
    wall_start = time.time()

    for i, pkt in enumerate(pkts, start=1):
        pkt_offset = float(pkt.time) - first_ts
        target_wall = wall_start + pkt_offset / rate_multiplier
        sleep = target_wall - time.time()
        if sleep > 0:
            time.sleep(sleep)

        # Build packet dict from scapy layers
        src_ip = dst_ip = src_port = dst_port = None
        protocol = "Unknown"
        info = ""
        raw_hex = bytes(pkt).hex()
        payload_hex = ""

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                protocol = "TCP"
                app = bytes(tcp.payload)
                payload_hex = app.hex()
                info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  [replay]"
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport
                protocol = "UDP"
                ip_b = bytes(pkt[IP])
                ihl = (ip_b[0] & 0x0F) * 4
                app = ip_b[ihl + 8:]
                payload_hex = app.hex()
                info = f"{src_ip}:{src_port} → {dst_ip}:{dst_port}  [replay]"
            else:
                protocol = "IP"
                info = f"{src_ip} → {dst_ip}  [replay]"
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            src_ip, dst_ip = ip6.src, ip6.dst
            protocol = "IPv6"
            info = f"{src_ip} → {dst_ip}  [replay]"

        msg = {
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    src_port,
            "dst_port":    dst_port,
            "protocol":    protocol,
            "length":      len(bytes(pkt)),
            "info":        info,
            "raw_hex":     raw_hex,
            "payload_hex": payload_hex,
        }

        try:
            ws.send_text(json.dumps(msg))
            ack = ws.recv_text(timeout=2.0)
            status = json.loads(ack) if ack else {}
            marker = "✓" if status.get("ok") else "✗"
            print(f"  {marker} #{i:>5}  {protocol:<6}  {src_ip} → {dst_ip}")
        except (ConnectionError, KeyboardInterrupt):
            break


# ── Stream modes ──────────────────────────────────────────────────────────────

def _stream(ws: _WS, mode: str, interval: float, count: int | None, src_ip: str) -> None:
    label = "NC-Frame" if mode == "nc-frame" else "random"
    print(f"[inject] streaming {label} packets at {1/interval:.1f} Hz")
    print("Press Ctrl+C to stop.\n")

    seq = 0
    try:
        while count is None or seq < count:
            pkt = (
                _build_nc_frame_packet(seq, src_ip)
                if mode == "nc-frame"
                else _build_random_packet(seq, src_ip)
            )

            ws.send_text(json.dumps(pkt))
            ack = ws.recv_text(timeout=2.0)
            status = json.loads(ack) if ack else {}

            if not status.get("ok") and status.get("error") == "capture not running":
                print(f"  ⏸ seq={seq:>5}  discarded — click Start in NetCapture to begin recording")
            else:
                marker  = "✓" if status.get("ok") else "✗"
                preview = pkt["payload_hex"][:32] + ("…" if len(pkt["payload_hex"]) > 32 else "")
                print(f"  {marker} seq={seq:>5}  {pkt['length']:>4} B  {preview}")

            seq += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[inject] stopped after {seq} packets")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    # Detect local IP for sensible src_ip default
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"

    parser = argparse.ArgumentParser(
        description="WebSocket packet injector for NetCapture /ws/inject",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--mode", choices=["nc-frame", "random", "replay"], default="nc-frame",
        help="Streaming mode (default: nc-frame)",
    )
    parser.add_argument(
        "--url", default="ws://localhost:8000/ws/inject",
        help="Backend WebSocket URL (default: ws://localhost:8000/ws/inject)",
    )
    parser.add_argument(
        "--rate", type=float, default=2.0,
        help="Packets per second for nc-frame/random modes (default: 2.0)",
    )
    parser.add_argument(
        "--count", type=int, default=None,
        help="Stop after N packets (default: unlimited)",
    )
    parser.add_argument(
        "--src-ip", default=local_ip,
        help=f"Source IP to report in injected packets (default: {local_ip})",
    )
    parser.add_argument(
        "--file", default=None,
        help="Path to .pcap file for replay mode",
    )
    parser.add_argument(
        "--speed", type=float, default=1.0,
        help="Replay speed multiplier (default: 1.0 = real time, 2.0 = 2× faster)",
    )
    args = parser.parse_args()

    if args.mode == "replay" and not args.file:
        parser.error("--mode replay requires --file <path.pcap>")

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

    print(f"Connected.\n")

    try:
        if args.mode == "replay":
            _replay(ws, args.file, args.speed)
        else:
            _stream(ws, args.mode, 1.0 / max(args.rate, 0.01), args.count, args.src_ip)
    finally:
        ws.close()


if __name__ == "__main__":
    main()
