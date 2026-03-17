"""
tools/udp_device.py — Mock UDP device for testing NetCapture's capture layer.

Sends/receives real UDP traffic on the machine's active LAN interface so that
the raw-socket capture (SIO_RCVALL) can pick it up.

IMPORTANT: must use the real interface IP, NOT 127.0.0.1 — loopback traffic
is invisible to SIO_RCVALL raw sockets on Windows.

Modes
─────
  sender   Fires UDP datagrams at <ip>:<port> every --interval seconds.
  receiver Listens on <ip>:<port> and prints arriving datagrams.
  echo     Listens on <ip>:<port>, prints each datagram and sends it back.
  chat     Runs sender + echo simultaneously (both sides visible in capture).

Usage examples
──────────────
  # Auto-detect local IP, echo server on port 9000
  python tools/udp_device.py --mode echo --port 9000

  # Sender firing at 5 Hz to a specific host
  python tools/udp_device.py --mode sender --ip 192.168.1.50 --port 9000 --rate 5

  # Full round-trip test on this machine (open two terminals):
  #   terminal 1:  python tools/udp_device.py --mode echo   --port 9000
  #   terminal 2:  python tools/udp_device.py --mode sender --port 9000

Run from the repo root:
  pixi run python tools/udp_device.py --mode chat --port 9000
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time

# ── Payloads ──────────────────────────────────────────────────────────────────

_MESSAGES: list[bytes] = [
    b'{"type":"ping","seq":%d,"ts":%d}',
    b"HELLO seq=%d time=%d",
    b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # minimal DNS-like
    b"\x06google\x03com\x00\x00\x01\x00\x01",
    b"NetCapture test packet seq=%d ts=%d",
    b"MEASURE,seq=%d,ts=%d,unit=ms",
]


def _make_payload(idx: int) -> bytes:
    template = _MESSAGES[idx % len(_MESSAGES)]
    t = int(time.time() * 1000)
    try:
        return template % (idx, t)
    except TypeError:
        return template  # template has no format slots


# ── IP helpers ────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the primary non-loopback IPv4 address of this machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


# ── Sender ────────────────────────────────────────────────────────────────────

def run_sender(
    dst_ip: str,
    dst_port: int,
    src_port: int,
    interval: float,
    count: int | None,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("", src_port))
        local = f"{get_local_ip()}:{sock.getsockname()[1]}"
        print(f"[sender] {local} → {dst_ip}:{dst_port}  interval={interval:.3f}s")
        seq = 0
        try:
            while count is None or seq < count:
                payload = _make_payload(seq)
                sock.sendto(payload, (dst_ip, dst_port))
                print(f"  ↑ seq={seq:>5}  {len(payload):>4} B  {payload[:60]}")
                seq += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[sender] stopped after {seq} packets")


# ── Receiver ─────────────────────────────────────────────────────────────────

def run_receiver(bind_ip: str, port: int, echo: bool = False) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_ip, port))
        sock.settimeout(1.0)
        label = "echo" if echo else "receiver"
        print(f"[{label}] listening on {bind_ip}:{port}")
        received = 0
        try:
            while True:
                try:
                    data, addr = sock.recvfrom(65535)
                    received += 1
                    print(f"  ↓ from {addr[0]}:{addr[1]}  {len(data):>4} B  {data[:60]}")
                    if echo:
                        sock.sendto(data, addr)
                        print(f"  ↑ echoed back to {addr[0]}:{addr[1]}")
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            print(f"\n[{label}] stopped — {received} packets received")


# ── Chat (sender + echo in the same process) ──────────────────────────────────

def run_chat(local_ip: str, port: int, interval: float) -> None:
    """
    Echo server on <local_ip>:<port>, sender fires at the same target.
    All traffic is on the real interface — fully visible to SIO_RCVALL.
    """
    print(f"[chat] echo server on {local_ip}:{port}")
    print(f"[chat] sender → {local_ip}:{port}  interval={interval:.3f}s")
    print("Press Ctrl+C to stop.\n")

    # Echo server thread
    stop = threading.Event()

    def _echo():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
            srv.bind((local_ip, port))
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    data, addr = srv.recvfrom(65535)
                    print(f"  ↓ {addr[0]}:{addr[1]} → {len(data)} B  {data[:50]}")
                    srv.sendto(data, addr)
                    print(f"  ↑ echoed")
                except socket.timeout:
                    pass

    t = threading.Thread(target=_echo, daemon=True)
    t.start()
    time.sleep(0.05)  # let server bind before sender starts

    # Sender (main thread)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as snd:
        seq = 0
        try:
            while True:
                payload = _make_payload(seq)
                snd.sendto(payload, (local_ip, port))
                print(f"  → seq={seq:>5}  {len(payload)} B")
                seq += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            t.join(timeout=2)
            print(f"\n[chat] stopped after {seq} sends")


# ── Feed mode (sends to backend UDP sink — no admin, works on loopback) ───────

def run_feed(backend_host: str, sink_port: int, interval: float, count: int | None) -> None:
    """
    Sends a stream of UDP datagrams directly to the NetCapture backend's UDP
    sink port (default 9001).  The backend receives them as normal application
    datagrams and streams each one to the frontend — no raw-socket or admin
    privileges required.

    Because we're sending to the backend process, loopback (127.0.0.1) is fine.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        target = (backend_host, sink_port)
        print(f"[feed] → {backend_host}:{sink_port}  interval={interval:.3f}s")
        print("Open the NetCapture display, disable Mock data, then click Start.\n")
        seq = 0
        try:
            while count is None or seq < count:
                payload = _make_payload(seq)
                sock.sendto(payload, target)
                print(f"  → seq={seq:>5}  {len(payload):>4} B  {payload[:60]}")
                seq += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[feed] stopped after {seq} packets")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    local_ip = get_local_ip()

    parser = argparse.ArgumentParser(
        description="Mock UDP device for testing NetCapture capture layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode", choices=["sender", "receiver", "echo", "chat", "feed"],
        default="feed",
        help=(
            "Operating mode (default: feed)\n"
            "  feed     — send to backend UDP sink on --backend-port (no admin needed)\n"
            "  chat     — echo server + sender on the LAN interface\n"
            "  sender   — send to --ip:--port\n"
            "  receiver — listen on --ip:--port\n"
            "  echo     — listen and echo back on --ip:--port"
        ),
    )
    parser.add_argument(
        "--ip", default=local_ip,
        help=f"Target/bind IP for sender/receiver/chat/echo (default: {local_ip})",
    )
    parser.add_argument(
        "--port", type=int, default=9000,
        help="UDP port for sender/receiver/chat/echo (default: 9000)",
    )
    parser.add_argument(
        "--backend", default="127.0.0.1",
        help="Backend host for feed mode (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--backend-port", type=int, default=9001,
        help="Backend UDP sink port for feed mode (default: 9001)",
    )
    parser.add_argument(
        "--src-port", type=int, default=0,
        help="Source port for sender (default: OS-assigned)",
    )
    parser.add_argument(
        "--rate", type=float, default=2.0,
        help="Packets per second (default: 2.0)",
    )
    parser.add_argument(
        "--count", type=int, default=None,
        help="Number of packets to send, then stop (default: unlimited)",
    )
    args = parser.parse_args()

    interval = 1.0 / max(args.rate, 0.01)

    print(f"Local interface IP detected as: {local_ip}")

    if args.mode == "feed":
        run_feed(args.backend, args.backend_port, interval, args.count)
    elif args.mode == "sender":
        if local_ip.startswith("127."):
            print("WARNING: loopback IP — SIO_RCVALL will NOT see this traffic (use --mode feed instead).")
        run_sender(args.ip, args.port, args.src_port, interval, args.count)
    elif args.mode == "receiver":
        run_receiver(args.ip, args.port, echo=False)
    elif args.mode == "echo":
        run_receiver(args.ip, args.port, echo=True)
    elif args.mode == "chat":
        if local_ip.startswith("127."):
            print("WARNING: loopback IP — SIO_RCVALL will NOT see this traffic (use --mode feed instead).")
        run_chat(args.ip, args.port, interval)


if __name__ == "__main__":
    main()
