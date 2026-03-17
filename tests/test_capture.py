"""
tests/test_capture.py — Unit tests for backend/capture.py parsing layer.

These tests build raw IP packets from scratch using struct, then call
parse_packet() directly.  No raw socket / Administrator privileges required.

Run from repo root:
    pixi run python -m pytest tests/ -v
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

# Make the backend package importable without an install step
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from capture import parse_packet  # noqa: E402


# ── Packet builders ───────────────────────────────────────────────────────────

def _ip_header(
    proto: int,
    src: str,
    dst: str,
    payload_len: int,
    ttl: int = 64,
) -> bytes:
    total = 20 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                       # version=4, IHL=5
        0,                          # DSCP/ECN
        total,                      # total length
        0,                          # identification
        0x4000,                     # flags=DF, frag offset=0
        ttl,
        proto,
        0,                          # checksum (0 = unchecked)
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def _tcp(
    src_port: int,
    dst_port: int,
    flags: int = 0x10,   # ACK
    payload: bytes = b"",
) -> bytes:
    # data offset = 5 (20 bytes, no options)
    header = struct.pack(
        "!HHIIBBHH",
        src_port, dst_port,
        0,          # seq
        0,          # ack
        (5 << 4),   # data offset
        flags,
        65535,      # window
        0,          # checksum
    ) + b"\x00\x00"  # urgent pointer
    return header + payload


def _icmp(icmp_type: int, code: int = 0) -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + b"\x00" * 4


def make_udp_pkt(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=9000, data=b"hello") -> bytes:
    transport = _udp(sport, dport, data)
    return _ip_header(17, src, dst, len(transport)) + transport


def make_tcp_pkt(src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=80, flags=0x02) -> bytes:
    transport = _tcp(sport, dport, flags)
    return _ip_header(6, src, dst, len(transport)) + transport


def make_icmp_pkt(src="10.0.0.1", dst="10.0.0.2", icmp_type=8, code=0) -> bytes:
    transport = _icmp(icmp_type, code)
    return _ip_header(1, src, dst, len(transport)) + transport


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestUDP:
    def test_basic_fields(self):
        pkt = parse_packet(make_udp_pkt(), 0.0, 1)
        assert pkt is not None
        assert pkt["protocol"] == "UDP"
        assert pkt["src_ip"] == "10.0.0.1"
        assert pkt["dst_ip"] == "10.0.0.2"
        assert pkt["src_port"] == 12345
        assert pkt["dst_port"] == 9000

    def test_seq_and_id(self):
        pkt = parse_packet(make_udp_pkt(), 0.0, 42)
        assert pkt["id"] == 42

    def test_dns_label(self):
        pkt = parse_packet(make_udp_pkt(dport=53), 0.0, 1)
        assert pkt["protocol"] == "DNS"

    def test_dhcp_label(self):
        pkt = parse_packet(make_udp_pkt(dport=67), 0.0, 1)
        assert pkt["protocol"] == "DHCP"

    def test_length_in_ip_header(self):
        raw = make_udp_pkt(data=b"x" * 100)
        pkt = parse_packet(raw, 0.0, 1)
        # IP total length = 20 (IP) + 8 (UDP) + 100 (payload)
        assert pkt["length"] == 128

    def test_ttl(self):
        transport = _udp(1000, 2000, b"ttl-test")
        raw = _ip_header(17, "1.2.3.4", "5.6.7.8", len(transport), ttl=128) + transport
        pkt = parse_packet(raw, 0.0, 1)
        assert pkt["ttl"] == 128

    def test_info_contains_ports(self):
        pkt = parse_packet(make_udp_pkt(sport=11111, dport=22222), 0.0, 1)
        assert "11111" in pkt["info"]
        assert "22222" in pkt["info"]

    def test_no_flags(self):
        pkt = parse_packet(make_udp_pkt(), 0.0, 1)
        assert pkt["flags"] is None

    def test_raw_hex_starts_with_ipv4(self):
        # raw_hex now begins at the IP layer — first nibble must be 4 (IPv4)
        pkt = parse_packet(make_udp_pkt(), 0.0, 1)
        assert int(pkt["raw_hex"][0], 16) == 4


class TestTCP:
    def test_basic_fields(self):
        pkt = parse_packet(make_tcp_pkt(), 0.0, 1)
        assert pkt is not None
        assert pkt["protocol"] == "HTTP"   # port 80
        assert pkt["src_port"] == 54321
        assert pkt["dst_port"] == 80

    def test_syn_flag(self):
        pkt = parse_packet(make_tcp_pkt(flags=0x02), 0.0, 1)
        assert pkt["flags"] == "SYN"

    def test_ack_flag(self):
        pkt = parse_packet(make_tcp_pkt(flags=0x10), 0.0, 1)
        assert pkt["flags"] == "ACK"

    def test_psh_ack_flags(self):
        pkt = parse_packet(make_tcp_pkt(flags=0x18), 0.0, 1)
        assert "PSH" in pkt["flags"]
        assert "ACK" in pkt["flags"]

    def test_fin_ack_flags(self):
        pkt = parse_packet(make_tcp_pkt(flags=0x11), 0.0, 1)
        assert "FIN" in pkt["flags"]
        assert "ACK" in pkt["flags"]

    def test_rst_flag(self):
        pkt = parse_packet(make_tcp_pkt(flags=0x04), 0.0, 1)
        assert "RST" in pkt["flags"]

    def test_tls_label_on_443(self):
        pkt = parse_packet(make_tcp_pkt(dport=443), 0.0, 1)
        assert pkt["protocol"] == "TLS"

    def test_ssh_label_on_22(self):
        pkt = parse_packet(make_tcp_pkt(dport=22), 0.0, 1)
        assert pkt["protocol"] == "SSH"

    def test_unknown_port_falls_back_to_tcp(self):
        pkt = parse_packet(make_tcp_pkt(dport=19999), 0.0, 1)
        assert pkt["protocol"] == "TCP"

    def test_info_contains_flag_and_ips(self):
        pkt = parse_packet(make_tcp_pkt(src="1.2.3.4", dst="5.6.7.8", flags=0x02), 0.0, 1)
        assert "SYN" in pkt["info"]
        assert "1.2.3.4" in pkt["info"]
        assert "5.6.7.8" in pkt["info"]


class TestICMP:
    def test_echo_request(self):
        pkt = parse_packet(make_icmp_pkt(icmp_type=8), 0.0, 1)
        assert pkt is not None
        assert pkt["protocol"] == "ICMP"
        assert "Echo request" in pkt["info"]

    def test_echo_reply(self):
        pkt = parse_packet(make_icmp_pkt(icmp_type=0), 0.0, 1)
        assert "Echo reply" in pkt["info"]

    def test_dest_unreachable(self):
        pkt = parse_packet(make_icmp_pkt(icmp_type=3, code=1), 0.0, 1)
        assert "Dest unreachable" in pkt["info"]

    def test_no_ports(self):
        pkt = parse_packet(make_icmp_pkt(), 0.0, 1)
        assert pkt["src_port"] is None
        assert pkt["dst_port"] is None


class TestEdgeCases:
    def test_too_short_returns_none(self):
        assert parse_packet(b"\x45", 0.0, 1) is None
        assert parse_packet(b"", 0.0, 1) is None

    def test_ipv6_skipped(self):
        # first nibble = 6 → IPv6 → should return None
        raw = b"\x60" + b"\x00" * 39
        assert parse_packet(raw, 0.0, 1) is None

    def test_unknown_protocol(self):
        # IP proto 253 = experimental
        transport = b"\x00" * 8
        raw = _ip_header(253, "1.1.1.1", "2.2.2.2", len(transport)) + transport
        pkt = parse_packet(raw, 0.0, 1)
        assert pkt is not None
        assert pkt["protocol"] == "IP/253"

    def test_timestamp_fields_present(self):
        pkt = parse_packet(make_udp_pkt(), time.time(), 1)
        assert "timestamp" in pkt
        assert "abs_time" in pkt
        # timestamp should be MM:SS.mmm format
        assert ":" in pkt["timestamp"]

    def test_raw_hex_correct_length(self):
        data = b"PAYLOAD"
        raw = make_udp_pkt(data=data)
        pkt = parse_packet(raw, 0.0, 1)
        # raw_hex starts at the IP layer — no Ethernet prefix
        ip_total = 20 + 8 + len(data)
        expected_hex_len = ip_total * 2
        assert len(pkt["raw_hex"]) == expected_hex_len

    def test_truncated_tcp_payload(self):
        # Only 15 bytes of TCP (header needs 20) → should still return a packet
        # but parsed as unknown since TCP header is incomplete
        transport = b"\x00" * 15
        raw = _ip_header(6, "1.2.3.4", "5.6.7.8", len(transport)) + transport
        pkt = parse_packet(raw, 0.0, 1)
        # Should not crash — returns packet with generic label
        assert pkt is not None
