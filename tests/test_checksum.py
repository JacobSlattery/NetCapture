"""
tests/test_checksum.py — Checksum validation unit tests.

Verifies _ones_complement_sum, _ip_checksum_ok, _tcp_checksum_ok,
_udp_checksum_ok, and compute_warnings against hand-crafted packets
with correct and corrupted checksums, padding, and fragments.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture.capture import (  # noqa: E402
    _ones_complement_sum,
    _ip_checksum_ok,
    _tcp_checksum_ok,
    _udp_checksum_ok,
    compute_warnings,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ip_checksum(header: bytearray) -> int:
    """Compute correct IP header checksum (RFC 1071)."""
    header[10:12] = b'\x00\x00'
    s = _ones_complement_sum(bytes(header))
    return (~s) & 0xFFFF


def _build_ip_header(
    proto: int,
    src: str,
    dst: str,
    payload_len: int,
    ttl: int = 64,
    flags_frag: int = 0x4000,  # DF, no fragments
    correct_checksum: bool = True,
) -> bytearray:
    total = 20 + payload_len
    hdr = bytearray(struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, flags_frag, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ))
    if correct_checksum:
        cksum = _ip_checksum(hdr)
        struct.pack_into("!H", hdr, 10, cksum)
    return hdr


def _tcp_checksum(src: str, dst: str, tcp_seg: bytearray) -> int:
    """Compute correct TCP checksum with pseudo-header."""
    tcp_seg[16:18] = b'\x00\x00'  # zero checksum field
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + bytes([0, 6]) + struct.pack("!H", len(tcp_seg)))
    s = _ones_complement_sum(pseudo + bytes(tcp_seg))
    return (~s) & 0xFFFF


def _udp_checksum(src: str, dst: str, udp_seg: bytearray) -> int:
    """Compute correct UDP checksum with pseudo-header."""
    udp_seg[6:8] = b'\x00\x00'
    udp_len = struct.unpack_from("!H", udp_seg, 4)[0]
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + bytes([0, 17]) + struct.pack("!H", udp_len))
    s = _ones_complement_sum(pseudo + bytes(udp_seg))
    return (~s) & 0xFFFF


def _make_tcp_packet(
    src="10.0.0.1", dst="10.0.0.2", sport=54321, dport=80,
    flags=0x02, payload=b"", correct_ip=True, correct_tcp=True,
    ip_flags_frag=0x4000,
) -> bytes:
    tcp_hdr = bytearray(struct.pack(
        "!HHIIBBHHH",
        sport, dport, 0, 0, (5 << 4), flags, 65535, 0, 0,
    ))
    tcp_seg = bytearray(tcp_hdr + payload)
    if correct_tcp:
        cksum = _tcp_checksum(src, dst, tcp_seg)
        struct.pack_into("!H", tcp_seg, 16, cksum)
    ip_hdr = _build_ip_header(6, src, dst, len(tcp_seg),
                              correct_checksum=correct_ip,
                              flags_frag=ip_flags_frag)
    return bytes(ip_hdr) + bytes(tcp_seg)


def _make_udp_packet(
    src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=9000,
    payload=b"hello", correct_ip=True, correct_udp=True,
    zero_checksum=False, ip_flags_frag=0x4000,
) -> bytes:
    length = 8 + len(payload)
    udp_seg = bytearray(struct.pack("!HHHH", sport, dport, length, 0) + payload)
    if zero_checksum:
        pass  # leave checksum as 0
    elif correct_udp:
        cksum = _udp_checksum(src, dst, udp_seg)
        struct.pack_into("!H", udp_seg, 6, cksum)
    else:
        struct.pack_into("!H", udp_seg, 6, 0xBEEF)  # bad checksum
    ip_hdr = _build_ip_header(17, src, dst, len(udp_seg),
                              correct_checksum=correct_ip,
                              flags_frag=ip_flags_frag)
    return bytes(ip_hdr) + bytes(udp_seg)


# ── _ones_complement_sum ─────────────────────────────────────────────────────

class TestOnesComplementSum:
    def test_zero_bytes(self):
        assert _ones_complement_sum(b'\x00\x00') == 0

    def test_single_word(self):
        assert _ones_complement_sum(b'\x00\x01') == 1

    def test_max_word(self):
        assert _ones_complement_sum(b'\xFF\xFF') == 0xFFFF

    def test_carry_wraps(self):
        # 0xFFFF + 0x0001 = 0x10000 → carry → 0x0001
        assert _ones_complement_sum(b'\xFF\xFF\x00\x01') == 0x0001

    def test_odd_length_padded(self):
        # Single byte 0x01 → padded to 0x0100 → sum = 256
        assert _ones_complement_sum(b'\x01') == 256

    def test_empty(self):
        assert _ones_complement_sum(b'') == 0

    def test_known_rfc_example(self):
        # RFC 1071 example: sum of 0x0001 + 0xF203 + 0xF4F5 + 0xF6F7
        data = b'\x00\x01\xF2\x03\xF4\xF5\xF6\xF7'
        result = _ones_complement_sum(data)
        # Manual: 1 + 0xF203 + 0xF4F5 + 0xF6F7 = 0x2DDF0 → 0xDDF0 + 2 = 0xDDF2
        assert result == 0xDDF2


# ── IP checksum ──────────────────────────────────────────────────────────────

class TestIpChecksum:
    def test_valid_ip_header(self):
        hdr = _build_ip_header(6, "192.168.1.1", "192.168.1.2", 20, correct_checksum=True)
        assert _ip_checksum_ok(bytes(hdr), 20) is True

    def test_bad_ip_header(self):
        hdr = _build_ip_header(6, "192.168.1.1", "192.168.1.2", 20, correct_checksum=False)
        assert _ip_checksum_ok(bytes(hdr), 20) is False

    def test_corrupted_byte_fails(self):
        hdr = bytearray(_build_ip_header(6, "10.0.0.1", "10.0.0.2", 20, correct_checksum=True))
        hdr[3] ^= 0xFF  # flip a byte
        assert _ip_checksum_ok(bytes(hdr), 20) is False


# ── TCP checksum ─────────────────────────────────────────────────────────────

class TestTcpChecksum:
    def test_valid_tcp(self):
        pkt = _make_tcp_packet(correct_tcp=True)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _tcp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is True

    def test_bad_tcp(self):
        pkt = _make_tcp_packet(correct_tcp=False)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _tcp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is False

    def test_valid_tcp_with_payload(self):
        pkt = _make_tcp_packet(payload=b"GET / HTTP/1.1\r\n", correct_tcp=True)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _tcp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is True


# ── UDP checksum ─────────────────────────────────────────────────────────────

class TestUdpChecksum:
    def test_valid_udp(self):
        pkt = _make_udp_packet(correct_udp=True)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _udp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is True

    def test_bad_udp(self):
        pkt = _make_udp_packet(correct_udp=False)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _udp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is False

    def test_zero_checksum_ok(self):
        pkt = _make_udp_packet(zero_checksum=True)
        src_bytes = socket.inet_aton("10.0.0.1")
        dst_bytes = socket.inet_aton("10.0.0.2")
        assert _udp_checksum_ok(pkt[20:], src_bytes, dst_bytes) is True


# ── compute_warnings (integration) ──────────────────────────────────────────

class TestComputeWarnings:
    def test_valid_tcp_no_warnings(self):
        pkt = _make_tcp_packet()
        assert compute_warnings(pkt) == []

    def test_valid_udp_no_warnings(self):
        pkt = _make_udp_packet()
        assert compute_warnings(pkt) == []

    def test_bad_ip_checksum(self):
        pkt = _make_tcp_packet(correct_ip=False, correct_tcp=True)
        w = compute_warnings(pkt)
        assert "Bad IP checksum" in w

    def test_bad_tcp_checksum(self):
        pkt = _make_tcp_packet(correct_ip=True, correct_tcp=False)
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" in w
        assert "Bad IP checksum" not in w

    def test_bad_udp_checksum(self):
        pkt = _make_udp_packet(correct_ip=True, correct_udp=False)
        w = compute_warnings(pkt)
        assert "Bad UDP checksum" in w
        assert "Bad IP checksum" not in w

    def test_both_bad(self):
        pkt = _make_tcp_packet(correct_ip=False, correct_tcp=False)
        w = compute_warnings(pkt)
        assert "Bad IP checksum" in w
        assert "Bad TCP checksum" in w

    def test_too_short(self):
        assert compute_warnings(b'\x45\x00') == []
        assert compute_warnings(b'') == []

    def test_ipv6_skipped(self):
        assert compute_warnings(b'\x60' + b'\x00' * 39) == []

    def test_ihl_too_small(self):
        # IHL = 3 (12 bytes) — invalid
        raw = bytearray(b'\x43' + b'\x00' * 19)
        assert compute_warnings(bytes(raw)) == []

    def test_trailing_padding_excluded(self):
        """Ethernet padding after the IP-declared total length must not corrupt checksum."""
        pkt = bytearray(_make_tcp_packet())
        # Add 20 bytes of non-zero padding — simulates Ethernet minimum frame
        pkt += b'\xDE\xAD' * 10
        # Should still pass — the IP total length field clips the segment
        assert compute_warnings(bytes(pkt)) == []

    def test_zero_padding_excluded(self):
        """Even zero padding should be excluded cleanly."""
        pkt = bytearray(_make_tcp_packet())
        pkt += b'\x00' * 20
        assert compute_warnings(bytes(pkt)) == []

    def test_fragment_skips_transport_check(self):
        """MF bit set — transport checksum cannot be validated."""
        # flags_frag = 0x2000 means MF=1, offset=0 (first fragment)
        pkt = _make_tcp_packet(correct_tcp=False, ip_flags_frag=0x2000)
        w = compute_warnings(pkt)
        # IP checksum should still be checked but TCP should be skipped
        assert "Bad TCP checksum" not in w

    def test_nonzero_fragment_offset_skips_transport(self):
        """Non-zero fragment offset — definitely not the full segment."""
        pkt = _make_tcp_packet(correct_tcp=False, ip_flags_frag=0x0080)
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" not in w

    def test_df_flag_no_fragment(self):
        """DF flag (0x4000) is not a fragment — transport check should run."""
        pkt = _make_tcp_packet(correct_tcp=False, ip_flags_frag=0x4000)
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" in w

    def test_no_flags_no_fragment(self):
        """flags_frag = 0x0000 means no DF, no MF, offset=0 — NOT a fragment."""
        pkt = _make_tcp_packet(correct_tcp=False, ip_flags_frag=0x0000)
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" in w

    def test_udp_zero_checksum_no_warning(self):
        pkt = _make_udp_packet(zero_checksum=True)
        assert compute_warnings(pkt) == []

    def test_truncated_tcp_segment_skipped(self):
        """TCP segment < 20 bytes — too short, skip transport check."""
        ip_hdr = _build_ip_header(6, "1.2.3.4", "5.6.7.8", 10, correct_checksum=True)
        pkt = bytes(ip_hdr) + b'\x00' * 10
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" not in w

    def test_truncated_udp_segment_skipped(self):
        """UDP segment < 8 bytes — too short, skip transport check."""
        ip_hdr = _build_ip_header(17, "1.2.3.4", "5.6.7.8", 4, correct_checksum=True)
        pkt = bytes(ip_hdr) + b'\x00' * 4
        w = compute_warnings(pkt)
        assert "Bad UDP checksum" not in w

    def test_non_tcp_udp_protocol(self):
        """ICMP (proto 1) — no transport checksum validation."""
        ip_hdr = _build_ip_header(1, "1.2.3.4", "5.6.7.8", 8, correct_checksum=True)
        pkt = bytes(ip_hdr) + b'\x08\x00\x00\x00\x00\x00\x00\x00'
        w = compute_warnings(pkt)
        assert "Bad TCP checksum" not in w
        assert "Bad UDP checksum" not in w

    def test_local_ip_suppresses_warnings(self):
        """Outgoing packets (src == local_ip) should suppress checksum warnings."""
        pkt = _make_tcp_packet(src="192.168.1.10", correct_ip=False, correct_tcp=False)
        # Without local_ip — warnings are reported
        w = compute_warnings(pkt)
        assert "Bad IP checksum" in w
        assert "Bad TCP checksum" in w
        # With matching local_ip — warnings suppressed (NIC offloading)
        w = compute_warnings(pkt, local_ip="192.168.1.10")
        assert w == []

    def test_local_ip_no_suppression_for_incoming(self):
        """Incoming packets (src != local_ip) should still report warnings."""
        pkt = _make_tcp_packet(src="10.0.0.1", correct_tcp=False)
        w = compute_warnings(pkt, local_ip="192.168.1.10")
        assert "Bad TCP checksum" in w

    def test_local_ip_none_no_effect(self):
        """local_ip=None should behave the same as before."""
        pkt = _make_tcp_packet(correct_tcp=False)
        w1 = compute_warnings(pkt)
        w2 = compute_warnings(pkt, local_ip=None)
        assert w1 == w2

    def test_ip_total_length_larger_than_buffer(self):
        """IP header claims more bytes than actually present — clip to len(raw)."""
        ip_hdr = bytearray(_build_ip_header(6, "10.0.0.1", "10.0.0.2", 200))
        # Only provide 20 bytes of TCP (not the 200 the header claims)
        tcp_seg = bytearray(struct.pack("!HHIIBBHHH", 80, 80, 0, 0, (5 << 4), 0x02, 65535, 0, 0))
        pkt = bytes(ip_hdr) + bytes(tcp_seg)
        # Should not crash — just tries with available bytes
        compute_warnings(pkt)  # no assertion, just verify no exception
