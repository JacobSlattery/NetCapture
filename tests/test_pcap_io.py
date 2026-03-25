"""
tests/test_pcap_io.py — Unit tests for PCAP read/write round-trip.

Covers write_pcap, read_pcap, detect_linktype, big-endian magic,
empty packets, and edge cases.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture.pcap_io import (  # noqa: E402
    detect_linktype,
    write_pcap,
    read_pcap,
    PCAP_MAGIC,
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    _GLOBAL_HDR,
    _PKT_HDR,
)


# ── detect_linktype ──────────────────────────────────────────────────────────

class TestDetectLinktype:
    def test_ipv4_raw(self):
        assert detect_linktype("45000028") == LINKTYPE_RAW  # first nibble 4

    def test_ipv6_raw(self):
        assert detect_linktype("60000000") == LINKTYPE_RAW  # first nibble 6

    def test_ethernet(self):
        # first byte 0xFF (MAC broadcast) → not IP → Ethernet
        assert detect_linktype("ffffffffffff") == LINKTYPE_ETHERNET

    def test_short_hex(self):
        assert detect_linktype("4") == LINKTYPE_RAW  # < 2 chars

    def test_empty(self):
        assert detect_linktype("") == LINKTYPE_RAW


# ── write_pcap ───────────────────────────────────────────────────────────────

class TestWritePcap:
    def test_empty_returns_empty(self):
        assert write_pcap([]) == b""

    def test_empty_raw_hex_skipped(self):
        data = write_pcap([{"raw_hex": ""}])
        # Only the global header, no packet records
        assert len(data) == _GLOBAL_HDR.size

    def test_single_packet_round_trip(self):
        packets = [{"raw_hex": "45000028" + "00" * 36, "_epoch_ts": 1700000000.123456}]
        data = write_pcap(packets)
        linktype, frames = read_pcap(data)
        result = list(frames)
        assert len(result) == 1
        assert result[0]["raw_hex"] == packets[0]["raw_hex"]
        assert abs(result[0]["_epoch_ts"] - 1700000000.123456) < 0.001

    def test_multiple_packets(self):
        packets = [
            {"raw_hex": "45000014" + "00" * 16, "_epoch_ts": 1000.0},
            {"raw_hex": "45000014" + "FF" * 16, "_epoch_ts": 1001.0},
        ]
        data = write_pcap(packets)
        _, frames = read_pcap(data)
        result = list(frames)
        assert len(result) == 2
        assert result[0]["raw_hex"] != result[1]["raw_hex"]

    def test_relative_timestamp_fallback(self):
        packets = [{"raw_hex": "4500001400000000", "timestamp": "01:30.500"}]
        data = write_pcap(packets, session_start=0.0)
        _, frames = read_pcap(data)
        result = list(frames)
        # base_ts=0.0, relative = 1*60 + 30.5 = 90.5
        # But write_pcap uses: epoch = base_ts + mins*60 + secs
        # So the epoch stored is 90.5
        assert abs(result[0]["_epoch_ts"] - 90.5) < 0.01

    def test_linktype_from_first_packet(self):
        # Ethernet-looking packet (first nibble not 4 or 6)
        packets = [{"raw_hex": "ffffffffffff" + "00" * 20}]
        data = write_pcap(packets)
        magic, _, _, _, _, _, linktype = _GLOBAL_HDR.unpack_from(data)
        assert linktype == LINKTYPE_ETHERNET


# ── read_pcap ────────────────────────────────────────────────────────────────

class TestReadPcap:
    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            read_pcap(b"\x00" * 10)

    def test_bad_magic(self):
        data = _GLOBAL_HDR.pack(0xDEADBEEF, 2, 4, 0, 0, 65535, 1)
        with pytest.raises(ValueError, match="Bad pcap magic"):
            read_pcap(data)

    def test_big_endian_magic(self):
        """File with swapped magic (0xd4c3b2a1) should still parse."""
        raw_hex = "45000014" + "00" * 16
        raw = bytes.fromhex(raw_hex)
        # Build a big-endian pcap manually
        be_hdr = struct.Struct(">IIII")
        global_hdr = struct.pack(">IHHiIII", 0xd4c3b2a1, 2, 4, 0, 0, 65535, LINKTYPE_RAW)
        pkt_hdr = be_hdr.pack(1000, 0, len(raw), len(raw))
        data = global_hdr + pkt_hdr + raw
        linktype, frames = read_pcap(data)
        result = list(frames)
        assert len(result) == 1
        assert result[0]["raw_hex"] == raw_hex

    def test_empty_pcap_no_packets(self):
        data = _GLOBAL_HDR.pack(PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_RAW)
        _, frames = read_pcap(data)
        assert list(frames) == []

    def test_truncated_packet_stops_iteration(self):
        """If incl_len extends past end of data, iteration stops."""
        raw = b"\x45" * 20
        data = _GLOBAL_HDR.pack(PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_RAW)
        data += _PKT_HDR.pack(0, 0, 100, 100)  # claims 100 bytes
        data += raw  # but only 20 bytes present
        _, frames = read_pcap(data)
        result = list(frames)
        # Should yield the packet (slice is shorter, but no crash)
        assert len(result) == 1
