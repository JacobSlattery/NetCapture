"""
tests/test_manager.py — Unit tests for CaptureManager (non-network operations).

Tests the synchronous parts: reset, subscribe/unsubscribe, get_buffer, status,
_process_packet, _emit_packet, import_packets, and _matches_filter.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture._manager import CaptureManager, reset_session_start, _get_session_start  # noqa: E402


def _make_pkt(**overrides) -> dict:
    base = {
        "protocol": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 54321,
        "dst_port": 80,
        "length": 100,
        "info": "test",
        "raw_hex": "",
        "ttl": 64,
        "flags": "SYN",
        "warnings": None,
        "_payload": None,
        "_header_bytes": b"",
        "_payload_offset": 20,
    }
    base.update(overrides)
    return base


class TestCaptureManagerInit:
    def test_initial_state(self):
        mgr = CaptureManager()
        assert mgr.is_running is False
        assert mgr.status()["running"] is False
        assert mgr.status()["mode"] == "idle"
        assert mgr.get_buffer() == []

    def test_reset(self):
        mgr = CaptureManager()
        mgr._seq = 100
        mgr._total_bytes = 9999
        mgr._proto_counts = {"TCP": 50}
        mgr._buffer.append({"id": 1})
        mgr.reset()
        assert mgr._seq == 0
        assert mgr._total_bytes == 0
        assert mgr._proto_counts == {}
        assert len(mgr._buffer) == 0


class TestSubscription:
    def test_subscribe_unsubscribe(self):
        mgr = CaptureManager()
        q = mgr.subscribe()
        assert q in mgr._subs
        mgr.unsubscribe(q)
        assert q not in mgr._subs

    def test_unsubscribe_nonexistent(self):
        mgr = CaptureManager()
        q = asyncio.Queue()
        mgr.unsubscribe(q)  # should not raise


class TestProcessPacket:
    def test_assigns_id(self):
        mgr = CaptureManager()
        pkt = _make_pkt()
        result = mgr._process_packet(pkt, apply_filter=False)
        assert result is not None
        assert result["id"] == 1

    def test_increments_seq(self):
        mgr = CaptureManager()
        mgr._process_packet(_make_pkt(), apply_filter=False)
        mgr._process_packet(_make_pkt(), apply_filter=False)
        assert mgr._seq == 2

    def test_updates_stats(self):
        mgr = CaptureManager()
        mgr._process_packet(_make_pkt(protocol="UDP", length=50), apply_filter=False)
        assert mgr._proto_counts["UDP"] == 1
        assert mgr._total_bytes == 50
        assert mgr._sec_pkts == 1
        assert mgr._sec_bytes == 50

    def test_appends_to_buffer(self):
        mgr = CaptureManager()
        mgr._process_packet(_make_pkt(), apply_filter=False)
        assert len(mgr._buffer) == 1

    def test_strips_internal_fields(self):
        mgr = CaptureManager()
        pkt = _make_pkt()
        result = mgr._process_packet(pkt, apply_filter=False)
        assert "_header_bytes" not in result # type: ignore
        assert "_payload_offset" not in result # type: ignore
        assert "_payload" not in result # type: ignore

    def test_filter_rejects(self):
        mgr = CaptureManager()
        from netcapture._filter import parse_filter
        mgr._filter_ast = parse_filter("udp")
        mgr._filter_terms = ["udp"]
        pkt = _make_pkt(protocol="TCP")
        result = mgr._process_packet(pkt, apply_filter=True)
        assert result is None
        assert mgr._seq == 0  # not counted

    def test_filter_accepts(self):
        mgr = CaptureManager()
        from netcapture._filter import parse_filter
        mgr._filter_ast = parse_filter("tcp")
        mgr._filter_terms = ["tcp"]
        pkt = _make_pkt(protocol="TCP")
        result = mgr._process_packet(pkt, apply_filter=True)
        assert result is not None

    def test_apply_filter_false_bypasses(self):
        mgr = CaptureManager()
        from netcapture._filter import parse_filter
        mgr._filter_ast = parse_filter("udp")
        mgr._filter_terms = ["udp"]
        pkt = _make_pkt(protocol="TCP")
        result = mgr._process_packet(pkt, apply_filter=False)
        assert result is not None  # filter bypassed


class TestEmitPacket:
    def test_emit_broadcasts(self):
        mgr = CaptureManager()
        q = mgr.subscribe()
        pkt = _make_pkt()
        mgr._emit_packet(pkt)
        assert not q.empty()
        msg = json.loads(q.get_nowait())
        assert msg["type"] == "packet"
        assert msg["data"]["id"] == 1
        mgr.unsubscribe(q)

    def test_emit_full_queue_no_crash(self):
        mgr = CaptureManager()
        q = mgr.subscribe()
        # Fill the queue
        for _ in range(mgr.BUFFER_SIZE):
            try:
                q.put_nowait("filler")
            except asyncio.QueueFull:
                break
        # Should not raise even with full queue
        mgr._emit_packet(_make_pkt())
        mgr.unsubscribe(q)


class TestImportPackets:
    def test_import_assigns_ids(self):
        mgr = CaptureManager()
        pkts = [{"protocol": "TCP", "length": 10}, {"protocol": "UDP", "length": 20}]
        count = asyncio.run(mgr.import_packets(pkts))
        assert count == 2
        assert pkts[0]["id"] == 1
        assert pkts[1]["id"] == 2

    def test_import_resets_state(self):
        mgr = CaptureManager()
        mgr._seq = 100
        asyncio.run(mgr.import_packets([{"protocol": "X", "length": 1}]))
        assert mgr._seq == 1

    def test_import_broadcasts(self):
        mgr = CaptureManager()
        q = mgr.subscribe()
        asyncio.run(mgr.import_packets([{"protocol": "TCP", "length": 10}]))
        msg = json.loads(q.get_nowait())
        assert msg["type"] == "batch"
        mgr.unsubscribe(q)

    def test_import_empty(self):
        mgr = CaptureManager()
        count = asyncio.run(mgr.import_packets([]))
        assert count == 0


class TestMatchesFilter:
    def test_no_filter_always_true(self):
        mgr = CaptureManager()
        assert mgr._matches_filter({"protocol": "TCP"}) is True

    def test_with_filter(self):
        mgr = CaptureManager()
        from netcapture._filter import parse_filter
        mgr._filter_ast = parse_filter("tcp")
        mgr._filter_terms = ["tcp"]
        assert mgr._matches_filter({"protocol": "TCP"}) is True
        assert mgr._matches_filter({"protocol": "UDP"}) is False


class TestSessionTimer:
    def test_get_session_start(self):
        reset_session_start()
        t = _get_session_start()
        assert isinstance(t, float)
        assert t > 0

    def test_reset(self):
        _get_session_start()  # ensure initialized
        reset_session_start()
        # next call should re-initialize
        t = _get_session_start()
        assert t > 0


class TestEmitStats:
    def test_emit_stats(self):
        mgr = CaptureManager()
        q = mgr.subscribe()
        mgr._sec_pkts = 10
        mgr._sec_bytes = 5000
        mgr._emit_stats()
        msg = json.loads(q.get_nowait())
        assert msg["type"] == "stats"
        assert msg["data"]["packets_per_sec"] == 10
        assert msg["data"]["bytes_per_sec"] == 5000
        # Counters should be reset
        assert mgr._sec_pkts == 0
        assert mgr._sec_bytes == 0
        mgr.unsubscribe(q)


class TestStatus:
    def test_status_fields(self):
        mgr = CaptureManager()
        s = mgr.status()
        assert "running" in s
        assert "mode" in s
        assert "iface" in s
        assert "packets" in s
