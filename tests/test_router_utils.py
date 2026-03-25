"""
tests/test_router_utils.py — Unit tests for router utility functions.

Covers _parse_addr, _normalize_inject_packet, inject_packet, inject_batch,
start_capture, stop_capture, reset_session, and get_status.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture._router import (  # noqa: E402
    _parse_addr,
    _normalize_inject_packet,
    inject_packet,
    inject_batch,
    start_capture,
    stop_capture,
    reset_session,
    get_status,
    get_buffer,
    on_packet,
    off_packet,
    on_stats,
    off_stats,
    packet_stream,
)
from netcapture._manager import manager  # noqa: E402


# ── _parse_addr ──────────────────────────────────────────────────────────────

class TestParseAddr:
    def test_empty(self):
        assert _parse_addr("") == ("", None)

    def test_host_only(self):
        assert _parse_addr("192.168.1.1") == ("192.168.1.1", None)

    def test_host_port(self):
        assert _parse_addr("192.168.1.1:8080") == ("192.168.1.1", 8080)

    def test_host_invalid_port(self):
        assert _parse_addr("192.168.1.1:abc") == ("192.168.1.1:abc", None)

    def test_host_port_zero(self):
        # Port 0 is out of range (1-65535)
        assert _parse_addr("192.168.1.1:0") == ("192.168.1.1:0", None)

    def test_host_port_too_high(self):
        assert _parse_addr("192.168.1.1:99999") == ("192.168.1.1:99999", None)

    def test_ipv6_bracketed(self):
        # Bracketed IPv6 is unambiguous and should be preferred by callers
        # _parse_addr doesn't strip brackets but at least doesn't crash
        assert _parse_addr("[::1]") == ("[::1]", None)

    def test_ipv6_with_port(self):
        # Ambiguous: last segment "8080" looks like a port and "2001:db8::1" still has ":"
        assert _parse_addr("2001:db8::1:8080") == ("2001:db8::1", 8080)

    def test_ipv6_loopback_ambiguous(self):
        # Known limitation: ::1 is ambiguous — "1" looks like a port
        # and ":" contains ":" so the heuristic treats it as host:port
        host, port = _parse_addr("::1")
        assert port == 1  # documents current (imperfect) behavior

    def test_port_1(self):
        assert _parse_addr("host:1") == ("host", 1)

    def test_port_65535(self):
        assert _parse_addr("host:65535") == ("host", 65535)


# ── _normalize_inject_packet ─────────────────────────────────────────────────

class TestNormalizeInjectPacket:
    def test_fills_defaults(self):
        pkt = {}
        _normalize_inject_packet(pkt)
        assert "abs_time" in pkt
        assert "timestamp" in pkt
        assert pkt["src_ip"] is None
        assert pkt["dst_ip"] is None
        assert pkt["src_port"] is None
        assert pkt["dst_port"] is None
        assert pkt["protocol"] == "Unknown"
        assert pkt["length"] == 0
        assert pkt["info"] == ""
        assert pkt["raw_hex"] == ""
        assert pkt["ttl"] is None
        assert pkt["flags"] is None

    def test_preserves_existing(self):
        pkt = {"protocol": "UDP", "src_ip": "1.2.3.4"}
        _normalize_inject_packet(pkt)
        assert pkt["protocol"] == "UDP"
        assert pkt["src_ip"] == "1.2.3.4"

    def test_payload_hex_decoded(self):
        pkt = {"payload_hex": "DEADBEEF"}
        _normalize_inject_packet(pkt)
        assert pkt["_payload"] == b'\xDE\xAD\xBE\xEF'
        assert "payload_hex" not in pkt  # popped

    def test_payload_hex_too_large(self):
        # 131073 hex chars = more than 64 KB limit
        pkt = {"payload_hex": "AA" * 65537}
        _normalize_inject_packet(pkt)
        assert "_payload" not in pkt

    def test_payload_hex_invalid(self):
        pkt = {"payload_hex": "ZZZZ"}
        _normalize_inject_packet(pkt)
        assert "_payload" not in pkt

    def test_no_payload_hex(self):
        pkt = {}
        _normalize_inject_packet(pkt)
        assert "_payload" not in pkt

    def test_timestamp_format(self):
        pkt = {}
        _normalize_inject_packet(pkt)
        # Should be MM:SS.mmm format
        ts = pkt["timestamp"]
        assert ":" in ts

    def test_abs_time_format(self):
        pkt = {}
        _normalize_inject_packet(pkt)
        # Should be HH:MM:SS.mmm format
        at = pkt["abs_time"]
        assert at.count(":") == 2
        assert "." in at


# ── inject_packet ────────────────────────────────────────────────────────────

class TestInjectPacket:
    def test_returns_false_when_not_running(self):
        manager._running = False
        result = inject_packet({"protocol": "TCP", "length": 10})
        assert result is False

    def test_returns_true_when_running(self):
        # Temporarily set running
        manager._running = True
        try:
            pkt = {"protocol": "UDP", "length": 50, "raw_hex": ""}
            result = inject_packet(pkt)
            assert result is True
            # Packet should have been normalized
            assert "abs_time" in pkt
            assert "timestamp" in pkt
        finally:
            manager._running = False
            manager.reset()


# ── inject_batch ────────────────────────────────────────────────────────────

class TestInjectBatch:
    def test_returns_zero_when_not_running(self):
        manager._running = False
        result = inject_batch([{"protocol": "TCP", "length": 10}])
        assert result == 0

    def test_returns_count_when_running(self):
        manager._running = True
        try:
            pkts = [
                {"protocol": "UDP", "length": 50, "raw_hex": ""},
                {"protocol": "TCP", "length": 30, "raw_hex": ""},
            ]
            result = inject_batch(pkts)
            assert result == 2
            # Both should have been normalized and assigned IDs
            assert pkts[0]["id"] == 1
            assert pkts[1]["id"] == 2
            assert "abs_time" in pkts[0]
            assert "abs_time" in pkts[1]
        finally:
            manager._running = False
            manager.reset()

    def test_skips_non_dict_entries(self):
        manager._running = True
        try:
            # Simulate malformed input (e.g. from untrusted JSON)
            batch: list = [{"protocol": "TCP", "length": 10, "raw_hex": ""}, "not a dict", 42]
            result = inject_batch(batch)
            assert result == 1
        finally:
            manager._running = False
            manager.reset()

    def test_empty_batch(self):
        manager._running = True
        try:
            result = inject_batch([])
            assert result == 0
        finally:
            manager._running = False
            manager.reset()


# ── start_capture / stop_capture / reset_session / get_status ───────────────

class TestCaptureLifecycle:
    def test_start_inject_mode(self):
        try:
            mode = asyncio.run(start_capture(interface="injected"))
            assert mode == "inject"
            assert manager.is_running is True
        finally:
            asyncio.run(stop_capture())

    def test_stop_when_not_running(self):
        # Should not raise
        asyncio.run(stop_capture())

    def test_get_status_idle(self):
        status = get_status()
        assert status["running"] is False
        assert "mode" in status
        assert "packets" in status

    def test_get_status_running(self):
        try:
            asyncio.run(start_capture())
            status = get_status()
            assert status["running"] is True
            assert status["mode"] == "inject"
        finally:
            asyncio.run(stop_capture())

    def test_reset_session_clears_buffer(self):
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            assert len(manager.get_buffer()) > 0
        finally:
            manager._running = False
        reset_session()
        assert len(manager.get_buffer()) == 0
        assert get_status()["packets"] == 0

    def test_start_stop_round_trip(self):
        asyncio.run(start_capture())
        assert manager.is_running is True
        inject_packet({"protocol": "UDP", "length": 20, "raw_hex": ""})
        assert get_status()["packets"] == 1
        asyncio.run(stop_capture())
        assert manager.is_running is False
        reset_session()


# ── get_buffer ──────────────────────────────────────────────────────────────

class TestGetBuffer:
    def test_empty_when_no_packets(self):
        reset_session()
        assert get_buffer() == []

    def test_returns_injected_packets(self):
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            inject_packet({"protocol": "UDP", "length": 20, "raw_hex": ""})
            buf = get_buffer()
            assert len(buf) == 2
            assert buf[0]["protocol"] == "TCP"
            assert buf[1]["protocol"] == "UDP"
        finally:
            manager._running = False
            manager.reset()

    def test_returns_copy(self):
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            buf1 = get_buffer()
            buf2 = get_buffer()
            assert buf1 is not buf2
        finally:
            manager._running = False
            manager.reset()


# ── on_packet / off_packet ──────────────────────────────────────────────────

class TestOnPacket:
    def test_callback_fires(self):
        received = []
        on_packet(lambda pkt: received.append(pkt))
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            assert len(received) == 1
            assert received[0]["protocol"] == "TCP"
        finally:
            manager._running = False
            manager.reset()
            manager._packet_cbs.clear()

    def test_callback_fires_for_batch(self):
        received = []
        on_packet(lambda pkt: received.append(pkt))
        manager._running = True
        try:
            inject_batch([
                {"protocol": "TCP", "length": 10, "raw_hex": ""},
                {"protocol": "UDP", "length": 20, "raw_hex": ""},
            ])
            assert len(received) == 2
        finally:
            manager._running = False
            manager.reset()
            manager._packet_cbs.clear()

    def test_decorator_usage(self):
        received = []

        @on_packet
        def handler(pkt):
            received.append(pkt["protocol"])

        manager._running = True
        try:
            inject_packet({"protocol": "UDP", "length": 5, "raw_hex": ""})
            assert received == ["UDP"]
        finally:
            manager._running = False
            manager.reset()
            off_packet(handler)

    def test_off_packet_stops_delivery(self):
        received = []
        cb = lambda pkt: received.append(pkt)  # noqa: E731
        on_packet(cb)
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            assert len(received) == 1
            off_packet(cb)
            inject_packet({"protocol": "UDP", "length": 20, "raw_hex": ""})
            assert len(received) == 1  # no new delivery
        finally:
            manager._running = False
            manager.reset()
            manager._packet_cbs.clear()

    def test_off_packet_nonexistent_no_error(self):
        off_packet(lambda: None)  # should not raise

    def test_exception_in_callback_does_not_crash(self):
        good_received = []

        def bad_cb(pkt):
            raise RuntimeError("boom")

        on_packet(bad_cb)
        on_packet(lambda pkt: good_received.append(pkt))
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            # Bad callback raised, but good callback still fired
            assert len(good_received) == 1
        finally:
            manager._running = False
            manager.reset()
            manager._packet_cbs.clear()

    def test_no_duplicate_registration(self):
        received = []
        cb = lambda pkt: received.append(1)  # noqa: E731
        on_packet(cb)
        on_packet(cb)  # should not add again
        manager._running = True
        try:
            inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
            assert len(received) == 1  # called once, not twice
        finally:
            manager._running = False
            manager.reset()
            manager._packet_cbs.clear()


# ── on_stats / off_stats ───────────────────────────────────────────────────

class TestOnStats:
    def test_callback_fires(self):
        received = []
        on_stats(lambda s: received.append(s))
        try:
            manager._emit_stats()
            assert len(received) == 1
            assert "total_packets" in received[0]
            assert "packets_per_sec" in received[0]
        finally:
            manager._stats_cbs.clear()

    def test_decorator_usage(self):
        received = []

        @on_stats
        def handler(s):
            received.append(s["total_bytes"])

        try:
            manager._emit_stats()
            assert len(received) == 1
        finally:
            off_stats(handler)

    def test_off_stats_stops_delivery(self):
        received = []
        cb = lambda s: received.append(s)  # noqa: E731
        on_stats(cb)
        manager._emit_stats()
        assert len(received) == 1
        off_stats(cb)
        manager._emit_stats()
        assert len(received) == 1  # not called again
        manager._stats_cbs.clear()

    def test_exception_does_not_crash(self):
        good = []
        on_stats(lambda s: (_ for _ in ()).throw(RuntimeError))  # raises
        on_stats(lambda s: good.append(s))
        try:
            manager._emit_stats()
            assert len(good) == 1
        finally:
            manager._stats_cbs.clear()


# ── packet_stream ───────────────────────────────────────────────────────────

class TestPacketStream:
    def test_yields_packets(self):
        async def _run():
            manager._running = True
            stream = packet_stream(queue_size=10)
            try:
                # Queue is registered immediately, so inject after creation
                inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
                inject_packet({"protocol": "UDP", "length": 20, "raw_hex": ""})
                pkt1 = await asyncio.wait_for(stream.__anext__(), timeout=1.0)
                pkt2 = await asyncio.wait_for(stream.__anext__(), timeout=1.0)
                return [pkt1, pkt2]
            finally:
                stream.close()
                manager._running = False
                manager.reset()

        results = asyncio.run(_run())
        assert len(results) == 2
        assert results[0]["protocol"] == "TCP"
        assert results[1]["protocol"] == "UDP"

    def test_close_unregisters(self):
        stream = packet_stream(queue_size=10)
        assert len(manager._packet_queues) == 1
        stream.close()
        assert len(manager._packet_queues) == 0

    def test_aclose(self):
        async def _run():
            stream = packet_stream(queue_size=10)
            assert len(manager._packet_queues) == 1
            await stream.aclose()
            assert len(manager._packet_queues) == 0

        asyncio.run(_run())

    def test_multiple_streams_independent(self):
        async def _run():
            manager._running = True
            s1 = packet_stream(queue_size=10)
            s2 = packet_stream(queue_size=10)
            try:
                assert len(manager._packet_queues) == 2
                inject_packet({"protocol": "TCP", "length": 10, "raw_hex": ""})
                p1 = await asyncio.wait_for(s1.__anext__(), timeout=1.0)
                p2 = await asyncio.wait_for(s2.__anext__(), timeout=1.0)
                assert p1["protocol"] == "TCP"
                assert p2["protocol"] == "TCP"
            finally:
                s1.close()
                s2.close()
                manager._running = False
                manager.reset()

        asyncio.run(_run())

    def test_dropped_when_full(self):
        """When queue is full, new packets are silently dropped."""
        manager._running = True
        stream = packet_stream(queue_size=2)
        try:
            inject_packet({"protocol": "TCP", "length": 1, "raw_hex": ""})
            inject_packet({"protocol": "TCP", "length": 2, "raw_hex": ""})
            inject_packet({"protocol": "TCP", "length": 3, "raw_hex": ""})  # dropped
            assert stream._q.qsize() == 2
        finally:
            stream.close()
            manager._running = False
            manager.reset()
