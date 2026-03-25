"""
tests/test_interpreters.py — Unit tests for the interpreter registry.

Covers register, find_interpreter, DecodedField/Frame serialization,
buggy interpreter recovery, and prepend ordering.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture.interpreters import (  # noqa: E402
    DecodedField,
    DecodedFrame,
    Interpreter,
    _REGISTRY,
    register,
    find_interpreter,
)


# ── DecodedField / DecodedFrame ──────────────────────────────────────────────

class TestDataModels:
    def test_field_to_dict(self):
        f = DecodedField(key="temp", value=23.5, type="f32")
        assert f.to_dict() == {"key": "temp", "value": 23.5, "type": "f32"}

    def test_frame_to_dict(self):
        f = DecodedField(key="x", value=1, type="u8")
        frame = DecodedFrame("Test", fields=[f])
        d = frame.to_dict()
        assert d["interpreterName"] == "Test"
        assert len(d["fields"]) == 1
        assert "error" not in d

    def test_frame_with_error(self):
        frame = DecodedFrame("Test", error="broken")
        d = frame.to_dict()
        assert d["error"] == "broken"

    def test_frame_empty_fields(self):
        frame = DecodedFrame("Test")
        d = frame.to_dict()
        assert d["fields"] == []


# ── Registry ─────────────────────────────────────────────────────────────────

class _DummyInterp:
    name = "Dummy"
    def match(self, pkt, payload):
        return payload == b"DUMMY"
    def decode(self, pkt, payload):
        return DecodedFrame("Dummy", fields=[DecodedField("x", 1, "u8")])


class _BuggyMatchInterp:
    name = "BuggyMatch"
    def match(self, pkt, payload):
        raise RuntimeError("match exploded")
    def decode(self, pkt, payload):
        return DecodedFrame("BuggyMatch")


class _BuggyDecodeInterp:
    name = "BuggyDecode"
    def match(self, pkt, payload):
        return True
    def decode(self, pkt, payload):
        raise RuntimeError("decode exploded")


class TestRegistry:
    def setup_method(self):
        """Save and restore registry to avoid polluting other tests."""
        self._saved = list(_REGISTRY)

    def teardown_method(self):
        _REGISTRY.clear()
        _REGISTRY.extend(self._saved)

    def test_register_append(self):
        interp = _DummyInterp()
        register(interp)
        assert _REGISTRY[-1] is interp
        _REGISTRY.pop()  # cleanup

    def test_register_prepend(self):
        interp = _DummyInterp()
        register(interp, prepend=True)
        assert _REGISTRY[0] is interp
        _REGISTRY.pop(0)  # cleanup

    def test_find_interpreter_match(self):
        _REGISTRY.clear()
        register(_DummyInterp())
        result = find_interpreter({}, b"DUMMY")
        assert result is not None
        assert result.interpreter_name == "Dummy"

    def test_find_interpreter_no_match(self):
        _REGISTRY.clear()
        register(_DummyInterp())
        result = find_interpreter({}, b"NOPE")
        assert result is None

    def test_buggy_match_skipped(self):
        _REGISTRY.clear()
        register(_BuggyMatchInterp())
        register(_DummyInterp())
        # BuggyMatch raises, should be skipped, DummyInterp should not match
        result = find_interpreter({}, b"DUMMY")
        assert result is not None
        assert result.interpreter_name == "Dummy"

    def test_buggy_decode_returns_error(self):
        _REGISTRY.clear()
        register(_BuggyDecodeInterp())
        result = find_interpreter({}, b"anything")
        assert result is not None
        assert "decode exploded" in result.error # type: ignore

    def test_empty_registry(self):
        _REGISTRY.clear()
        assert find_interpreter({}, b"anything") is None


# ── Interpreter protocol ─────────────────────────────────────────────────────

class TestInterpreterProtocol:
    def test_dummy_is_interpreter(self):
        assert isinstance(_DummyInterp(), Interpreter)

    def test_missing_method_not_interpreter(self):
        class Bad:
            name = "Bad"
            def match(self, pkt, payload): return True
            # missing decode
        assert not isinstance(Bad(), Interpreter)
