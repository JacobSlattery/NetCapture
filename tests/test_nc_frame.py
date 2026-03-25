"""
tests/test_nc_frame.py — Unit tests for the NC-Frame binary interpreter.

Covers all 15 type tags, match heuristics, truncation handling,
unknown tags, and version mismatch.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture.interpreters.nc_frame import NcFrameInterpreter  # noqa: E402


interp = NcFrameInterpreter()
DUMMY_PKT = {}  # match/decode accept pkt but NC-Frame doesn't use it


def _frame(*field_specs: tuple[str, int, bytes]) -> bytes:
    """Build an NC-Frame payload: magic + version + count + fields."""
    buf = bytearray([0x4E, 0x43, 0x01, len(field_specs)])
    for key, tag, value_bytes in field_specs:
        key_bytes = key.encode()
        buf.append(len(key_bytes))
        buf.extend(key_bytes)
        buf.append(tag)
        buf.extend(value_bytes)
    return bytes(buf)


# ── Match ────────────────────────────────────────────────────────────────────

class TestMatch:
    def test_valid_magic(self):
        assert interp.match(DUMMY_PKT, b'\x4E\x43\x01\x00') is True

    def test_wrong_magic(self):
        assert interp.match(DUMMY_PKT, b'\x00\x00\x01\x00') is False

    def test_too_short(self):
        assert interp.match(DUMMY_PKT, b'\x4E') is False
        assert interp.match(DUMMY_PKT, b'') is False


# ── Decode — individual tags ─────────────────────────────────────────────────

class TestDecodeU8:
    def test_u8(self):
        payload = _frame(("val", 0x01, b'\x2A'))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == 42
        assert result.fields[0].type == "u8"

class TestDecodeU16:
    def test_u16(self):
        payload = _frame(("val", 0x02, struct.pack("!H", 1000)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == 1000
        assert result.fields[0].type == "u16"

class TestDecodeU32:
    def test_u32(self):
        payload = _frame(("val", 0x03, struct.pack("!I", 70000)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == 70000
        assert result.fields[0].type == "u32"

class TestDecodeU64:
    def test_u64(self):
        payload = _frame(("val", 0x0C, struct.pack("!Q", 2**48)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == 2**48
        assert result.fields[0].type == "u64"

class TestDecodeI8:
    def test_i8(self):
        payload = _frame(("val", 0x08, struct.pack("!b", -42)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == -42
        assert result.fields[0].type == "i8"

class TestDecodeI16:
    def test_i16(self):
        payload = _frame(("val", 0x09, struct.pack("!h", -1000)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == -1000

class TestDecodeI32:
    def test_i32(self):
        payload = _frame(("val", 0x0A, struct.pack("!i", -70000)))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == -70000

class TestDecodeI64:
    def test_i64(self):
        payload = _frame(("val", 0x0B, struct.pack("!q", -(2**48))))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == -(2**48)

class TestDecodeF32:
    def test_f32(self):
        payload = _frame(("val", 0x04, struct.pack("!f", 3.14)))
        result = interp.decode(DUMMY_PKT, payload)
        assert abs(result.fields[0].value - 3.14) < 0.001
        assert result.fields[0].type == "f32"

class TestDecodeF64:
    def test_f64(self):
        payload = _frame(("val", 0x0D, struct.pack("!d", 3.141592653589793)))
        result = interp.decode(DUMMY_PKT, payload)
        assert abs(result.fields[0].value - 3.141592653589793) < 1e-10
        assert result.fields[0].type == "f64"

class TestDecodeStr:
    def test_str(self):
        text = "hello"
        payload = _frame(("val", 0x05, bytes([len(text)]) + text.encode()))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == "hello"
        assert result.fields[0].type == "str"

    def test_empty_str(self):
        payload = _frame(("val", 0x05, b'\x00'))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == ""

class TestDecodeStrlong:
    def test_strlong(self):
        text = "a long string"
        payload = _frame(("val", 0x0F, struct.pack("!H", len(text)) + text.encode()))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == text
        assert result.fields[0].type == "strlong"

class TestDecodeBool:
    def test_true(self):
        payload = _frame(("val", 0x06, b'\x01'))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value is True

    def test_false(self):
        payload = _frame(("val", 0x06, b'\x00'))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value is False

    def test_nonzero_is_true(self):
        payload = _frame(("val", 0x06, b'\xFF'))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value is True

class TestDecodeJson:
    def test_json_list(self):
        j = json.dumps([1, 2, 3]).encode()
        payload = _frame(("val", 0x07, struct.pack("!H", len(j)) + j))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == [1, 2, 3]
        assert result.fields[0].type == "list"

    def test_json_dict(self):
        j = json.dumps({"a": 1}).encode()
        payload = _frame(("val", 0x07, struct.pack("!H", len(j)) + j))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == {"a": 1}
        assert result.fields[0].type == "object"

    def test_json_scalar(self):
        j = b'"hello"'
        payload = _frame(("val", 0x07, struct.pack("!H", len(j)) + j))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == "hello"
        assert result.fields[0].type == "json"

class TestDecodeHex:
    def test_hex(self):
        raw = b'\xDE\xAD\xBE\xEF'
        payload = _frame(("val", 0x0E, struct.pack("!H", len(raw)) + raw))
        result = interp.decode(DUMMY_PKT, payload)
        assert result.fields[0].value == "deadbeef"
        assert result.fields[0].type == "hex"


# ── Multiple fields ──────────────────────────────────────────────────────────

class TestMultipleFields:
    def test_two_fields(self):
        payload = _frame(
            ("temp", 0x04, struct.pack("!f", 23.5)),
            ("ok",   0x06, b'\x01'),
        )
        result = interp.decode(DUMMY_PKT, payload)
        assert len(result.fields) == 2
        assert result.fields[0].key == "temp"
        assert result.fields[1].key == "ok"
        assert result.error is None


# ── Error cases ──────────────────────────────────────────────────────────────

class TestDecodeErrors:
    def test_too_short_header(self):
        result = interp.decode(DUMMY_PKT, b'\x4E\x43')
        assert result.error is not None

    def test_bad_magic(self):
        result = interp.decode(DUMMY_PKT, b'\x00\x00\x01\x00')
        assert "Magic" in result.error # type: ignore

    def test_bad_version(self):
        result = interp.decode(DUMMY_PKT, b'\x4E\x43\x02\x00')
        assert "version" in result.error.lower() # type: ignore

    def test_unknown_tag(self):
        # Tag 0xFF is not recognized
        payload = bytearray([0x4E, 0x43, 0x01, 1, 3]) + b'key' + bytes([0xFF])
        result = interp.decode(DUMMY_PKT, bytes(payload))
        assert result.error is not None
        assert "0xff" in result.error.lower()

    def test_truncated_key(self):
        # Claims key length 10 but only 2 bytes follow
        payload = bytes([0x4E, 0x43, 0x01, 1, 10]) + b'ab'
        result = interp.decode(DUMMY_PKT, payload)
        assert result.error is not None

    def test_truncated_value(self):
        # u32 needs 4 bytes but only 2 provided
        payload = bytearray([0x4E, 0x43, 0x01, 1, 1]) + b'x' + bytes([0x03, 0x00, 0x00])
        result = interp.decode(DUMMY_PKT, bytes(payload))
        assert result.error is not None

    def test_truncated_at_tag(self):
        # Has key but no tag byte
        payload = bytearray([0x4E, 0x43, 0x01, 1, 1]) + b'x'
        result = interp.decode(DUMMY_PKT, bytes(payload))
        assert result.error is not None

    def test_truncated_at_key_len(self):
        # count=1 but nothing after header
        payload = bytes([0x4E, 0x43, 0x01, 1])
        result = interp.decode(DUMMY_PKT, payload)
        assert result.error is not None

    def test_partial_fields_returned_on_truncation(self):
        """First field decodes OK, second is truncated — fields[0] should be present."""
        payload = _frame(("ok", 0x06, b'\x01'))
        # Append a second field header that's truncated
        payload += bytes([3]) + b'bad' + bytes([0x03])  # u32 needs 4 bytes, 0 provided
        # Fix count to 2
        payload = bytearray(payload)
        payload[3] = 2
        result = interp.decode(DUMMY_PKT, bytes(payload))
        assert len(result.fields) == 1
        assert result.fields[0].key == "ok"
        assert result.error is not None
