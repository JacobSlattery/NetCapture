"""
NC-Frame binary interpreter.

Wire layout:
  [0-1]  magic    0x4E 0x43  ("NC")
  [2]    version  0x01
  [3]    count    number of fields (uint8, max 255)
  [4…]   fields   repeated:
           [1]  key_len  (uint8, max 255 bytes)
           [N]  key      (UTF-8, N = key_len)
           [1]  tag      (type tag — see table below)
           […]  value    (width determined by tag)

Type tags:
  Unsigned integers
  0x01  u8      1 byte  unsigned integer                  (0 - 255)
  0x02  u16     2 bytes big-endian unsigned integer       (0 - 65 535)
  0x03  u32     4 bytes big-endian unsigned integer       (0 - 4 294 967 295)
  0x0C  u64     8 bytes big-endian unsigned integer       (0 - 2^64-1)

  Signed integers
  0x08  i8      1 byte  signed integer                   (-128 - 127)
  0x09  i16     2 bytes big-endian signed integer        (-32 768 - 32 767)
  0x0A  i32     4 bytes big-endian signed integer        (-2 147 483 648 - 2 147 483 647)
  0x0B  i64     8 bytes big-endian signed integer        (-2^63 - 2^63-1)

  Floating-point
  0x04  f32     4 bytes IEEE 754 big-endian float
  0x0D  f64     8 bytes IEEE 754 big-endian double

  Text
  0x05  str     1-byte length prefix  + UTF-8  (max 255 bytes)
  0x0F  strlong 2-byte length prefix  + UTF-8  (max 65 535 bytes)

  Other
  0x06  bool    1 byte (0 = false, anything else = true)
  0x07  json    2-byte big-endian length prefix + UTF-8 JSON (list, dict, or any JSON value)
  0x0E  hex     2-byte big-endian length prefix + raw bytes  (displayed as a hex string)
"""

from __future__ import annotations

import json
import struct

from . import DecodedField, DecodedFrame, register

_MAGIC = (0x4E, 0x43)

_TAG_NAMES: dict[int, str] = {
    0x01: "u8",
    0x02: "u16",
    0x03: "u32",
    0x04: "f32",
    0x05: "str",
    0x06: "bool",
    0x07: "json",
    0x08: "i8",
    0x09: "i16",
    0x0A: "i32",
    0x0B: "i64",
    0x0C: "u64",
    0x0D: "f64",
    0x0E: "hex",
    0x0F: "strlong",
}


class NcFrameInterpreter:
    name = "NC-Frame"

    def match(self, pkt: dict, payload: bytes) -> bool:  # noqa: ARG002
        return (
            len(payload) >= 2
            and payload[0] == _MAGIC[0]
            and payload[1] == _MAGIC[1]
        )

    def decode(self, pkt: dict, payload: bytes) -> DecodedFrame:  # noqa: ARG001
        if len(payload) < 4:
            return DecodedFrame(self.name, error="Payload too short for NC-Frame header")
        if payload[0] != _MAGIC[0] or payload[1] != _MAGIC[1]:
            return DecodedFrame(self.name, error="Magic bytes mismatch")
        if payload[2] != 0x01:
            return DecodedFrame(
                self.name,
                error=f"Unsupported NC-Frame version 0x{payload[2]:02x}",
            )

        count  = payload[3]
        fields: list[DecodedField] = []
        off    = 4
        end    = len(payload)

        try:
            for _ in range(count):
                # ── Key ───────────────────────────────────────────────────────
                if off >= end:
                    return DecodedFrame(self.name, fields=fields, error="Truncated: expected key length byte")
                key_len = payload[off]
                off += 1
                if off + key_len > end:
                    return DecodedFrame(self.name, fields=fields, error=f"Truncated: key needs {key_len} bytes, only {end - off} remain")
                key     = payload[off : off + key_len].decode()
                off += key_len

                # ── Tag ───────────────────────────────────────────────────────
                if off >= end:
                    return DecodedFrame(self.name, fields=fields, error="Truncated: expected type tag byte")
                tag       = payload[off]
                off += 1
                type_name = _TAG_NAMES.get(tag, f"0x{tag:02x}")

                # ── Value ─────────────────────────────────────────────────────
                def _need(n: int) -> None:
                    if off + n > end:
                        raise ValueError(f"Truncated: value needs {n} bytes, only {end - off} remain")

                if tag == 0x01:    # u8
                    _need(1)
                    value: str | int | float | bool = payload[off]
                    off += 1

                elif tag == 0x02:  # u16
                    _need(2)
                    value = struct.unpack_from("!H", payload, off)[0]
                    off += 2

                elif tag == 0x03:  # u32
                    _need(4)
                    value = struct.unpack_from("!I", payload, off)[0]
                    off += 4

                elif tag == 0x04:  # f32
                    _need(4)
                    value = round(struct.unpack_from("!f", payload, off)[0], 6)
                    off += 4

                elif tag == 0x05:  # str  (1-byte length prefix, max 255 bytes)
                    _need(1)
                    slen  = payload[off]
                    off += 1
                    _need(slen)
                    value = payload[off : off + slen].decode()
                    off += slen

                elif tag == 0x06:  # bool
                    _need(1)
                    value = payload[off] != 0
                    off += 1

                elif tag == 0x07:  # json  (2-byte length prefix)
                    _need(2)
                    jlen  = struct.unpack_from("!H", payload, off)[0]
                    off += 2
                    _need(jlen)
                    value = json.loads(payload[off : off + jlen].decode())
                    off += jlen
                    # Refine generic "json" label based on actual decoded type
                    if isinstance(value, list):
                        type_name = "list"
                    elif isinstance(value, dict):
                        type_name = "object"

                elif tag == 0x08:  # i8
                    _need(1)
                    value = struct.unpack_from("!b", payload, off)[0]
                    off += 1

                elif tag == 0x09:  # i16
                    _need(2)
                    value = struct.unpack_from("!h", payload, off)[0]
                    off += 2

                elif tag == 0x0A:  # i32
                    _need(4)
                    value = struct.unpack_from("!i", payload, off)[0]
                    off += 4

                elif tag == 0x0B:  # i64
                    _need(8)
                    value = struct.unpack_from("!q", payload, off)[0]
                    off += 8

                elif tag == 0x0C:  # u64
                    _need(8)
                    value = struct.unpack_from("!Q", payload, off)[0]
                    off += 8

                elif tag == 0x0D:  # f64
                    _need(8)
                    value = round(struct.unpack_from("!d", payload, off)[0], 10)
                    off += 8

                elif tag == 0x0E:  # hex  (2-byte length prefix + raw bytes → hex string)
                    _need(2)
                    blen  = struct.unpack_from("!H", payload, off)[0]
                    off += 2
                    _need(blen)
                    value = payload[off : off + blen].hex()
                    off += blen

                elif tag == 0x0F:  # strlong  (2-byte length prefix, max 65 535 bytes)
                    _need(2)
                    slen  = struct.unpack_from("!H", payload, off)[0]
                    off += 2
                    _need(slen)
                    value = payload[off : off + slen].decode()
                    off += slen

                else:
                    return DecodedFrame(
                        self.name,
                        fields=fields,
                        error=f"Unknown type tag 0x{tag:02x} at byte offset {off - 1}",
                    )

                fields.append(DecodedField(key=key, value=value, type=type_name))

        except Exception as exc:
            return DecodedFrame(self.name, fields=fields, error=str(exc))

        return DecodedFrame(self.name, fields=fields)


register(NcFrameInterpreter())
