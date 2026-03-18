"""
NC-Frame binary interpreter.

Wire layout:
  [0-1]  magic    0x4E 0x43  ("NC")
  [2]    version  0x01
  [3]    count    number of fields (uint8)
  [4…]   fields   repeated:
           [1]  key_len  (bytes)
           [N]  key      (UTF-8, N = key_len)
           [1]  tag      (type tag, see below)
           […]  value    (size determined by tag)

Type tags:
  0x01  u8    1 byte  unsigned integer
  0x02  u16   2 bytes big-endian unsigned integer
  0x03  u32   4 bytes big-endian unsigned integer
  0x04  f32   4 bytes IEEE 754 big-endian float
  0x05  str   1 byte length prefix + N bytes UTF-8
  0x06  bool  1 byte (0 = false, anything else = true)

The matching counterpart in the frontend is the NC-Frame section of interpreters.ts
(now unused — backend handles decoding and sends `decoded` in the packet dict).
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
    0x07: "json",   # 2-byte length prefix + UTF-8 JSON (list, dict, or any JSON value)
}


class NcFrameInterpreter:
    name = "NC-Frame"

    def match(self, pkt: dict, payload: bytes) -> bool:  # noqa: ARG002
        return (
            len(payload) >= 2
            and payload[0] == _MAGIC[0]
            and payload[1] == _MAGIC[1]
        )

    def decode(self, payload: bytes) -> DecodedFrame:
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

        try:
            for _ in range(count):
                # Key
                key_len = payload[off]
                off += 1
                key     = payload[off : off + key_len].decode()
                off += key_len

                # Tag
                tag       = payload[off]
                off += 1
                type_name = _TAG_NAMES.get(tag, f"0x{tag:02x}")

                # Value
                if tag == 0x01:    # u8
                    value: str | int | float | bool = payload[off] 
                    off += 1
                elif tag == 0x02:  # u16
                    value = struct.unpack_from("!H", payload, off)[0]
                    off += 2
                elif tag == 0x03:  # u32
                    value = struct.unpack_from("!I", payload, off)[0]
                    off += 4
                elif tag == 0x04:  # f32
                    value = round(struct.unpack_from("!f", payload, off)[0], 4)
                    off += 4
                elif tag == 0x05:  # str
                    slen  = payload[off]
                    off += 1
                    value = payload[off : off + slen].decode()
                    off += slen
                elif tag == 0x06:  # bool
                    value = payload[off] != 0
                    off += 1
                elif tag == 0x07:  # json (list / dict / any JSON value)
                    jlen  = struct.unpack_from("!H", payload, off)[0]
                    off += 2
                    value = json.loads(payload[off : off + jlen].decode())
                    off += jlen
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
