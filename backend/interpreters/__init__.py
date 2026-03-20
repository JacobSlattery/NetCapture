"""
backend/interpreters — translation-layer registry.

Each interpreter implements the Interpreter protocol:

    class MyInterpreter:
        name = "My Protocol"

        def match(self, pkt: dict, payload: bytes) -> bool:
            # Return True if this interpreter should handle the packet.
            # pkt contains the full parsed packet dict.  Available keys:
            #   src_ip       str             source IP address
            #   dst_ip       str             destination IP address
            #   src_port     int | None      source port (TCP/UDP only)
            #   dst_port     int | None      destination port (TCP/UDP only)
            #   protocol     str             e.g. "TCP", "UDP", "DNS", "TLS"
            #   length       int             total packet length in bytes
            #   ttl          int | None      IP time-to-live
            #   flags        str | None      TCP flags string, e.g. "SYN, ACK"
            #   info         str             one-line summary shown in the table
            #   raw_hex      str             full raw frame as a hex string
            #   _header_bytes bytes          raw transport header (TCP/UDP/ICMP
            #                               header bytes before the payload).
            #                               Empty bytes (b'') for non-TCP/UDP/ICMP.
            # payload is the isolated application-layer bytes (transport headers
            # already stripped).
            ...

        def decode(self, pkt: dict, payload: bytes) -> DecodedFrame:
            # Parse the payload and return structured fields.
            # pkt contains the same keys as match() above — useful when your
            # decoder needs transport-layer context (e.g. TCP sequence numbers,
            # source port for sub-protocol dispatch, _header_bytes for raw flags).
            ...

    register(MyInterpreter())

Registering an interpreter:
  Import and instantiate it in this file (after the registry helpers), or
  import your module from main.py before the first packet arrives.
  The first interpreter whose match() returns True wins.

Priority:
  By default interpreters are appended (run after built-ins).
  Pass prepend=True to register() to insert at the front of the registry so
  your interpreter is checked before the built-in NC-Frame decoder:

    register(MyInterpreter(), prepend=True)

Wire format sent to the frontend:
  {
    "interpreterName": "My Protocol",
    "fields": [
      {"key": "temp", "value": 23.5, "type": "f32"},
      ...
    ],
    "error": "optional error string",   // only present on failure
    "payloadOffset": 42                 // byte offset in raw_hex where payload starts
  }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class DecodedField:
    key:   str
    value: Any   # primitive, list, or dict — supports arbitrarily nested structures
    type:  str   # 'u8'|'u16'|'u32'|'u64'|'i8'|'i16'|'i32'|'i64'|'f32'|'f64'
                 # 'str'|'bool'|'hex'|'list'|'dict'

    def to_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "type": self.type}


@dataclass
class DecodedFrame:
    interpreter_name: str
    fields: list[DecodedField] = field(default_factory=list)
    error:  str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "interpreterName": self.interpreter_name,
            "fields": [f.to_dict() for f in self.fields],
        }
        if self.error is not None:
            d["error"] = self.error
        return d


# ── Interpreter protocol ──────────────────────────────────────────────────────

@runtime_checkable
class Interpreter(Protocol):
    """
    Structural protocol — implement these three members to create a decoder.

    name:
        String shown in the decoded panel header in the UI.

    match(pkt, payload) -> bool:
        Return True to claim this packet for decoding.
        pkt is the parsed packet dict (see module docstring for available keys).
        payload is the stripped application-layer bytes.
        If match() raises, the exception is swallowed and the next interpreter
        in the registry is tried.

    decode(pkt, payload) -> DecodedFrame:
        Parse payload into structured fields.
        pkt provides the same context as match() — handy for accessing
        _header_bytes, src_port, TCP sequence numbers, etc.
        If decode() raises, a DecodedFrame with an error message is returned
        and no further interpreters are tried.
    """
    name: str
    def match(self, pkt: dict, payload: bytes) -> bool: ...
    def decode(self, pkt: dict, payload: bytes) -> DecodedFrame: ...


# ── Registry ──────────────────────────────────────────────────────────────────

_REGISTRY: list[Interpreter] = []


def register(interp: Interpreter, *, prepend: bool = False) -> None:
    """
    Add an interpreter to the registry.  First match wins.

    prepend=True inserts at the front so your interpreter runs before
    the built-in NC-Frame decoder.  Default (False) appends to the end.
    """
    if prepend:
        _REGISTRY.insert(0, interp)
    else:
        _REGISTRY.append(interp)


def find_interpreter(pkt: dict, payload: bytes) -> DecodedFrame | None:
    """
    Walk the registry and return the first matching DecodedFrame, or None.
    Called from CaptureManager._emit_packet for every captured packet.

    match() exceptions are swallowed so a buggy match never blocks other
    interpreters.  decode() exceptions are caught and returned as error frames.
    """
    for interp in _REGISTRY:
        try:
            matched = interp.match(pkt, payload)
        except Exception:
            continue  # buggy match() — try the next interpreter
        if matched:
            try:
                return interp.decode(pkt, payload)
            except Exception as exc:
                return DecodedFrame(interp.name, error=f"Interpreter error: {exc}")
    return None


# ── Load built-in interpreters ────────────────────────────────────────────────
# Import each module so its register() call runs at import time.

from . import nc_frame as _nc_frame  # noqa: E402, F401
