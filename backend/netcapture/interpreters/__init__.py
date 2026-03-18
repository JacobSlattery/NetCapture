"""
backend/interpreters — translation-layer registry.

Each interpreter implements the Interpreter protocol:

    class MyInterpreter:
        name = "My Protocol"

        def match(self, pkt: dict, payload: bytes) -> bool:
            # Return True if this interpreter should handle the packet.
            # pkt contains the full packet dict (protocol, src_port, dst_port, …).
            # payload is the isolated application-layer bytes.
            ...

        def decode(self, payload: bytes) -> DecodedFrame:
            # Parse the payload and return structured fields.
            ...

    register(MyInterpreter())

Registering an interpreter:
  Import and instantiate it in this file (after the registry helpers), or
  import your module from main.py before the first packet arrives.
  The first interpreter whose match() returns True wins.

Wire format sent to the frontend:
  {
    "interpreterName": "My Protocol",
    "fields": [
      {"key": "temp", "value": 23.5, "type": "f32"},
      ...
    ],
    "error": "optional error string"   // only present on failure
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
    type:  str   # 'u8' | 'u16' | 'u32' | 'f32' | 'str' | 'bool' | 'list' | 'dict'

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
    name: str
    def match(self, pkt: dict, payload: bytes) -> bool: ...
    def decode(self, payload: bytes) -> DecodedFrame: ...


# ── Registry ──────────────────────────────────────────────────────────────────

_REGISTRY: list[Interpreter] = []


def register(interp: Interpreter) -> None:
    """Add an interpreter to the registry.  First match wins."""
    _REGISTRY.append(interp)


def find_interpreter(pkt: dict, payload: bytes) -> DecodedFrame | None:
    """
    Walk the registry and return the first matching DecodedFrame, or None.
    Called from CaptureManager._emit_packet for every captured packet.
    """
    for interp in _REGISTRY:
        try:
            if interp.match(pkt, payload):
                return interp.decode(payload)
        except Exception as exc:  # never let a buggy interpreter crash the capture loop
            return DecodedFrame(interp.name, error=f"Interpreter error: {exc}")
    return None


# ── Load built-in interpreters ────────────────────────────────────────────────
# Import each module so its register() call runs at import time.

from . import nc_frame as _nc_frame  # noqa: E402, F401
