"""
NetCapture — embeddable real-time network capture library.

Embedding in a FastAPI application
───────────────────────────────────
    from netcapture import create_router

    app.include_router(create_router(), prefix="/netcapture")

Passing custom profiles and interpreters
─────────────────────────────────────────
    from netcapture import create_router, Interpreter, DecodedFrame, DecodedField

    class MyInterpreter:
        name = "My Protocol"

        def match(self, pkt: dict, payload: bytes) -> bool:
            return pkt.get("dst_port") == 5000

        def decode(self, payload: bytes) -> DecodedFrame:
            return DecodedFrame("My Protocol", fields=[
                DecodedField("raw", payload.hex(), "str"),
            ])

    app.include_router(create_router(
        profiles=[
            {
                "id":          "my-device",
                "name":        "My Device",
                "description": "Traffic on port 5000",
                "interface":   "any",
                "filter":      "port == 5000",
            },
        ],
        extra_interpreters=[MyInterpreter()],
        address_book=[
            {"id": "1", "address": "192.168.1.100",      "name": "My Sensor",   "notes": "Living room"},
            {"id": "2", "address": "192.168.1.100:9001",  "name": "Sensor Feed", "notes": "Port-specific name"},
        ],
    ), prefix="/netcapture")

Registering interpreters independently (before create_router is called)
────────────────────────────────────────────────────────────────────────
    from netcapture import register_interpreter

    register_interpreter(MyInterpreter())

The frontend component must be configured with matching URLs:

    <NetCapture
      wsUrl="wss://yourhost/netcapture/ws/capture"
      apiBase="/netcapture"
    />
"""

from ._router import create_router
from ._manager import CaptureManager
from .interpreters import register as register_interpreter, Interpreter, DecodedFrame, DecodedField
from .profiles import DEFAULT_PROFILES

__all__ = [
    "create_router",
    "CaptureManager",
    "register_interpreter",
    "Interpreter",
    "DecodedFrame",
    "DecodedField",
    "DEFAULT_PROFILES",
]
