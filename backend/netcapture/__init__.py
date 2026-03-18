"""
NetCapture — embeddable real-time network capture library.

Embedding in a FastAPI application
───────────────────────────────────
    from netcapture import create_router

    app.include_router(create_router(), prefix="/netcapture")

The frontend component must be configured with matching URLs:

    <NetCapture
      wsUrl="wss://yourhost/netcapture/ws/capture"
      apiBase="/netcapture"
    />
"""

from ._router import create_router
from ._manager import CaptureManager

__all__ = ["create_router", "CaptureManager"]
