"""
python -m netcapture  — launch NetCapture as a standalone application.

Opens the full UI + backend on http://localhost:8000 (or --port / --host).

Usage
─────
    python -m netcapture
    python -m netcapture --port 9000
    python -m netcapture --host 0.0.0.0 --port 8080

The frontend must be built first (npm run build / pixi run build-ui).
If the static directory is missing, the API still runs but the UI won't load.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import create_router

app = FastAPI(title="NetCapture", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(create_router())

_static = Path(__file__).parent / "static"
if _static.exists():
    app.mount("/", StaticFiles(directory=str(_static), html=True), name="frontend")


def main() -> None:
    parser = argparse.ArgumentParser(description="NetCapture standalone server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()

    import uvicorn
    print(f"NetCapture running at http://{args.host}:{args.port}")
    uvicorn.run("netcapture.__main__:app", host=args.host, port=args.port,
                reload=False, log_level="info")


if __name__ == "__main__":
    main()
