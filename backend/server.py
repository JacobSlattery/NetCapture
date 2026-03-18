"""
Standalone NetCapture server.

Runs the full NetCapture stack as a self-contained app: FastAPI + CORS +
static file serving + uvicorn.  This is the development / standalone entry
point used by pixi tasks.  When embedding NetCapture into a larger application
use create_router() instead:

    from netcapture import create_router
    app.include_router(create_router(), prefix="/netcapture")
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from netcapture import create_router

app = FastAPI(title="NetCapture", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(create_router())

_static = Path(__file__).parent / "netcapture" / "static"
if _static.exists():
    app.mount("/", StaticFiles(directory=str(_static), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
