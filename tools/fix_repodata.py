"""
Post-build fix: downgrade repodata.json from v2 to v1 for broad compatibility.

Run after `pixi run build-pkg` or `pixi run build-pkg-compiled`:
    python tools/fix_repodata.py dist/conda

This ensures the local channel works with all pixi / rattler versions.
"""

import json
import sys
from pathlib import Path


def fix(channel_dir: str) -> None:
    for repodata_path in Path(channel_dir).rglob("repodata.json"):
        data = json.loads(repodata_path.read_text())
        if data.get("repodata_version", 1) > 1:
            data["repodata_version"] = 1
            repodata_path.write_text(json.dumps(data, indent=2))
            print(f"  fixed {repodata_path} -> repodata_version 1")
        else:
            print(f"  ok    {repodata_path}")


if __name__ == "__main__":
    channel = sys.argv[1] if len(sys.argv) > 1 else "dist/conda"
    fix(channel)
