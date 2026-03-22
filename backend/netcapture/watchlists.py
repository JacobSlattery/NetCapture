"""
backend/watchlists.py — named watchlist definitions.

A watchlist entry pins a specific decoded field path and a packet matcher,
allowing the frontend to monitor that value across live traffic.

Fields
──────
  id              Unique identifier.
  label           Display name shown in the watchlist panel.
  fieldPath       Dot-separated decoded field path (e.g. "temperature",
                  "status.code", "items.0.name").
  matcher         Dict of optional packet-matching criteria:
                    protocol, src_ip, dst_ip, src_port, dst_port, interpreterName
  group           Optional grouping label (defaults to interpreterName).
  builtin         True for defaults passed to create_router — read-only.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path


DEFAULT_WATCHLISTS: list[dict] = []


class WatchlistStore:
    """
    Manages watchlist entries with optional file persistence.

    Built-in entries (from *defaults*) are always present and cannot be
    modified or deleted.  User-created entries are stored in *path* (JSON)
    and survive server restarts.  Pass ``path=None`` for in-memory-only mode.
    """

    def __init__(self, defaults: list[dict], path: Path | None = None) -> None:
        self._defaults: list[dict] = [dict(w, builtin=True) for w in defaults]
        self._path = path
        self._user: list[dict] = []
        if path is not None:
            self._load()

    def _load(self) -> None:
        if self._path and self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._user = [w for w in data if isinstance(w, dict)]
            except Exception as exc:
                print(f"[watchlists] warning: could not load {self._path}: {exc}")

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._user, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[watchlists] warning: could not save to {self._path}: {exc}")

    def list(self) -> list[dict]:
        return self._defaults + self._user

    def create(self, data: dict) -> dict:
        entry = {k: v for k, v in data.items() if k != "builtin"}
        entry.setdefault("id", uuid.uuid4().hex[:8])
        entry.setdefault("label", "")
        entry.setdefault("fieldPath", "")
        entry.setdefault("matcher", {})
        entry.setdefault("group", "")
        self._user.append(entry)
        self._save()
        return entry

    def update(self, entry_id: str, data: dict) -> dict | None:
        if any(w["id"] == entry_id for w in self._defaults):
            return None
        for i, w in enumerate(self._user):
            if w["id"] == entry_id:
                updated = {k: v for k, v in data.items() if k != "builtin"}
                updated["id"] = entry_id
                self._user[i] = updated
                self._save()
                return updated
        return None

    def delete(self, entry_id: str) -> bool:
        if any(w["id"] == entry_id for w in self._defaults):
            return False
        before = len(self._user)
        self._user = [w for w in self._user if w["id"] != entry_id]
        if len(self._user) < before:
            self._save()
            return True
        return False

    def replace_all(self, entries: list[dict]) -> list[dict]:
        """Replace all user entries (used for import/sync from frontend)."""
        self._user = [
            {k: v for k, v in e.items() if k != "builtin"}
            for e in entries
        ]
        self._save()
        return self.list()
