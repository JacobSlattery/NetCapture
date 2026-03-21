"""
backend/profiles.py — named capture profiles.

A profile bundles an interface, capture filter, and optional BPF filter so the
user can pick a logical target ("UDP Device") from the dropdown instead of
configuring everything by hand each session.

Fields
──────
  id          Unique slug.
  name        Display name shown in the dropdown.
  description Optional subtitle / UI hint.
  interface   Network interface to bind.  Comma-separate for multiple
              interfaces (npcap/scapy mode only): "eth0, eth1".
              Special values: "any" (default), "loopback" (Npcap loopback).
  filter      Python-style capture filter — same syntax as the display filter
              bar.  Applied as a pre-filter in the capture thread on both
              npcap and raw-socket modes (unless the expression references
              interpreter / decoded fields, in which case it runs post-decode).
  bpf_filter  Optional kernel-level BPF filter (npcap mode only).
              Uses BPF syntax: "tcp", "udp port 9001", "host 192.168.1.1".
  builtin     True for the built-in defaults — read-only (set by ProfileStore).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path


DEFAULT_PROFILES: list[dict] = [
    {
        "id":          "udp-device",
        "name":        "UDP Device",
        "description": "Traffic from udp_device — port 9001 (feed mode)",
        "interface":   "loopback",
        "filter":      "port == 9001",
    },
    {
        "id":          "udp-device-bpf",
        "name":        "UDP Device (BPF)",
        "description": "UDP device (9001) and TCP device (9000)",
        "interface":   "loopback",
        "bpf_filter":  "udp port 9001",
    },
]


class ProfileStore:
    """
    Manages capture profiles with optional file persistence.

    Built-in profiles (from *defaults*) are always present and cannot be
    modified or deleted.  User-created profiles are stored in *path* (JSON)
    and survive server restarts.  Pass ``path=None`` for in-memory-only mode.
    """

    def __init__(self, defaults: list[dict], path: Path | None = None) -> None:
        self._defaults: list[dict] = [dict(p, builtin=True) for p in defaults]
        self._path = path
        self._user: list[dict] = []
        if path is not None:
            self._load()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path and self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._user = [p for p in data if isinstance(p, dict)]
            except Exception as exc:
                print(f"[profiles] warning: could not load {self._path}: {exc}")

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._user, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[profiles] warning: could not save to {self._path}: {exc}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def list(self) -> list[dict]:
        return self._defaults + self._user

    def create(self, data: dict) -> dict:
        entry = {k: v for k, v in data.items() if k != "builtin"}
        entry.setdefault("id", uuid.uuid4().hex[:8])
        entry.setdefault("description", "")
        entry.setdefault("filter", "")
        entry.setdefault("bpf_filter", "")
        self._user.append(entry)
        self._save()
        return entry

    def update(self, profile_id: str, data: dict) -> dict | None:
        """Returns the updated profile, or None if not found or is a builtin."""
        if any(p["id"] == profile_id for p in self._defaults):
            return None  # built-ins are read-only
        for i, p in enumerate(self._user):
            if p["id"] == profile_id:
                updated = {k: v for k, v in data.items() if k != "builtin"}
                updated["id"] = profile_id
                self._user[i] = updated
                self._save()
                return updated
        return None

    def delete(self, profile_id: str) -> bool:
        """Returns True if deleted, False if not found or is a builtin."""
        if any(p["id"] == profile_id for p in self._defaults):
            return False  # built-ins cannot be deleted
        before = len(self._user)
        self._user = [p for p in self._user if p["id"] != profile_id]
        if len(self._user) < before:
            self._save()
            return True
        return False
