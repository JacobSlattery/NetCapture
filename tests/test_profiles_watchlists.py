"""
tests/test_profiles_watchlists.py — Unit tests for ProfileStore and WatchlistStore.

Covers CRUD, builtin immutability, file persistence, corrupt data recovery,
and WatchlistStore.replace_all.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from netcapture.profiles import ProfileStore, DEFAULT_PROFILES  # noqa: E402
from netcapture.watchlists import WatchlistStore  # noqa: E402


# ── ProfileStore ─────────────────────────────────────────────────────────────

class TestProfileStore:
    def test_defaults_present(self):
        store = ProfileStore(DEFAULT_PROFILES, path=None)
        profiles = store.list()
        assert len(profiles) >= len(DEFAULT_PROFILES)
        assert all(p.get("builtin") for p in profiles[:len(DEFAULT_PROFILES)])

    def test_create(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Test", "interface": "eth0"})
        assert entry["name"] == "Test"
        assert "id" in entry
        assert store.list() == [entry]

    def test_create_strips_builtin(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Test", "builtin": True})
        assert "builtin" not in entry

    def test_create_defaults(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Minimal"})
        assert entry["description"] == ""
        assert entry["filter"] == ""
        assert entry["bpf_filter"] == ""

    def test_update(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Original"})
        updated = store.update(entry["id"], {"name": "Updated", "filter": "tcp"})
        assert updated is not None
        assert updated["name"] == "Updated"
        assert updated["filter"] == "tcp"
        assert updated["id"] == entry["id"]

    def test_update_builtin_returns_none(self):
        store = ProfileStore(DEFAULT_PROFILES, path=None)
        result = store.update(DEFAULT_PROFILES[0]["id"], {"name": "Hacked"})
        assert result is None

    def test_update_nonexistent_returns_none(self):
        store = ProfileStore([], path=None)
        assert store.update("nope", {"name": "X"}) is None

    def test_update_strips_builtin(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Test"})
        updated = store.update(entry["id"], {"name": "U", "builtin": True})
        assert "builtin" not in updated # type: ignore

    def test_delete(self):
        store = ProfileStore([], path=None)
        entry = store.create({"name": "Doomed"})
        assert store.delete(entry["id"]) is True
        assert store.list() == []

    def test_delete_builtin_returns_false(self):
        store = ProfileStore(DEFAULT_PROFILES, path=None)
        assert store.delete(DEFAULT_PROFILES[0]["id"]) is False

    def test_delete_nonexistent_returns_false(self):
        store = ProfileStore([], path=None)
        assert store.delete("nope") is False

    def test_persistence_save_and_load(self, tmp_path):
        fp = tmp_path / "profiles.json"
        store1 = ProfileStore([], path=fp)
        store1.create({"name": "Persisted"})
        # Load in a new instance
        store2 = ProfileStore([], path=fp)
        assert len(store2.list()) == 1
        assert store2.list()[0]["name"] == "Persisted"

    def test_persistence_corrupt_file(self, tmp_path):
        fp = tmp_path / "profiles.json"
        fp.write_text("NOT JSON!!!", encoding="utf-8")
        store = ProfileStore([], path=fp)
        # Should recover — empty user list
        assert store.list() == []

    def test_persistence_non_list_json(self, tmp_path):
        fp = tmp_path / "profiles.json"
        fp.write_text('{"bad": "shape"}', encoding="utf-8")
        store = ProfileStore([], path=fp)
        assert store.list() == []

    def test_persistence_filters_non_dicts(self, tmp_path):
        fp = tmp_path / "profiles.json"
        fp.write_text('[{"name": "good"}, "bad", 42]', encoding="utf-8")
        store = ProfileStore([], path=fp)
        assert len(store.list()) == 1

    def test_list_combines_defaults_and_user(self):
        store = ProfileStore([{"id": "d1", "name": "Default"}], path=None)
        store.create({"name": "User"})
        profiles = store.list()
        assert len(profiles) == 2
        assert profiles[0]["builtin"] is True
        assert "builtin" not in profiles[1]


# ── WatchlistStore ───────────────────────────────────────────────────────────

class TestWatchlistStore:
    def test_create_defaults(self):
        store = WatchlistStore([], path=None)
        entry = store.create({"label": "Temp"})
        assert entry["label"] == "Temp"
        assert entry["fieldPath"] == ""
        assert entry["matcher"] == {}
        assert entry["group"] == ""
        assert "id" in entry

    def test_update(self):
        store = WatchlistStore([], path=None)
        entry = store.create({"label": "Orig"})
        updated = store.update(entry["id"], {"label": "New", "fieldPath": "temp"})
        assert updated["label"] == "New" # type: ignore
        assert updated["fieldPath"] == "temp" # type: ignore

    def test_update_builtin_returns_none(self):
        store = WatchlistStore([{"id": "b1", "label": "B"}], path=None)
        assert store.update("b1", {"label": "Hacked"}) is None

    def test_delete(self):
        store = WatchlistStore([], path=None)
        entry = store.create({"label": "Bye"})
        assert store.delete(entry["id"]) is True
        assert store.list() == []

    def test_delete_builtin_returns_false(self):
        store = WatchlistStore([{"id": "b1", "label": "B"}], path=None)
        assert store.delete("b1") is False

    def test_replace_all(self):
        store = WatchlistStore([], path=None)
        store.create({"label": "Old1"})
        store.create({"label": "Old2"})
        result = store.replace_all([
            {"id": "new1", "label": "New1"},
            {"id": "new2", "label": "New2", "builtin": True},
        ])
        # Builtins should be stripped from the replaced entries
        user_entries = [e for e in result if not e.get("builtin")]
        assert len(user_entries) == 2
        assert all("builtin" not in e for e in user_entries)

    def test_replace_all_clears_old(self):
        store = WatchlistStore([], path=None)
        store.create({"label": "WillBeGone"})
        store.replace_all([])
        assert store.list() == []

    def test_persistence(self, tmp_path):
        fp = tmp_path / "watchlists.json"
        store1 = WatchlistStore([], path=fp)
        store1.create({"label": "Persisted"})
        store2 = WatchlistStore([], path=fp)
        assert len(store2.list()) == 1

    def test_persistence_creates_parent_dirs(self, tmp_path):
        fp = tmp_path / "deep" / "nested" / "watchlists.json"
        store = WatchlistStore([], path=fp)
        store.create({"label": "Deep"})
        assert fp.exists()
