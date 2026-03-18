"""
backend/profiles.py — named capture profiles.

A profile bundles an interface selection with a pre-set display filter so
the user can pick a logical target ("UDP Device", "My Devices") from the
interface dropdown rather than manually entering filter expressions.

Fields
──────
  id          Unique slug used as the <option> value in the frontend.
  name        Display name shown in the dropdown.
  description Subtitle shown below the name (optional, UI hint).
  interface   Network interface to bind (matches an entry from /api/interfaces,
              or "any" for the default outbound interface).
  filter      Wireshark-style display filter expression.
              Uses the same syntax as the frontend filter bar.
              Leave empty to show all traffic on the selected interface.

Adding a profile
────────────────
  Append a dict to the PROFILES list below.  No restart needed if the
  frontend polls /api/profiles at load time; a hard refresh is sufficient
  when embedding in a larger SPA.
"""

from __future__ import annotations

PROFILES: list[dict] = [
    {
        "id":          "udp-device",
        "name":        "UDP Device",
        "description": "Traffic from udp_device — port 9001 (feed mode)",
        "interface":   "any",
        "filter":      "port == 9001",
    },
    {
        "id":          "my-devices",
        "name":        "My Devices",
        "description": "UDP device (9001) and TCP device (9000)",
        "interface":   "any",
        "filter":      "port == 9001 || port == 9000",
    },
]
