"""
backend/profiles.py — named capture profiles.

A profile bundles an interface selection with a pre-set display filter so
the user can pick a logical target ("UDP Device", "UDP Device (BPF)") from the
interface dropdown rather than manually entering filter expressions.

Fields
──────
  id          Unique slug used as the <option> value in the frontend.
  name        Display name shown in the dropdown.
  description Subtitle shown below the name (optional, UI hint).
  interface   Network interface to bind. Use the system adapter name shown in
              the interface dropdown (e.g. "Ethernet", "Wi-Fi").
              Special values:
                "any"      — default outbound interface (scapy default)
                "loopback" — Npcap loopback adapter (127.0.0.1 inter-process traffic)
  filter      Wireshark-style display filter expression.
              Uses the same syntax as the frontend filter bar.
              Leave empty to show all traffic on the selected interface.
  bpf_filter  Optional kernel-level BPF filter applied at capture time.
              Only takes effect in Npcap mode. Examples: "tcp", "port 443",
              "host 192.168.1.1 and udp".

Adding a profile
────────────────
  Append a dict to the PROFILES list below.  No restart needed if the
  frontend polls /api/profiles at load time; a hard refresh is sufficient
  when embedding in a larger SPA.
"""

from __future__ import annotations

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
