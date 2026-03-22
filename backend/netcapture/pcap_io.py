"""
Minimal libpcap (.pcap) reader and writer.

No external dependencies — uses only Python stdlib struct.
Supports link types:
  1   = LINKTYPE_ETHERNET  (frames include 14-byte Ethernet header)
  101 = LINKTYPE_RAW       (frames start at IP header)
"""
from __future__ import annotations

import struct
import time
from typing import Iterator

PCAP_MAGIC        = 0xa1b2c3d4
PCAP_VERSION_MAJ  = 2
PCAP_VERSION_MIN  = 4
PCAP_SNAPLEN      = 65535

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW      = 101

_GLOBAL_HDR = struct.Struct("<IHHiIII")   # magic, maj, min, thiszone, sigfigs, snaplen, linktype
_PKT_HDR    = struct.Struct("<IIII")       # ts_sec, ts_usec, incl_len, orig_len


def detect_linktype(raw_hex: str) -> int:
    """
    Heuristic: if the first byte has upper nibble 4 or 6 it's a raw IP frame;
    otherwise assume Ethernet.
    """
    if len(raw_hex) < 2:
        return LINKTYPE_RAW
    first = int(raw_hex[:2], 16)
    return LINKTYPE_RAW if (first >> 4) in (4, 6) else LINKTYPE_ETHERNET


def write_pcap(packets: list[dict], session_start: float | None = None) -> bytes:
    """
    Serialise a list of packet dicts to a libpcap byte string.

    Each dict must have ``raw_hex`` (str) and optionally ``_epoch_ts`` (float).
    Falls back to wall-clock time for packets lacking ``_epoch_ts``.
    """
    if not packets:
        return b""

    # Determine link type from first packet with data
    linktype = LINKTYPE_RAW
    for p in packets:
        if p.get("raw_hex"):
            linktype = detect_linktype(p["raw_hex"])
            break

    out = bytearray()
    out += _GLOBAL_HDR.pack(
        PCAP_MAGIC, PCAP_VERSION_MAJ, PCAP_VERSION_MIN, 0, 0, PCAP_SNAPLEN, linktype
    )

    base_ts = session_start or time.time()
    for pkt in packets:
        raw = bytes.fromhex(pkt.get("raw_hex") or "")
        if not raw:
            continue
        epoch = pkt.get("_epoch_ts")
        if epoch is None:
            # Try to reconstruct from relative timestamp "MM:SS.mmm"
            try:
                ts_str = pkt.get("timestamp", "00:00.000")
                parts  = ts_str.split(":")
                mins, secs = float(parts[0]), float(parts[1])
                epoch = base_ts + mins * 60 + secs
            except Exception:
                epoch = base_ts
        ts_sec  = int(epoch)
        ts_usec = int((epoch - ts_sec) * 1_000_000)
        length  = len(raw)
        out += _PKT_HDR.pack(ts_sec, ts_usec, length, length)
        out += raw

    return bytes(out)


def read_pcap(data: bytes) -> tuple[int, Iterator[dict]]:
    """
    Parse a libpcap byte string.

    Returns (linktype, iterator_of_raw_dicts).
    Each dict has ``raw_hex`` (str) and ``_epoch_ts`` (float).
    Raises ValueError on bad magic number.
    """
    if len(data) < _GLOBAL_HDR.size:
        raise ValueError("File too short to be a valid pcap")

    magic, maj, min_, _, _, snaplen, linktype = _GLOBAL_HDR.unpack_from(data, 0)

    if magic not in (PCAP_MAGIC, 0xd4c3b2a1):
        raise ValueError(f"Bad pcap magic: 0x{magic:08x}")

    swap = magic == 0xd4c3b2a1  # big-endian pcap
    _pkt_hdr = struct.Struct(">IIII") if swap else _PKT_HDR

    def _iter() -> Iterator[dict]:
        offset = _GLOBAL_HDR.size
        while offset + _pkt_hdr.size <= len(data):
            ts_sec, ts_usec, incl_len, orig_len = _pkt_hdr.unpack_from(data, offset)
            offset += _pkt_hdr.size
            raw = data[offset: offset + incl_len]
            offset += incl_len
            yield {
                "raw_hex":   raw.hex(),
                "_epoch_ts": ts_sec + ts_usec / 1_000_000,
            }

    return linktype, _iter()
