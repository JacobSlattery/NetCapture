# NetCapture

Real-time network packet capture and analysis tool. Runs standalone or embeds into a larger Svelte + FastAPI application.

**Key features:**

- Live packet capture via Npcap (L2, loopback) or raw sockets (IP-layer, Administrator)
- WebSocket injection for test traffic without elevated privileges
- Wireshark-style display filter with autocomplete and saved presets
- Protocol interpreters with structured field decoding (built-in NC-Frame, extensible)
- Packet detail panel with hex viewer, layer coloring, and decoded fields
- Address book for naming IPs and IP:port pairs
- PCAP, CSV, and JSON import/export
- Track mode to follow a specific connection across packets
- Watchlist panel to monitor specific decoded field values from multiple packet sources simultaneously
- Embeddable as a Svelte component + FastAPI router in larger applications

---

## Requirements

- [Pixi](https://prefix.dev/docs/pixi/overview) — manages Python and Node environments
- [Node.js](https://nodejs.org) >= 20 (provided by Pixi)
- Python >= 3.11 (provided by Pixi)
- **Windows only** — raw socket and Npcap capture are Windows-specific; PCAP/JSON/CSV import and export work on any platform

---

## Standalone — Development

Two terminals: one for the backend API, one for the Vite dev server.

**Terminal 1 — backend**
```bash
pixi run dev-api
```
Starts FastAPI + uvicorn on `http://localhost:8000`.

**Terminal 2 — frontend**
```bash
pixi run install-ui   # first time only
pixi run dev-ui
```
Starts the Vite dev server on `http://localhost:5173`.

---

## Standalone — Production Build

Builds the frontend into the backend package, then serves everything from a single process on port 8000.

```bash
pixi run serve
```

Or manually:
```bash
pixi run build-ui          # compiles frontend → backend/netcapture/static/
python backend/server.py   # FastAPI serves API + static files
```

---

## Building a Conda Package

Build NetCapture as a `.conda` package for installation into other pixi environments.

### Pure Python (default)

```bash
pixi run build-pkg
```

Builds the frontend, then packages everything into a pure-Python `.conda` artifact at `dist/conda/`. Works with any Python 3.11-3.12, full stack traces, no compiler needed at build time.

### Compiled (Cython)

```bash
pixi run build-pkg-compiled
```

Same as above but compiles implementation modules to native `.pyd` extensions via Cython. Source code is not human-readable in the output package. Only public API stubs (`__init__.py`, `__main__.py`, `interpreters/__init__.py`) remain as Python.

**Requirements:** Visual Studio 2022 (any edition with C++ build tools).

**Trade-offs vs pure Python:**
- Source code is not directly readable
- Locked to a single Python version (cp312) and platform (win-64)
- Stack traces show compiled function names instead of source lines
- `inspect.getsource()` and monkey-patching don't work on compiled modules

### Installing the package

In the consuming project's `pixi.toml`, point to the local channel:

```toml
channels = ["file:///C:/path/to/NetCapture/dist/conda", "conda-forge"]

[dependencies]
netcapture = ">=1.0.0"
```

---

## Capture Modes

NetCapture selects a capture mode automatically, in order of preference:

| Mode | Requires | What it captures |
|------|----------|-----------------|
| `scapy` | Npcap + scapy installed, `--environment npcap` | All traffic on any interface including loopback (L2) |
| `real` | Run as Administrator | All IP traffic on one non-loopback interface |
| `inject` | Nothing | Packets pushed in via `/ws/inject` — use a capture profile with **Enable injection** and no interface set |

The active mode is shown as a badge in the toolbar (e.g. **Npcap** or **Raw**).

### Enabling Npcap / Scapy

1. Download and install [Npcap](https://npcap.com). Check **"WinPcap API-compatible mode"** during install.
2. Run the backend in the npcap environment:

```bash
pixi run --environment npcap dev-api
```

Or for production:
```bash
pixi run --environment npcap serve
```

### Forcing a Capture Mode

Set `NETCAPTURE_MODE` to pin a specific mode instead of auto-detecting:

```bash
NETCAPTURE_MODE=scapy   pixi run --environment npcap dev-api   # require scapy/npcap
NETCAPTURE_MODE=real    pixi run dev-api                        # require raw sockets (admin)
```

If the forced mode is unavailable the server will return an error rather than silently falling back.

---

## Mock Devices

### WebSocket Injector (`ws_injector.py`)

The easiest way to test without a real device or elevated privileges. Connects to `/ws/inject` and streams packets directly into the live display.

```bash
pixi run inject                            # NC-Frame at 2 Hz (default)
pixi run inject --mode random --rate 10    # random payloads at 10 Hz
pixi run inject --mode replay --file capture.pcap --speed 2.0   # replay a pcap at 2x speed
```

**Setup:** create or select a capture profile with **Enable injection** checked. Leave the interface blank for injection-only mode, or fill in a real interface to capture from the network and accept injected packets simultaneously. Click **Start** before running the injector. Packets sent while capture is stopped are silently discarded — the injector prints a pause icon for each discarded packet and a checkmark once recording begins.

> Injected packets bypass the profile's capture pre-filter so they always appear regardless of the interface filter. The display filter still applies normally.

**Modes (`--mode`)**

| Mode | Description |
|------|-------------|
| `nc-frame` | NC-Frame binary packets — decoded fields appear in the detail panel (default) |
| `random` | Cycles through plaintext, JSON, and binary payload templates |
| `replay` | Re-injects a `.pcap` file at original inter-packet timing (requires scapy) |

Options: `--rate N` (packets/sec), `--count N` (stop after N), `--speed X` (replay multiplier), `--url ws://host:port/ws/inject`.

### UDP Mock Device (`udp_device.py`)

Sends real UDP traffic over the network stack — requires Npcap or Administrator to capture:

```bash
pixi run mock-device                      # random text/binary payloads (default)
pixi run mock-device --format nc-frame    # NC-Frame binary packets — decoded in the detail panel
```

The device runs in `feed` mode by default — it sends UDP datagrams to `127.0.0.1:9001`. With Npcap running in the `npcap` environment these are captured via the loopback interface.

**Payload formats (`--format`)**

| Format | Description |
|--------|-------------|
| `random` | Cycles through plaintext, JSON, and binary templates |
| `nc-frame` | NC-Frame binary protocol — decoded fields appear in the packet detail panel |

> Note: the `--format` flag only applies to `feed` mode. The `sender`, `chat`, and other modes always use the `random` format.

**Operating modes (`--mode`)**

| Mode | Description |
|------|-------------|
| `feed` | Sends to `127.0.0.1:9001` — captured via loopback (requires Npcap) |
| `chat` | Echo server + sender on the LAN interface |
| `sender` | Sends datagrams to `--ip:--port` |
| `receiver` | Listens on `--ip:--port` |
| `echo` | Listens on `--ip:--port` and echoes each datagram back |

> `chat`, `sender`, and `echo` modes use the real LAN interface and require Npcap or Administrator to capture.

### Fault Injector (`fault_injector.py`)

Injects packets with deliberate problems to test checksum warning indicators and decoder error handling. Useful for exercising the `has_warnings`, `has_error`, and `has_issues` display filters.

**Setup:** select a profile with **Enable injection** checked (interface can be blank or a real interface) and click **Start**.

```bash
pixi run inject-faults          # one cycle of all scenarios then loop
```

Each cycle sends seven scenario packets via `/ws/inject`:

| Scenario | Description |
|----------|-------------|
| `healthy-udp` | Valid UDP datagram — no warnings |
| `bad-ip-cksum` | Correct UDP payload, bad IP header checksum |
| `bad-udp-cksum` | Correct IP header, bad UDP checksum |
| `bad-tcp-cksum` | Valid TCP segment with bad TCP checksum |
| `decoder-err` | Valid checksums but malformed NC-Frame payload — decoder error |
| `both` | Bad IP checksum **and** malformed NC-Frame — both indicators |
| `healthy-tcp` | Valid TCP segment — no warnings |

---

## UI Overview

### Toolbar

The toolbar has two rows:

**Row 1 — capture controls**

`NetCapture` brand . interface/profile selector . BPF filter input + presets *(Npcap only)* . `Start`/`Stop` . `Clear` . capture mode badge . gear settings (far right)

**Row 2 — filter bar**

`Presets` dropdown . filter input with autocomplete . `Apply` . `Clear` — the active filter is persisted across sessions

### Settings Panel (gear icon)

Click the gear icon at the top-right to open the settings panel:

| Section | Setting | Description |
|---------|---------|-------------|
| **Recording** | Export | **PCAP** — Wireshark-compatible pcap file; **CSV**; **JSON** — full packet data |
| | Import | **PCAP** — load a pcap file; **CSV**; **JSON** — load a previous export |
| **Addresses** | Addresses | **Manage** — open the address book editor; **Export / Import** — save or load entries |
| **Filter Presets** | Filter Presets | **Manage** — open the preset editor; **Export / Import** — save or load presets |
| **Capture Profiles** | Capture Profiles | **Manage** — open the profile editor; **Export / Import** — save or load user-created profiles |
| **Capture** | Buffer size | Max packets kept in memory (ring buffer size) |
| | Ring buffer | On = drop oldest when full; Off = keep all until stopped |
| | Auto-stop after | Stop capture automatically after N packets (0 = unlimited) |
| **Display** | Timestamp | Relative (MM:SS.mmm from start) or Absolute (HH:MM:SS.mmm) |
| | Auto-scroll | Follow newest packets during live capture |
| | Track matching | **Strict** — exact 5-tuple + interpreter; **Loose** — protocol + IPs + dst port only (survives reconnects and source-port changes) |
| | Columns | Toggle visibility of individual packet table columns |
| **Watchlist** | Watchlist | **Export** — save current watch entries as JSON; **Import** — load entries from a JSON file |

All display and capture settings are persisted to `localStorage` and restored on next load.

### Packet Table

- **Resizable columns** — hover a column header to reveal a drag handle on its right edge; drag to resize.
- **Hideable columns** — toggle individual columns on/off from Settings > Display > Columns.
- **Auto-scroll** — when enabled, the table follows the newest packet during live capture. Scrolling up pauses auto-scroll; scrolling back to the bottom resumes it.
- **Packet health indicators** — rows with network-level issues are highlighted with a colored left border: amber for checksum warnings (bad IP/TCP/UDP checksum), red for decoder errors. A warning icon also appears in the Info cell with a tooltip showing the issue details.
- **Right-click context menu** on Source, Destination, or Protocol cells:
  - **Filter for / Exclude** — appends an `ip.src ==`, `ip.dst ==`, or `proto ==` condition to the filter
  - **Filter / Exclude by name** — appears when the address has a resolved name; uses `src_name`/`dst_name`
  - **Filter source/dest port** — appends a port condition
  - **Add IP to address book** — opens the address book editor pre-filled with the IP
  - **Add IP:Port to address book** — opens the address book editor pre-filled with `IP:port` (shown only when a port is present)

### Packet Detail Panel

Click any row to open the detail panel. It shows:

- **Header** — source to destination, protocol, timestamp, and (when tracking is active) a track status indicator showing the current mode: `Tracking [strict]` or `Tracking [loose]`.
- **Warnings banner** — displayed immediately below the header when the packet has network-level checksum warnings or a decoder error. Checksum warnings appear in amber; decoder errors appear in red.
- **Hex viewer** — raw bytes with layer-colored regions (IP header, transport header, payload).
- **Decoded fields** — three-column table (Field | Type | Value) with drag-resizable columns. Hover any decoded row to highlight the corresponding bytes in the hex viewer, and vice versa. Nested dicts and arrays are fully expanded. Hover the structural bytes (braces, commas) of a nested object to highlight its container without selecting individual values. Right-click any decoded field to add it to the Watchlist.
- **Track mode** — click **Track** in the header to lock the detail panel onto packets matching the same source, destination, protocol, and interpreter. Changed fields are highlighted in the next matching packet; only the specific changed sub-field is highlighted, even several levels deep in nested structures.
- **Resizable panels** — drag the vertical splitter between the protocol tree and the decoded/hex area to adjust widths; drag the horizontal bar at the top edge of the detail panel to adjust its height. All panel sizes persist across sessions.

### Watchlist

The Watchlist panel monitors specific decoded field values from one or more packet sources simultaneously. Open it with the **Watchlist** button in the toolbar (or press `W`).

- **Add a watch entry** — right-click any decoded field in the detail panel and select **Add to Watchlist**, or click **+ Add** in the watchlist header. Each entry has a label, a dot-path to the field (e.g. `meta.fw`, `sensors.0.readings.1`), and an optional packet matcher (protocol, source/destination IP and port, interpreter name — all fields optional; leave any blank to match any value).
- **Live updates** — as matching packets arrive, values update in real time. The entry is immediately seeded with the value from the packet it was added from. When a value changes, a pulse indicator appears next to it for ~3 seconds.
- **Current and previous values** — each row shows the current value and the previous value side by side. Click either to jump to the packet that supplied it; if track mode is active it is automatically stopped so the selected packet stays visible.
- **Edit and remove** — right-click any entry row for a context menu with **Edit** (reopens the editor pre-filled) and **Remove**. The trash icon on hover also removes the entry directly.
- **Grouping** — entries are grouped by the `group` label (defaults to the interpreter name). Leave the group field blank to fall back to the interpreter name automatically.
- **Export / Import** — save the current watch entries as JSON or load a previously saved file via **Settings > Watchlist**. Column widths and panel width are persisted across sessions.

### Follow Stream

Right-click a TCP or UDP packet and select **Follow Stream** to see all packets in the same conversation (matched by source/destination IP and port pair), displayed as a continuous payload stream with color-coded direction indicators.

### Address Book Editor

Maps IP addresses (and IP:port pairs) to human-readable names. Names appear in the Source and Destination columns, highlighted in blue.

- **Resizable dialog** — drag the bottom-right corner to resize the window
- **Resizable columns** — drag column header edges to adjust column widths
- Entries with a port (e.g. `192.168.1.1:9001`) take precedence over IP-only entries when matching
- Entries with blank address or name are automatically removed on save

### Filter Presets Editor

Manage saved filter expressions for quick reuse.

- **Resizable dialog** — drag the bottom-right corner to resize the window
- **Resizable columns** — drag the Title column edge to adjust widths
- **Unified list** — built-in presets and user presets are in one editable list
- **Restore defaults** — resets the list back to the original built-in presets

### Capture Profile Editor

Open via **Settings > Capture Profiles > Manage**. Create, edit, and delete named capture configurations that persist across sessions.

- **Built-in profiles** — shown with a lock icon; read-only
- **User profiles** — fully editable and deletable; stored server-side in `~/.netcapture/profiles.json`
- **Interface** — type any adapter name, or pick from the dropdown of known interfaces; leave blank when using injection-only mode; comma-separate multiple interfaces for simultaneous capture (npcap/scapy mode only, e.g. `eth0, eth1`)
- **Enable injection** — when checked, the profile accepts packets via `/ws/inject` alongside (or instead of) real capture; an `INJ` badge appears in the profile list; injected packets bypass the capture pre-filter
- **Capture Filter** — Python filter syntax (same as the display filter bar); applied as a backend pre-filter to captured packets (not to injected packets)
- **BPF Filter** — optional kernel-level BPF expression (npcap mode only); applied before packets reach the application

All dialogs stay open until explicitly closed with the close button — clicking outside does nothing.

---

## Embedding in a Larger Application

NetCapture is a Python package (backend) and a Svelte component library (frontend) that can be mounted into any existing app.

### Architecture overview

```
Your FastAPI app  (e.g. port 8080)
+-- app.include_router(create_router(), prefix="/netcapture")
        |-- /netcapture/api/...        REST endpoints
        |-- /netcapture/ws/capture     live packet stream (display WebSocket)
        +-- /netcapture/ws/inject      packet injection (shared port)

Optional — dedicated inject server  (e.g. port 9000)
+-- asyncio.create_task(start_inject_server(port=9000))
        +-- ws://host:9000/ws/inject   packet injection (own port)

Your Svelte / SvelteKit app
+-- <NetCapture wsUrl="wss://host/netcapture/ws/capture" apiBase="/netcapture" />
```

The component is **a single-instance tool** — only one `<NetCapture>` should be mounted at a time. Svelte stores are module-level singletons so two simultaneous instances would share all state. In a multi-page SPA you can navigate away and back freely; state (packet buffer, selected packet, settings) persists in memory for the session.

---

### Backend — Python / FastAPI

Install the package:
```bash
pip install ./backend            # basic (raw socket + WS inject modes)
pip install ./backend[npcap]     # with scapy for Npcap support
```

Or install from the conda package (see [Building a Conda Package](#building-a-conda-package)).

Mount the router in your FastAPI app, choosing any prefix:
```python
from fastapi import FastAPI
from netcapture import create_router

app = FastAPI()
app.include_router(create_router(), prefix="/netcapture")
```

All NetCapture routes will be available under `/netcapture/api/...`, the display WebSocket at `/netcapture/ws/capture`, and the injection WebSocket at `/netcapture/ws/inject`.

#### Live Packet Injection

Any external program can push packets into the live stream over a persistent WebSocket connection at `/ws/inject`. Every injected packet goes through the full pipeline — display-filter matching, protocol interpreter (NC-Frame, etc.), ID assignment, and live broadcast to all connected frontend clients.

Connect to `ws://localhost:8000/ws/inject` (adjust prefix if embedded) and send JSON:

```json
{
  "src_ip":    "192.168.1.50",
  "dst_ip":    "192.168.1.1",
  "src_port":  9001,
  "dst_port":  9001,
  "protocol":  "UDP",
  "length":    48,
  "info":      "192.168.1.50:9001 -> 192.168.1.1:9001",
  "raw_hex":   "4500...",
  "payload_hex": "4e430108..."
}
```

Or send an array for batch injection: `[{ ... }, { ... }]`

The server responds to each message with `{"ok": true, "injected": N}`, `{"ok": false, "discarded": N, "error": "capture not running"}` if capture hasn't been started, or `{"ok": false, "error": "..."}` for malformed input.

> **Capture must be running** — select a capture profile with **Enable injection** checked and click **Start** before sending packets. Packets received while stopped are discarded.

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `protocol` | yes | e.g. `"UDP"`, `"TCP"`, `"NC-Frame"` |
| `length` | yes | Wire length in bytes |
| `src_ip`, `dst_ip` | recommended | Source / destination address |
| `src_port`, `dst_port` | recommended | Port numbers |
| `info` | recommended | One-line summary shown in the packet table |
| `raw_hex` | recommended | Full packet as hex — enables the hex viewer and layer coloring |
| `payload_hex` | optional | Application-layer bytes as hex, passed to interpreters (e.g. NC-Frame decoder); max 64 KB |
| `abs_time`, `timestamp` | optional | Auto-generated from wall clock if omitted |

This enables use cases like piping output from `tshark`, forwarding packets from a remote capture host, replaying a pcap at original timing, or any process that needs to push traffic into the viewer without going through the network stack.

#### Direct In-Process Injection

If the code sending packets to NetCapture runs **in the same Python process**, skip the WebSocket entirely and call `inject_packet()` directly. The packet goes straight into the capture manager with no serialization, no network round-trip, and no open socket:

```python
import netcapture

# Returns True if accepted, False if capture is not currently running.
netcapture.inject_packet({
    "protocol":    "UDP",
    "length":      48,
    "src_ip":      "192.168.1.50",
    "dst_ip":      "192.168.1.1",
    "src_port":    9001,
    "dst_port":    9001,
    "info":        "sensor reading",
    "payload_hex": "4e430108...",
})
```

The dict accepts the same fields as the WebSocket endpoint (see the field table above). Missing fields are filled with defaults. The dict is modified in-place.

#### Injection on a Dedicated Port

By default the injection endpoint lives at `/ws/inject` on the same port as your main application. If you need injectors to connect to a fixed port that is independent of the host application, use `start_inject_server()` from your app's [lifespan](https://fastapi.tiangolo.com/advanced/events/):

```python
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
import netcapture

@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(
        netcapture.start_inject_server(host="0.0.0.0", port=9000)
    )
    yield
    task.cancel()

app = FastAPI(lifespan=lifespan)
app.include_router(netcapture.create_router(), prefix="/netcapture")
```

`start_inject_server` spins up a minimal WebSocket-only server (no REST endpoints) on the given port. Both endpoints accept the same packet JSON format and feed into the same live stream — you can use either or both simultaneously.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | `"0.0.0.0"` | Interface to bind (use `"127.0.0.1"` to restrict to localhost) |
| `port` | `8765` | TCP port to listen on |

> The dedicated server runs inside the same asyncio event loop as the host application. Signal handling is intentionally left to the outer process so `SIGTERM`/`SIGINT` shut everything down cleanly together.

> **Port conflicts / permission errors** — if the port is already in use or the process lacks permission (ports below 1024 typically require root), `start_inject_server` logs a warning and returns cleanly. The main application and the `/ws/inject` endpoint on the main router continue to work normally; only the dedicated port is unavailable.

#### Programmatic Capture Control

If your application runs in the same Python process as NetCapture, you can control the entire lifecycle without making HTTP calls:

```python
import asyncio
import netcapture

async def main():
    # Mount the router (if you're also serving the UI)
    # app.include_router(netcapture.create_router(), prefix="/netcapture")

    # Start capture in injection-only mode (no network capture needed)
    mode = await netcapture.start_capture()  # defaults to interface="injected"

    # Inject a single packet
    netcapture.inject_packet({
        "protocol":    "UDP",
        "length":      48,
        "src_ip":      "192.168.1.50",
        "dst_ip":      "192.168.1.1",
        "src_port":    9001,
        "dst_port":    9001,
        "info":        "sensor reading",
        "payload_hex": "4e430108...",
    })

    # High-throughput batch injection (one broadcast for all packets)
    count = netcapture.inject_batch([pkt1, pkt2, pkt3])

    # Check status
    status = netcapture.get_status()  # {"running": True, "mode": "inject", ...}

    # Stop and reset
    await netcapture.stop_capture()
    netcapture.reset_session()

asyncio.run(main())
```

`start_capture()` accepts the same parameters as the HTTP endpoint: `interface` (default `"injected"`), `filter`, and `bpf_filter`. Use `interface="any"` or a specific adapter name to capture real network traffic alongside injection.

#### Consuming Packets Programmatically

NetCapture can act as a capture engine that pipes packets to your application code. Three consumption patterns are available:

**Callback-based** — lightweight, fires synchronously on the event loop for every packet:

```python
@netcapture.on_packet
def handle(pkt):
    print(pkt["src_ip"], "→", pkt["dst_ip"], pkt.get("decoded"))

# Later:
netcapture.off_packet(handle)
```

**Async stream** — ideal for `async for` loops with backpressure control:

```python
async def process():
    stream = netcapture.packet_stream(queue_size=5000)
    try:
        async for pkt in stream:
            await forward_to_database(pkt)
            if should_stop:
                break
    finally:
        stream.close()
```

The queue is registered immediately on creation, so packets injected between `packet_stream()` and the first `await` are captured. Multiple independent streams can run simultaneously.

**Stats callback** — fires once per second with throughput counters:

```python
@netcapture.on_stats
def on_stats(stats):
    print(f"{stats['packets_per_sec']} pkt/s, {stats['bytes_per_sec']} B/s")
    print(f"Total: {stats['total_packets']} packets, {stats['total_bytes']} bytes")
    print(f"Protocols: {stats['protocol_counts']}")
```

**Buffer snapshot** — get all buffered packets at any point:

```python
packets = netcapture.get_buffer()  # list of up to 20,000 most recent packet dicts
```

**Advanced: direct manager access** — the `manager` singleton is exported for power users:

```python
q = netcapture.manager.subscribe()    # raw asyncio.Queue (JSON-serialized messages)
netcapture.manager.unsubscribe(q)
netcapture.manager.get_buffer()
netcapture.manager.is_running
```

> **Callback performance note:** Packet callbacks run synchronously on the asyncio event loop thread. Keep them lightweight — offload heavy work to a thread pool or queue. A callback that raises an exception is silently skipped; other callbacks and the capture pipeline are not affected. Do not mutate the packet dict passed to callbacks — it is shared with the buffer and WebSocket serialization.

#### Custom Profiles

Profiles populate the interface/profile selector dropdown and bundle an interface, capture filter, and optional BPF filter into a named preset. Users can also create, edit, and delete profiles at runtime via the profile editor in Settings.

**Profile fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique slug (e.g. `"my-device"`) |
| `name` | yes | Display name shown in the dropdown |
| `description` | no | Subtitle / tooltip hint |
| `interface` | no | Adapter name (`"Ethernet"`, `"Wi-Fi"`), `"any"`, `"loopback"`, or comma-separated for multiple interfaces (`"eth0, eth1"`) — multi-interface requires npcap/scapy mode; leave empty when `inject: true` for injection-only mode |
| `filter` | no | Python-style capture filter applied as a backend pre-filter on both npcap and raw-socket modes (e.g. `"port == 5000"`) |
| `bpf_filter` | no | Kernel-level BPF filter, npcap mode only (e.g. `"udp port 9001"`, `"tcp and port 443"`) |
| `inject` | no | `true` — also accept packets via `/ws/inject` alongside the real capture; set `interface` to `""` for injection-only mode (no real capture) |

Pass your own list to `create_router()` to replace the defaults:

```python
app.include_router(create_router(
    profiles=[
        {
            "id":          "my-device",
            "name":        "My Device",
            "description": "Traffic on port 5000",
            "interface":   "eth0",
            "filter":      "port == 5000",
        },
    ],
), prefix="/netcapture")
```

To extend the defaults rather than replace them:

```python
from netcapture import create_router, DEFAULT_PROFILES

app.include_router(create_router(
    profiles=DEFAULT_PROFILES + [my_profile],
), prefix="/netcapture")
```

**Profile persistence:**

User-created profiles (added via the UI) are saved to `~/.netcapture/profiles.json` by default. Change the path with the `profiles_path` parameter:

```python
app.include_router(create_router(
    profiles_path="/app/data/profiles.json",   # custom path
    # profiles_path=None,                      # in-memory only (no persistence)
), prefix="/netcapture")
```

Built-in profiles (passed via `profiles=`) are always present regardless of the persistence file and cannot be modified or deleted through the UI.

**Capture filter vs BPF filter:**

The `filter` field uses the same Python filter syntax as the display filter bar (e.g. `port == 9001`, `protocol == "UDP" and src_ip == "10.0.0.1"`). It is applied as a pre-filter in the capture thread on both npcap and raw-socket modes.

The `bpf_filter` field uses BPF syntax (e.g. `udp port 9001`) and is applied at the kernel level by Npcap, before packets reach the application. It is more efficient for high-volume captures but only works in npcap mode.

Both filters can be set on the same profile — BPF filters at the kernel level first, then the capture filter narrows further if needed.

#### Custom Interpreters (Protocol Decoders)

Interpreters decode the application-layer payload of captured packets into structured fields.
Implement the `Interpreter` protocol and pass instances to `create_router()`:

```python
from netcapture import create_router, Interpreter, DecodedFrame, DecodedField

class MyProtocol:
    name = "My Protocol"

    def match(self, pkt: dict, payload: bytes) -> bool:
        # Called for every packet — return True to claim it.
        #
        # pkt keys available in both match() and decode():
        #   src_ip          str           source IP address
        #   dst_ip          str           destination IP address
        #   src_port        int | None    source port (TCP/UDP only)
        #   dst_port        int | None    destination port (TCP/UDP only)
        #   protocol        str           e.g. "TCP", "UDP", "DNS", "TLS"
        #   length          int           total packet length in bytes
        #   ttl             int | None    IP time-to-live
        #   flags           str | None    TCP flags string, e.g. "SYN, ACK"
        #   info            str           one-line summary shown in the packet table
        #   raw_hex         str           full raw frame as a hex string
        #   _header_bytes   bytes         raw transport header bytes (TCP/UDP/ICMP
        #                                 header before the application payload).
        #                                 Useful for TCP sequence numbers, flags,
        #                                 UDP checksum, etc. Empty (b'') if N/A.
        #
        # payload is the isolated application-layer bytes — transport headers
        # (IP, TCP/UDP/ICMP) have already been stripped.
        return pkt.get("dst_port") == 5000 and len(payload) >= 2 and payload[0] == 0xAB

    def decode(self, pkt: dict, payload: bytes) -> DecodedFrame:
        # Parse the payload and return structured fields.
        # pkt provides the same context as match() — access _header_bytes,
        # src_port, TCP sequence numbers, etc. as needed.
        return DecodedFrame(self.name, fields=[
            DecodedField("type",   payload[0],                         "u8"),
            DecodedField("value",  int.from_bytes(payload[1:3], "big"), "u16"),
            DecodedField("label",  payload[3:].decode(),                "str"),
        ])

app.include_router(create_router(
    extra_interpreters=[MyProtocol()],
), prefix="/netcapture")
```

**Supported `DecodedField` types:**

| Type | Wire size | Description |
|------|-----------|-------------|
| `u8` / `u16` / `u32` / `u64` | 1-8 bytes | Unsigned integers |
| `i8` / `i16` / `i32` / `i64` | 1-8 bytes | Signed integers |
| `f32` / `f64` | 4-8 bytes | IEEE 754 floats |
| `str` | any | Short string (<= 255 bytes) |
| `strlong` | any | Long string (<= 65 535 bytes) |
| `bool` | 1 byte | Boolean |
| `hex` | any | Raw bytes displayed as hex string |
| `json` | any | Nested list or dict (arbitrary depth) |
| `list` / `dict` | — | Nested Python structures (via `json` tag) |

The type string is shown in the UI next to each field value and is useful for conveying value semantics (e.g. `i16` signals signed and bounded, `f32` signals floating-point).

**Registration order and priority:**

Built-in interpreters run first; `extra_interpreters` are appended in order. The first interpreter whose `match()` returns `True` wins. To run your interpreter *before* the built-ins (e.g. if your packets share the NC magic bytes), use `prepend=True`:

```python
from netcapture import register_interpreter
register_interpreter(MyProtocol(), prepend=True)
```

You can also register as part of `create_router()` (appended, not prepended):

```python
app.include_router(create_router(
    extra_interpreters=[MyProtocol()],
), prefix="/netcapture")
```

**Error handling:**

If `match()` raises an exception, that interpreter is silently skipped and the next one is tried. If `decode()` raises, a `DecodedFrame` with the error message is returned and the error is shown in red in the decoded panel — partial results decoded before the exception are preserved.

#### Address Book

Map IP addresses (and IP:port pairs) to human-readable names. Names are shown in the Source and Destination columns of the packet table, highlighted in blue. The address book can be pre-populated at startup and edited live by the user via **Settings > Manage Addresses**.

Pass initial entries to `create_router()`:

```python
app.include_router(create_router(
    address_book=[
        {"id": "1", "address": "192.168.1.100",      "name": "My Sensor"},
        {"id": "2", "address": "192.168.1.100:9001",  "name": "Sensor Feed", "notes": "UDP port 9001"},
        {"id": "3", "address": "127.0.0.1",           "name": "Localhost"},
    ],
), prefix="/netcapture")
```

Each entry requires `id`, `address`, and `name`. `notes` is optional. The `address` field accepts:
- `"192.168.1.1"` — matches all traffic to/from that IP
- `"192.168.1.1:9001"` — matches only that IP+port combination (checked first)

**Filtering with names:**

Once an address is named, you can filter by name in the filter bar:

```
src_name == "My Sensor"         # source resolves to this name
dst_name == "Sensor Feed"       # destination resolves to this name
addr_name == "My Sensor"        # either direction
ip.src == "My Sensor"           # ip.src also accepts resolved names
```

**Testing with the UDP mock device:**

Add `127.0.0.1` to the address book to name mock device traffic (the loopback capture sees it as `127.0.0.1`):

```python
address_book=[{"id": "1", "address": "127.0.0.1", "name": "UDP Mock Device"}]
```

Then run `pixi run mock-device --format nc-frame` and start capturing on the loopback interface — the Source column will show **UDP Mock Device** instead of the raw IP.

#### Programmatic Capture Control

If your application runs in the same Python process as NetCapture, you can control the entire lifecycle without making HTTP calls:

```python
import asyncio
import netcapture

async def main():
    # Mount the router (if you're also serving the UI)
    # app.include_router(netcapture.create_router(), prefix="/netcapture")

    # Start capture in injection-only mode (no network capture needed)
    mode = await netcapture.start_capture()  # defaults to interface="injected"

    # Inject a single packet
    netcapture.inject_packet({
        "protocol":    "UDP",
        "length":      48,
        "src_ip":      "192.168.1.50",
        "dst_ip":      "192.168.1.1",
        "src_port":    9001,
        "dst_port":    9001,
        "info":        "sensor reading",
        "payload_hex": "4e430108...",
    })

    # High-throughput batch injection (one broadcast for all packets)
    count = netcapture.inject_batch([pkt1, pkt2, pkt3])

    # Check status
    status = netcapture.get_status()  # {"running": True, "mode": "inject", ...}

    # Stop and reset
    await netcapture.stop_capture()
    netcapture.reset_session()

asyncio.run(main())
```

`start_capture()` accepts the same parameters as the HTTP endpoint: `interface` (default `"injected"`), `filter`, and `bpf_filter`. Use `interface="any"` or a specific adapter name to capture real network traffic alongside injection.

The `manager` singleton is also exported for advanced use (e.g. `netcapture.manager.get_buffer()`, `netcapture.manager.subscribe()`).

#### Exported symbols

| Symbol | What it is |
|--------|-----------|
| **Router** | |
| `create_router(profiles, extra_interpreters, address_book, watchlists, profiles_path, watchlists_path)` | FastAPI router factory |
| **Capture lifecycle** | |
| `start_capture(interface, filter, bpf_filter)` | Async — start the capture engine programmatically |
| `stop_capture()` | Async — stop the capture engine |
| `get_status()` | Return capture status dict (`running`, `mode`, `iface`, `packets`) |
| `reset_session()` | Reset the session timer and clear the packet buffer |
| **Injection** | |
| `inject_packet(pkt)` | Inject one packet — zero overhead, no WebSocket required |
| `inject_batch(packets)` | Inject multiple packets — single broadcast for all |
| `start_inject_server(host, port)` | Async — runs a standalone WS inject server on a dedicated port |
| **Packet consumption** | |
| `on_packet(callback)` | Register a per-packet callback (sync, on event loop); works as `@decorator` |
| `off_packet(callback)` | Unregister a packet callback |
| `on_stats(callback)` | Register a per-second stats callback; works as `@decorator` |
| `off_stats(callback)` | Unregister a stats callback |
| `packet_stream(queue_size=1000)` | Create an async iterator of packet dicts (`PacketStream`) |
| `get_buffer()` | Snapshot of the rolling packet buffer (list of dicts) |
| **Interpreters** | |
| `register_interpreter(interp, prepend=False)` | Add an interpreter to the global registry |
| `Interpreter` | `Protocol` class — use for type hints when building interpreters |
| `DecodedFrame` | Return type of `decode()` — holds interpreter name + field list |
| `DecodedField` | A single decoded field: `key`, `value`, `type` |
| **Defaults & advanced** | |
| `DEFAULT_PROFILES` | The built-in profile list — extend rather than replace |
| `DEFAULT_WATCHLISTS` | The built-in watchlist list — extend rather than replace |
| `manager` | The `CaptureManager` singleton — subscribe, buffer, etc. |
| `CaptureManager` | The capture engine class |
| `PacketStream` | Type returned by `packet_stream()` — for type annotations |

### Frontend — Svelte Component

> **Peer requirements:** Svelte **^5**, Vite **^6**, and `@sveltejs/vite-plugin-svelte` **^6** (or SvelteKit **^2**). The component uses Svelte 5 runes and the `mount()` API — it will not work with Svelte 4.

#### 1. Install

**Option A — local path install (recommended for monorepos):**
```bash
cd frontend
npm install              # install frontend deps first
npm run package          # build the library -> frontend/dist/
```

Then in your app:
```bash
npm install /path/to/netcapture/frontend
```

**Option B — source import (SvelteKit / Vite apps in the same repo):**

Skip `npm run package`. Point your app's `package.json` directly at the source:
```json
{
  "dependencies": {
    "netcapture": "file:../netcapture/frontend"
  }
}
```
Svelte-aware bundlers resolve the `"svelte"` export condition and use the raw `.svelte` sources, so your build pipeline processes them directly.

---

#### 2. CSS and theming

Import the NetCapture stylesheet **once** in your app's global CSS or root layout. It provides all `--nc-*` CSS custom properties and the protocol row-tint classes:

```js
// In your app's entry point (e.g. main.ts / +layout.svelte)
import 'netcapture/netcapture.css'
```

> **Tailwind 4 users:** add a `@source` directive to your CSS so Tailwind scans NetCapture's component files and generates the utility classes they use:
> ```css
> /* your app's global CSS (e.g. app.css) */
> @import "tailwindcss";
>
> /* npm install path: */
> @source "../node_modules/netcapture/src/lib";
> /* local file: install — adjust to point at the frontend/src/lib directory: */
> @source "../../netcapture/frontend/src/lib";
> ```
> Point `@source` at the `src/lib` subdirectory specifically, not the whole `src/` or `frontend/` tree.

> **Tailwind 3 users:** add NetCapture's source to the `content` array in `tailwind.config.js`:
> ```js
> // tailwind.config.js
> module.exports = {
>   content: [
>     // ... your existing paths ...
>     './node_modules/netcapture/src/lib/**/*.{svelte,ts}',
>     // local file: install:
>     // '../../netcapture/frontend/src/lib/**/*.{svelte,ts}',
>   ],
> }
> ```

**Dark theme:**

The component reads the `[data-theme="dark"]` attribute. Pass the `theme` prop to scope it to the component wrapper (avoids touching the parent page):

```svelte
<NetCapture theme="dark" wsUrl="..." apiBase="..." />
```

Or apply it to an ancestor element in your own layout:

```html
<div data-theme="dark">
  <NetCapture wsUrl="..." apiBase="..." />
</div>
```

---

#### 3. Container height

The component fills `100%` of its parent's height (`h-full`). You must give the wrapping element an explicit height — otherwise it collapses to zero:

```svelte
<!-- Fixed height -->
<div style="height: 700px;">
  <NetCapture wsUrl="..." apiBase="..." />
</div>

<!-- Fill remaining viewport below a navbar -->
<div style="height: calc(100vh - 64px);">
  <NetCapture wsUrl="..." apiBase="..." />
</div>

<!-- SvelteKit full-page layout -->
<main class="h-screen">
  <NetCapture wsUrl="..." apiBase="..." />
</main>
```

---

#### 4. Usage

```svelte
<script lang="ts">
  import { NetCapture } from 'netcapture'
  import 'netcapture/netcapture.css'
</script>

<!-- Fill the remaining page height below a 64 px header -->
<div style="height: calc(100vh - 64px);">
  <NetCapture
    wsUrl="wss://yourhost/netcapture/ws/capture"
    apiBase="/netcapture"
  />
</div>
```

**SvelteKit example (`src/routes/capture/+page.svelte`):**

```svelte
<script lang="ts">
  import { NetCapture } from 'netcapture'
</script>

<svelte:head><title>NetCapture</title></svelte:head>

<div class="h-[calc(100vh-4rem)]">
  <NetCapture
    wsUrl="wss://yourhost/netcapture/ws/capture"
    apiBase="/netcapture"
    theme="dark"
  />
</div>
```

Import the CSS in your root layout instead of every page:

```svelte
<!-- src/routes/+layout.svelte -->
<script>
  import 'netcapture/netcapture.css'
  import type { Snippet } from 'svelte'
  let { children }: { children: Snippet } = $props()
</script>

{@render children()}
```

---

#### Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `wsUrl` | `string` | `''` | Full WebSocket URL. Empty = auto-detect from `window.location`. |
| `apiBase` | `string` | `''` | Prefix for all REST fetch calls. Empty = same origin `/api/...`. |
| `theme` | `'light' \| 'dark' \| ''` | `''` | Color theme. `''` inherits from an ancestor `[data-theme]` attribute. |

When `wsUrl` and `apiBase` are both empty (standalone mode) the component connects to the same host it was served from.

---

#### TypeScript types

Useful types are exported from the library entry point:

```ts
import type { Packet, NetworkInterface, CaptureProfile, DecodedFrame, Stats } from 'netcapture'
```

| Type | Description |
|------|-------------|
| `Packet` | A captured or injected packet |
| `NetworkInterface` | `{ name, description? }` — interface dropdown entry |
| `CaptureProfile` | Named capture preset passed to `create_router()` |
| `AddressBookEntry` | `{ id, address, name, notes? }` |
| `DecodedFrame` | Interpreter output: `{ interpreterName, fields, error? }` |
| `DecodedField` | A single decoded field: `{ key, value, type }` |
| `DecodedValue` | Primitive or nested decoded value (string, number, boolean, object, array) |
| `Stats` | Aggregate capture stats from the backend |
| `ChartPoint` | `{ time, packets, bytes }` — traffic chart data point |
| `CaptureMode` | `'idle' \| 'scapy' \| 'real' \| 'listen' \| 'error'` |
| `ConnectionStatus` | `'disconnected' \| 'connecting' \| 'connected' \| 'error'` |

---

#### WebSocket lifecycle

The WebSocket connection is managed at module scope by `captureService.ts`, not inside the component. This means:

- The connection is established when the component first mounts and **persists when you navigate away** in an SPA.
- If the component remounts (e.g. you navigate back), it reuses the existing connection without reconnecting.
- Auto-reconnect with a 1-second retry handles server restarts — no manual reconnection logic needed.

---

## Project Layout

```
NetCapture/
+-- backend/
|   +-- netcapture/          # Python package
|   |   +-- __init__.py      # public exports: create_router, register_interpreter, etc.
|   |   +-- __main__.py      # python -m netcapture entry point
|   |   +-- _router.py       # FastAPI APIRouter factory (accepts profiles + interpreters)
|   |   +-- _manager.py      # CaptureManager, capture loop, session state
|   |   +-- _filter.py       # Wireshark-style filter parser + evaluator
|   |   +-- capture.py       # Raw socket capture + IP/TCP/UDP/ICMP parsing
|   |   +-- capture_scapy.py # Scapy/Npcap capture (loopback support)
|   |   +-- pcap_io.py       # PCAP file read/write (no scapy required)
|   |   +-- profiles.py      # DEFAULT_PROFILES + ProfileStore (CRUD + file persistence)
|   |   +-- interpreters/    # Packet payload decoders
|   |   |   +-- __init__.py  # registry: register(), find_interpreter(), Interpreter protocol
|   |   |   +-- nc_frame.py  # built-in NC-Frame binary decoder
|   |   +-- static/          # Built frontend (git-ignored, populated by build-ui)
|   +-- server.py            # Standalone FastAPI entry point
|   +-- setup.py             # Cython compilation (used by build-pkg-compiled)
|   +-- strip_sources.py     # Post-build cleanup — removes .py/.c/.pyc for compiled modules
|   +-- pyproject.toml       # Package metadata and dependencies
+-- frontend/
|   +-- src/
|   |   +-- lib/             # Exportable component library
|   |   |   +-- index.ts              # Library entry point — exports NetCapture + types
|   |   |   +-- NetCapture.svelte     # Main public component (wsUrl, apiBase, theme props)
|   |   |   +-- captureService.ts     # WebSocket + REST service layer
|   |   |   +-- stores.ts             # Svelte writable/derived stores (settings, visibility, etc.)
|   |   |   +-- filter.ts             # Wireshark-style filter parser + evaluator
|   |   |   +-- types.ts              # TypeScript type definitions
|   |   |   +-- components/           # Internal UI components
|   |   |       +-- Toolbar.svelte         # Capture controls + filter bar + settings panel
|   |   |       +-- PacketTable.svelte     # Packet list with resizable/hideable columns
|   |   |       +-- PacketDetail.svelte    # Hex viewer + decoded field inspector
|   |   |       +-- FollowStream.svelte    # TCP/UDP stream reassembly view
|   |   |       +-- ContextMenu.svelte     # Right-click context menu
|   |   |       +-- AddressBookEditor.svelte  # Address book manager dialog
|   |   |       +-- PresetEditor.svelte       # Filter preset manager dialog
|   |   |       +-- ProfileEditor.svelte      # Capture profile manager dialog
|   |   |       +-- StatsBar.svelte           # Status bar with counters and protocol breakdown
|   |   |       +-- Charts.svelte             # Traffic history chart (lazy-loaded)
|   |   |       +-- FieldValue.svelte         # Decoded field value renderer
|   |   +-- app.css          # Global styles + CSS custom properties (theme vars)
|   |   +-- main.ts          # Standalone app entry point
|   +-- package.json
+-- tools/
|   +-- udp_device.py        # Mock UDP device — real UDP traffic via loopback or LAN
|   +-- ws_injector.py       # WebSocket injector — pushes packets via /ws/inject
|   +-- fault_injector.py    # Test tool — injects packets with bad checksums and decoder errors
+-- tests/                   # Pytest unit tests
+-- pixi.toml                # Task runner and environment definitions
+-- recipe.yaml              # Conda recipe — pure-Python build
+-- recipe-compiled.yaml     # Conda recipe — Cython-compiled build
```

---

## Filter Syntax

The filter bar accepts Wireshark-style expressions with autocomplete. Start typing to see suggestions for fields, operators, protocol shorthands, and previously used filters.

```
src_ip == 192.168.1.1
protocol == TCP
info contains "hello"
interpreter == NC-Frame
decoded.type == status
decoded.meta.fw == 1.2.3
protocol == TCP and dst_port == 443
src_ip == 10.0.0.1 or src_ip == 10.0.0.2
not protocol == ICMP
has_issues
has_warnings && tcp
warnings contains "checksum"
```

**Fields** (with operator):

| Field | Aliases | Description |
|-------|---------|-------------|
| `ip.src` | | Source IP (exact or address-book name) |
| `ip.dst` | | Destination IP (exact or address-book name) |
| `ip.addr` | | Source **or** destination IP |
| `src_name` | | Source address-book name only |
| `dst_name` | | Destination address-book name only |
| `addr_name` | | Either direction address-book name |
| `port` | `tcp.port`, `udp.port` | Source or destination port (exact int) |
| `src.port` | `tcp.srcport`, `udp.srcport` | Source port |
| `dst.port` | `tcp.dstport`, `udp.dstport` | Destination port |
| `proto` | `ip.proto`, `protocol` | Protocol name (case-insensitive) |
| `info` | `frame.info` | Info string (case-insensitive substring for `==`) |
| `interpreter` | | Interpreter name (e.g. `NC-Frame`) |
| `warnings` | | Network-level warning list (e.g. `"Bad IP checksum"`) |
| `decoded.<field>` | | Interpreter field by key |
| `decoded.<field>.<nested>` | | Nested interpreter field (arbitrary depth) |
| `decoded.error` | | Decoder error string |

`ip.src` and `ip.dst` also match against resolved address-book names, so `ip.src == "MyDevice"` works even though it's an IP field. `src_name`/`dst_name`/`addr_name` match exclusively on resolved names.

**Bare-word flags** (no operator — evaluate to true/false):

| Flag | Matches when |
|------|-------------|
| `has_warnings` | Packet has one or more network-level warnings (e.g. bad checksum) |
| `has_error` | Packet has a decoder error |
| `has_issues` | Packet has warnings **or** a decoder error |
| `tcp`, `udp`, `icmp`, `arp`, ... | Protocol shorthand — same as `proto == tcp` |

**Operators:** `==`, `!=`, `contains`

**Combiners:** `and` / `&&`, `or` / `||`, `not` / `!`

**Parentheses** for grouping: `(proto == TCP or proto == UDP) and port == 443`

> The filter bar uses the same syntax in two contexts: the **display filter** (row 2, client-side, applies to all packets including injected) and the **capture filter** (in profile settings, server-side pre-filter, does not apply to injected packets). Some fields like `src_name`, `dst_name`, `warnings`, and the bare-word flags are only available in the display filter — the backend pre-filter operates on raw packet fields only.
