# NetCapture

Real-time network packet capture and display. Runs standalone or embeds into a larger Svelte + FastAPI application.

---

## Requirements

- [Pixi](https://prefix.dev/docs/pixi/overview) — manages Python and Node environments
- [Node.js](https://nodejs.org) ≥ 20 (provided by Pixi)
- Python ≥ 3.11 (provided by Pixi)
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

## Capture Modes

NetCapture selects a capture mode automatically, in order of preference:

| Mode | Requires | What it captures |
|------|----------|-----------------|
| `scapy` | Npcap + scapy installed, `--environment npcap` | All traffic on any interface including loopback (L2) |
| `real` | Run as Administrator | All IP traffic on one non-loopback interface |
| `inject` | Nothing | Packets pushed in via `/ws/inject` — select **WS Inject** interface in the UI |

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
pixi run inject --mode replay --file capture.pcap --speed 2.0   # replay a pcap at 2× speed
```

**Setup:** select **WS Inject (/ws/inject)** from the interface dropdown and click **Start** before running the injector. Packets sent while capture is stopped are silently discarded — the injector prints `⏸` for each discarded packet and `✓` once recording begins.

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

**Operating modes (`--mode`)**

| Mode | Description |
|------|-------------|
| `feed` | Sends to `127.0.0.1:9001` — captured via loopback (requires Npcap) |
| `chat` | Echo server + sender on the LAN interface |
| `sender` | Sends datagrams to `--ip:--port` |
| `receiver` | Listens on `--ip:--port` |
| `echo` | Listens on `--ip:--port` and echoes each datagram back |

> `chat`, `sender`, and `echo` modes use the real LAN interface and require Npcap or Administrator to capture.

---

## UI Overview

### Toolbar

The toolbar has two rows:

**Row 1 — capture controls**

`NetCapture` brand · interface/profile selector · `Start`/`Stop` · `Clear` · capture mode badge · ⚙ settings (far right)

**Row 2 — filter bar**

`Presets` dropdown · filter input · `Apply` · `Clear` · BPF filter input + presets button *(Npcap mode only)*

### Settings Panel (⚙ gear icon)

Click the gear icon at the top-right to open the settings panel:

| Section | Setting | Description |
|---------|---------|-------------|
| **Recording** | Export ▸ | **PCAP** — Wireshark-compatible pcap file; **JSON** — full packet data |
| | Import ▸ | **PCAP** — load a pcap file; **JSON** — load a previous JSON export; **CSV** — Wireshark CSV export |
| **Addresses** | Manage Addresses | Open the address book editor |
| | Export / Import Address Book | Save or load address book entries |
| **Filter Presets** | Manage Presets | Open the preset editor |
| | Export / Import Presets | Save or load filter presets |
| **Capture** | Buffer size | Max packets kept in memory (ring buffer size) |
| | Ring buffer | On = drop oldest when full; Off = keep all until stopped |
| | Auto-stop after | Stop capture automatically after N packets (0 = unlimited) |
| **Display** | Timestamp | Relative (MM:SS.mmm from start) or Absolute (HH:MM:SS.mmm) |
| | Auto-scroll | Follow newest packets during live capture |
| | Columns | Toggle visibility of individual packet table columns |

All display and capture settings are persisted to `localStorage` and restored on next load.

### Packet Table

- **Resizable columns** — hover a column header to reveal a drag handle on its right edge; drag to resize.
- **Hideable columns** — toggle individual columns on/off from Settings → Display → Columns.
- **Auto-scroll** — when enabled, the table follows the newest packet during live capture. Scrolling up pauses auto-scroll; scrolling back to the bottom resumes it.
- **Right-click context menu** on Source, Destination, or Protocol cells:
  - **Filter for / Exclude** — appends an `ip.src ==`, `ip.dst ==`, or `proto ==` condition to the filter
  - **Filter / Exclude by name** — appears when the address has a resolved name; uses `src_name`/`dst_name`
  - **Filter source/dest port** — appends a port condition
  - **Add IP to address book** — opens the address book editor pre-filled with the IP
  - **Add IP:Port to address book** — opens the address book editor pre-filled with `IP:port` (shown only when a port is present)

### Address Book Editor

Maps IP addresses (and IP:port pairs) to human-readable names. Names appear in the Source and Destination columns, highlighted in blue.

- **Resizable dialog** — drag the bottom-right corner to resize the window
- **Resizable columns** — drag column header edges to adjust column widths
- Entries with a port (e.g. `192.168.1.1:9001`) take precedence over IP-only entries when matching

### Filter Presets Editor

Manage saved filter expressions for quick reuse.

- **Resizable dialog** — drag the bottom-right corner to resize the window
- **Resizable columns** — drag the Title column edge to adjust widths
- **Unified list** — built-in presets and user presets are in one editable list
- **Restore defaults** — resets the list back to the original built-in presets

Both editors stay open until the user explicitly closes them with the **✕** button or **Cancel** — clicking outside the dialog does nothing.

---

## Embedding in a Larger Application

NetCapture is a Python package (backend) and a Svelte component library (frontend) that can be mounted into any existing app.

### Architecture overview

```
Your FastAPI app
└── app.include_router(create_router(), prefix="/netcapture")
        ├── /netcapture/api/...        REST endpoints
        ├── /netcapture/ws/capture     live packet stream (display WebSocket)
        └── /netcapture/ws/inject      packet injection (external programs)

Your Svelte / SvelteKit app
└── <NetCapture wsUrl="wss://host/netcapture/ws/capture" apiBase="/netcapture" />
```

The component is **a single-instance tool** — only one `<NetCapture>` should be mounted at a time. Svelte stores are module-level singletons so two simultaneous instances would share all state. In a multi-page SPA you can navigate away and back freely; state (packet buffer, selected packet, settings) persists in memory for the session.

---

### Backend — Python / FastAPI

Install the package:
```bash
pip install ./backend            # basic (raw socket + WS inject modes)
pip install ./backend[npcap]     # with scapy for Npcap support
```

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
// Single packet
{
  "src_ip":    "192.168.1.50",
  "dst_ip":    "192.168.1.1",
  "src_port":  9001,
  "dst_port":  9001,
  "protocol":  "UDP",
  "length":    48,
  "info":      "192.168.1.50:9001 → 192.168.1.1:9001",
  "raw_hex":   "4500...",
  "payload_hex": "4e430108..."
}

// Or a batch array for efficiency
[{ ... }, { ... }]
```

The server responds to each message with `{"ok": true, "injected": N}`, `{"ok": false, "discarded": N, "error": "capture not running"}` if capture hasn't been started, or `{"ok": false, "error": "..."}` for malformed input.

> **Capture must be running** — select **WS Inject (/ws/inject)** from the interface dropdown and click **Start** before sending packets. Packets received while stopped are discarded without error.

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `protocol` | yes | e.g. `"UDP"`, `"TCP"`, `"NC-Frame"` |
| `length` | yes | Wire length in bytes |
| `src_ip`, `dst_ip` | recommended | Source / destination address |
| `src_port`, `dst_port` | recommended | Port numbers |
| `info` | recommended | One-line summary shown in the packet table |
| `raw_hex` | recommended | Full packet as hex — enables the hex viewer and layer coloring |
| `payload_hex` | optional | Application-layer bytes as hex, passed to interpreters (e.g. NC-Frame decoder) |
| `abs_time`, `timestamp` | optional | Auto-generated from wall clock if omitted |

This enables use cases like piping output from `tshark`, forwarding packets from a remote capture host, replaying a pcap at original timing, or any process that needs to push traffic into the viewer without going through the network stack.

#### Custom Profiles

Profiles populate the interface/preset dropdown in the UI. Pass your own list to replace the defaults:

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

Each profile requires `id`, `name`, `interface`, and `filter`. `description` and `bpf_filter` are optional. `bpf_filter` is a kernel-level BPF expression applied at capture time (Npcap mode only — e.g. `"udp port 9001"`, `"tcp and port 443"`).

The `interface` field accepts the system adapter name (e.g. `"Ethernet"`, `"Wi-Fi"`), `"any"` for the default outbound interface, or `"loopback"` for the Npcap loopback adapter (127.0.0.1 inter-process traffic, requires Npcap).

To extend the defaults rather than replace them:

```python
from netcapture import create_router, DEFAULT_PROFILES

app.include_router(create_router(
    profiles=DEFAULT_PROFILES + [my_profile],
), prefix="/netcapture")
```

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
| `u8` / `u16` / `u32` / `u64` | 1–8 bytes | Unsigned integers |
| `i8` / `i16` / `i32` / `i64` | 1–8 bytes | Signed integers |
| `f32` / `f64` | 4–8 bytes | IEEE 754 floats |
| `str` | any | Short string (≤ 255 bytes) |
| `strlong` | any | Long string (≤ 65 535 bytes) |
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

Map IP addresses (and IP:port pairs) to human-readable names. Names are shown in the Source and Destination columns of the packet table, highlighted in blue. The address book can be pre-populated at startup and edited live by the user via **Settings → Manage Addresses**.

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

#### Exported symbols

| Symbol | What it is |
|--------|-----------|
| `create_router(profiles, extra_interpreters, address_book)` | FastAPI router factory |
| `register_interpreter(interp)` | Add an interpreter to the global registry |
| `Interpreter` | `Protocol` class — use for type hints when building interpreters |
| `DecodedFrame` | Return type of `decode()` — holds interpreter name + field list |
| `DecodedField` | A single decoded field: `key`, `value`, `type` |
| `DEFAULT_PROFILES` | The built-in profile list — extend rather than replace |
| `CaptureManager` | The capture engine — advanced use only |

### Frontend — Svelte Component

> **Peer requirements:** Svelte **^5**, Vite **^6**, and `@sveltejs/vite-plugin-svelte` **^6** (or SvelteKit **^2**). The component uses Svelte 5 runes and the `mount()` API — it will not work with Svelte 4.

#### 1. Install

**Option A — local path install (recommended for monorepos):**
```bash
cd frontend
npm install              # install frontend deps first
npm run package          # build the library → frontend/dist/
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
> @source "../node_modules/netcapture/src";
> ```
> If you installed via local path, adjust the path to point at the `frontend/src/` directory.

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
| `Stats` | Aggregate capture stats from the backend |
| `CaptureMode` | `'idle' \| 'scapy' \| 'real' \| 'inject' \| 'error'` |
| `ConnectionStatus` | `'disconnected' \| 'connecting' \| 'connected' \| 'error'` |

---

#### WebSocket lifecycle

The WebSocket connection is managed at module scope by `captureService.ts`, not inside the component. This means:

- The connection is established when the component first mounts and **persists when you navigate away** in an SPA.
- If the component remounts (e.g. you navigate back), it reuses the existing connection without reconnecting.
- Auto-reconnect with exponential back-off handles server restarts — no manual reconnection logic needed.

---

## Project Layout

```
NetCapture/
├── backend/
│   ├── netcapture/          # Python package
│   │   ├── __init__.py      # public exports: create_router, register_interpreter, etc.
│   │   ├── __main__.py      # python -m netcapture entry point
│   │   ├── _router.py       # FastAPI APIRouter factory (accepts profiles + interpreters)
│   │   ├── _manager.py      # CaptureManager, capture loop, session state
│   │   ├── _filter.py       # Wireshark-style filter parser + evaluator
│   │   ├── capture.py       # Raw socket capture
│   │   ├── capture_scapy.py # Scapy/Npcap capture (loopback support)
│   │   ├── pcap_io.py       # PCAP file read/write (no scapy required)
│   │   ├── profiles.py      # DEFAULT_PROFILES list
│   │   ├── interpreters/    # Packet payload decoders
│   │   │   ├── __init__.py  # registry: register(), find_interpreter(), Interpreter protocol
│   │   │   └── nc_frame.py  # built-in NC-Frame binary decoder
│   │   └── static/          # Built frontend (git-ignored, populated by build-ui)
│   ├── server.py            # Standalone FastAPI entry point
│   └── pyproject.toml       # Package metadata and dependencies
├── frontend/
│   ├── src/
│   │   ├── lib/             # Exportable component library
│   │   │   ├── index.ts              # Library entry point — exports NetCapture
│   │   │   ├── NetCapture.svelte     # Main public component (wsUrl, apiBase props)
│   │   │   ├── captureService.ts     # WebSocket + REST service layer
│   │   │   ├── stores.ts             # Svelte writable/derived stores (settings, visibility, etc.)
│   │   │   ├── filter.ts             # Wireshark-style filter parser + evaluator
│   │   │   ├── types.ts              # TypeScript type definitions
│   │   │   └── components/           # Internal UI components
│   │   │       ├── Toolbar.svelte         # Capture controls + settings panel
│   │   │       ├── PacketTable.svelte     # Packet list with resizable/hideable columns
│   │   │       ├── PacketDetail.svelte    # Hex + decoded field inspector
│   │   │       ├── AddressBookEditor.svelte  # Resizable address book manager dialog
│   │   │       ├── PresetEditor.svelte       # Resizable filter preset manager dialog
│   │   │       ├── StatsBar.svelte
│   │   │       ├── Charts.svelte
│   │   │       └── FieldValue.svelte
│   │   ├── app.css          # Global styles + CSS custom properties (theme vars)
│   │   └── main.ts          # Standalone app entry point
│   └── package.json
├── tools/
│   ├── udp_device.py        # Mock UDP device — real UDP traffic via loopback or LAN
│   └── ws_injector.py       # WebSocket injector — pushes packets via /ws/inject (no admin needed)
├── tests/                   # Pytest unit tests
└── pixi.toml                # Task runner and environment definitions
```

---

## Filter Syntax

The filter bar accepts Wireshark-style expressions:

```
src_ip == 192.168.1.1
protocol == TCP
dst_port >= 443
length > 100
info contains "hello"
interpreter == nc_frame
decoded.type == status
decoded.meta.fw == 1.2.3
protocol == TCP and dst_port == 443
src_ip == 10.0.0.1 or src_ip == 10.0.0.2
not protocol == ICMP
```

Fields: `src_ip`/`ip.src`, `dst_ip`/`ip.dst`, `ip.addr`, `src_name`, `dst_name`, `addr_name`, `src_port`/`src.port`, `dst_port`/`dst.port`, `port`, `protocol`/`proto`, `info`, `interpreter`, `decoded.<field>`, `decoded.<field>.<nested>`

`ip.src` and `ip.dst` also match against resolved address book names, so `ip.src == "MyDevice"` works even though it's an IP field. `src_name`/`dst_name`/`addr_name` match exclusively on resolved names.

Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `contains`

Combiners: `and`, `or`, `not`
