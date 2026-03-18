# NetCapture

Real-time network packet capture and display. Runs standalone or embeds into a larger Svelte + FastAPI application.

---

## Requirements

- [Pixi](https://prefix.dev/docs/pixi/overview) — manages Python and Node environments
- [Node.js](https://nodejs.org) ≥ 20 (provided by Pixi)
- Python ≥ 3.11 (provided by Pixi)
- **Windows only** for raw capture modes; the UDP listen mode runs anywhere

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
| `scapy` | Npcap + scapy installed, `--environment npcap` | All traffic on any interface (L2) |
| `real` | Run as Administrator | All IP traffic on one interface |
| `listen` | Nothing | Only UDP packets sent to port 9001 |

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
NETCAPTURE_MODE=listen  pixi run dev-api                        # UDP sink only, no admin needed
```

If the forced mode is unavailable the server will return an error rather than silently falling back.

---

## Mock Device (no admin rights)

Sends synthetic UDP packets to the backend sink so you can develop without elevated privileges:

```bash
pixi run mock-device
```

Modes: `--mode feed` (default), `chat`, `sender`, `receiver`, `echo`.

---

## Embedding in a Larger Application

NetCapture is a Python package (backend) and a Svelte component library (frontend) that can be mounted into any existing app.

### Backend — Python / FastAPI

Install the package:
```bash
pip install ./backend            # basic (raw socket + listen modes)
pip install ./backend[npcap]     # with scapy for Npcap support
```

Mount the router in your FastAPI app, choosing any prefix:
```python
from fastapi import FastAPI
from netcapture import create_router

app = FastAPI()
app.include_router(create_router(), prefix="/netcapture")
```

All NetCapture routes will be available under `/netcapture/api/...` and the WebSocket at `/netcapture/ws/capture`.

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

Each profile requires `id`, `name`, `interface`, and `filter`. `description` is optional.
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
        # pkt keys: src_ip, dst_ip, src_port, dst_port, protocol, length, …
        return pkt.get("dst_port") == 5000 and len(payload) >= 2 and payload[0] == 0xAB

    def decode(self, payload: bytes) -> DecodedFrame:
        # Parse the payload and return structured fields.
        return DecodedFrame(self.name, fields=[
            DecodedField("type",   payload[0],           "u8"),
            DecodedField("value",  int.from_bytes(payload[1:3], "big"), "u16"),
            DecodedField("label",  payload[3:].decode(), "str"),
        ])

app.include_router(create_router(
    extra_interpreters=[MyProtocol()],
), prefix="/netcapture")
```

Built-in interpreters run first; `extra_interpreters` are appended in order. The first interpreter whose `match()` returns `True` wins.

You can also register interpreters independently (useful when the interpreter lives in a different module):

```python
from netcapture import register_interpreter
register_interpreter(MyProtocol())
```

#### Exported symbols

#### Address Book

Map IP addresses (and IP:port pairs) to human-readable names. Names are shown in the Source and Destination columns of the packet table, highlighted in blue. The address book can be pre-populated at startup and edited live by the user via the **Addresses** button in the toolbar.

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

**Right-click filter menus:**

Right-clicking the Source, Destination, or Proto cell of any row shows a context menu with quick filter options:
- **Filter for / Exclude** — appends `ip.src == x`, `ip.dst == x`, or `proto == x` to the active filter
- **Filter / Exclude by name** — appears when the address has a resolved name; uses `src_name`/`dst_name`
- **Filter source/dest port** — appends a port condition

The appended clause is always combined with the existing filter using `and`, wrapped in parentheses.

**Testing with the UDP mock device:**

Add `127.0.0.1` or `127.0.0.1:9001` to the address book to name the mock device traffic:

```python
address_book=[{"id": "1", "address": "127.0.0.1:9001", "name": "UDP Mock Device"}]
```

Then start the mock device and start capturing — the Source column will show **UDP Mock Device** instead of the raw IP.

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

Build the component library:
```bash
cd frontend
npm install
npm run package          # outputs to frontend/dist/
```

Then install it in your Svelte app:
```bash
npm install /path/to/netcapture/frontend
```

Use the component, passing the URLs that match your backend prefix:
```svelte
<script>
  import { NetCapture } from 'netcapture'
</script>

<NetCapture
  wsUrl="wss://yourhost/netcapture/ws/capture"
  apiBase="/netcapture"
/>
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `wsUrl` | `string` | `''` | WebSocket URL. Empty = auto-detect from `window.location`. |
| `apiBase` | `string` | `''` | Prefix for all API fetch calls. Empty = same origin. |

When both are empty (standalone mode) the component connects to the same host it was served from, so no configuration is needed for the standalone case.

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
│   │   ├── capture_scapy.py # Scapy/Npcap capture
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
│   │   │   ├── index.ts         # Library entry point — exports NetCapture
│   │   │   ├── NetCapture.svelte  # Main public component (wsUrl, apiBase props)
│   │   │   ├── captureService.ts  # WebSocket + REST service layer
│   │   │   ├── stores.ts          # Svelte writable/derived stores
│   │   │   ├── filter.ts          # Wireshark-style filter parser + evaluator
│   │   │   ├── types.ts           # TypeScript type definitions
│   │   │   └── components/        # Internal UI components
│   │   │       ├── Toolbar.svelte
│   │   │       ├── StatsBar.svelte
│   │   │       ├── PacketTable.svelte
│   │   │       ├── PacketDetail.svelte
│   │   │       ├── Charts.svelte
│   │   │       └── FieldValue.svelte
│   │   ├── app.css          # Global styles + CSS custom properties (theme vars)
│   │   └── main.ts          # Standalone app entry point
│   └── package.json
├── tools/
│   └── udp_device.py        # Mock UDP device for testing
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
