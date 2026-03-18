import { writable, derived } from 'svelte/store'
import { parseFilter, matchesFilter } from './filter'
import type {
  Packet, NetworkInterface, Stats, ChartPoint,
  CaptureMode, ConnectionStatus, CaptureProfile, TrackFingerprint,
  AddressBookEntry,
} from './types'

// All captured packets (capped at MAX_PACKETS in captureService)
export const packets = writable<Packet[]>([])

// Currently selected packet for detail panel
export const selectedPacket = writable<Packet | null>(null)

// Capture state
export const isCapturing = writable<boolean>(false)

// Active capture mode reported by backend
export const captureMode = writable<CaptureMode>('idle')

// WebSocket / connection state
export const connectionStatus = writable<ConnectionStatus>('disconnected')

// Selected network interface — persisted to localStorage.
// Starts empty so the select shows blank until onMount confirms the right value.
const _IFACE_KEY = 'nc:selectedInterface'
export const selectedInterface = writable<string>('')
selectedInterface.subscribe(v => { if (v) localStorage.setItem(_IFACE_KEY, v) })

// Available network interfaces from backend
export const interfaces = writable<NetworkInterface[]>([{ name: 'any', description: 'All interfaces' }])

// Named capture profiles from backend (/api/profiles)
export const profiles = writable<CaptureProfile[]>([])

// Currently active profile (null when a plain interface is selected) — ID persisted
export const activeProfile = writable<CaptureProfile | null>(null);
{
  let initialized = false
  activeProfile.subscribe(p => {
    if (!initialized) { initialized = true; return }
    if (p) localStorage.setItem('nc:activeProfileId', p.id)
    else localStorage.removeItem('nc:activeProfileId')
  })
}

// Address book — maps IP / IP:port to human-readable names
export const addressBook = writable<AddressBookEntry[]>([])

// When non-null, Toolbar will open the address book editor pre-filled with this address
export const addressBookPrefill = writable<string | null>(null)

// Timestamp (ms) of last successful track-mode packet match — null until first match
export const trackLastUpdate = writable<number | null>(null)

// Timestamp display mode: 'relative' (session offset) or 'absolute' (wall clock)
export const timestampMode = writable<'relative' | 'absolute'>(
  (localStorage.getItem('nc:timestampMode') as 'relative' | 'absolute') ?? 'relative'
)
timestampMode.subscribe(v => localStorage.setItem('nc:timestampMode', v))

// BPF-style display filter (client-side)
export const captureFilter = writable<string>('')

// Auto-scroll: follow newest packets during live capture
export const autoScrollEnabled = writable<boolean>(
  localStorage.getItem('nc:autoScroll') !== 'false'
)
autoScrollEnabled.subscribe(v => localStorage.setItem('nc:autoScroll', String(v)))

// Max packets kept in the rolling buffer
export const maxPackets = writable<number>(
  Math.max(100, Number(localStorage.getItem('nc:maxPackets') || 10000))
)
maxPackets.subscribe(v => localStorage.setItem('nc:maxPackets', String(v)))

// Auto-stop after N packets (0 = unlimited)
export const capturePacketLimit = writable<number>(
  Math.max(0, Number(localStorage.getItem('nc:packetLimit') || 0))
)
capturePacketLimit.subscribe(v => localStorage.setItem('nc:packetLimit', String(v)))

// Ring buffer: keep newest N packets (true) vs keep all (false)
export const ringBuffer = writable<boolean>(
  localStorage.getItem('nc:ringBuffer') !== 'false'
)
ringBuffer.subscribe(v => localStorage.setItem('nc:ringBuffer', String(v)))

// Column visibility for the packet table
export interface ColumnVisibility {
  no: boolean; time: boolean; source: boolean; destination: boolean
  proto: boolean; length: boolean; info: boolean
}
const _CV_DEFAULT: ColumnVisibility = {
  no: true, time: true, source: true, destination: true,
  proto: true, length: true, info: true,
}
export const columnVisibility = writable<ColumnVisibility>((() => {
  try { return { ..._CV_DEFAULT, ...JSON.parse(localStorage.getItem('nc:colVis') ?? '{}') } }
  catch { return { ..._CV_DEFAULT } }
})())
columnVisibility.subscribe(v => localStorage.setItem('nc:colVis', JSON.stringify(v)))

// Aggregate stats updated each second
export const stats = writable<Stats>({
  total_packets: 0,
  total_bytes: 0,
  packets_per_sec: 0,
  bytes_per_sec: 0,
  protocol_counts: {},
})

// Chart history updated every second — kept separate to avoid triggering
// full stats subscribers on every tick
export const chartHistory = writable<ChartPoint[]>([])

// ── Track mode ────────────────────────────────────────────────────────────────
export const trackMode        = writable<boolean>(false)
export const trackFingerprint = writable<TrackFingerprint | null>(null)
export const trackPrev        = writable<Packet | null>(null)

// Derived filtered packet list using the Wireshark-style filter parser.
// An invalid filter expression shows all packets (no filtering applied).
export const filteredPackets = derived(
  [packets, captureFilter],
  ([$packets, $filter]) => {
    const result = parseFilter($filter)
    if (!result._expr) return $packets
    return $packets.filter(p => matchesFilter(p, result))
  }
)
