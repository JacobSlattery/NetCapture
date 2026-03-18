import { writable, derived } from 'svelte/store'
import { parseFilter, matchesFilter } from './filter'
import type {
  Packet, NetworkInterface, Stats, ChartPoint,
  CaptureMode, ConnectionStatus, CaptureProfile, TrackFingerprint,
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

// BPF-style display filter (client-side)
export const captureFilter = writable<string>('')

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
