import { writable, derived } from 'svelte/store'

// All captured packets (capped at MAX_PACKETS in App.svelte)
export const packets = writable([])

// Currently selected packet for detail panel
export const selectedPacket = writable(null)

// Capture state
export const isCapturing = writable(false)

// Active capture mode reported by backend: 'idle' | 'real' | 'listen' | 'error'
export const captureMode = writable('idle')

// WebSocket / connection state: 'disconnected' | 'connecting' | 'connected' | 'error'
export const connectionStatus = writable('disconnected')

// Selected network interface
export const selectedInterface = writable('any')

// Available network interfaces from backend
export const interfaces = writable([{ name: 'any', description: 'All interfaces' }])

// BPF-style display filter (client-side)
export const captureFilter = writable('')

// Aggregate stats updated each second
export const stats = writable({
  total_packets: 0,
  total_bytes: 0,
  packets_per_sec: 0,
  bytes_per_sec: 0,
  protocol_counts: {},
})

// Chart history updated every 200 ms — kept separate to avoid triggering
// full stats subscribers on every chart tick
export const chartHistory = writable([])

// Derived filtered packet list
export const filteredPackets = derived(
  [packets, captureFilter],
  ([$packets, $filter]) => {
    const f = $filter.trim().toLowerCase()
    if (!f) return $packets
    return $packets.filter(p =>
      p.protocol?.toLowerCase().includes(f) ||
      p.src_ip?.includes(f) ||
      p.dst_ip?.includes(f) ||
      p.info?.toLowerCase().includes(f) ||
      String(p.src_port ?? '').includes(f) ||
      String(p.dst_port ?? '').includes(f)
    )
  }
)
