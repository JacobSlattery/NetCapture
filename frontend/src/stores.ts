import { writable, derived } from 'svelte/store'
import type {
  Packet, NetworkInterface, Stats, ChartPoint, CaptureMode, ConnectionStatus,
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

// Selected network interface
export const selectedInterface = writable<string>('any')

// Available network interfaces from backend
export const interfaces = writable<NetworkInterface[]>([{ name: 'any', description: 'All interfaces' }])

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
