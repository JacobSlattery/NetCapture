// ── Interpreter / translation layer ──────────────────────────────────────────

export type DecodedValue =
  | string | number | boolean
  | DecodedValue[]
  | { [k: string]: DecodedValue }

export interface DecodedField {
  key:   string
  value: DecodedValue
  type:  string   // 'u8'|'u16'|'u32'|'u64'|'i8'|'i16'|'i32'|'i64'|'f32'|'f64'
                  // 'str'|'strlong'|'bool'|'hex'|'json'|'list'|'dict'
}

export interface DecodedFrame {
  interpreterName: string
  fields: DecodedField[]
  error?: string
  payloadOffset?: number   // byte offset in raw_hex where the interpreter's payload starts
}

// ── Track mode fingerprint ────────────────────────────────────────────────────

export interface TrackFingerprint {
  protocol:        string
  src_ip:          string
  dst_ip:          string
  src_port:        number | null
  dst_port:        number | null
  interpreterName: string | undefined
}

// ── Watchlist ────────────────────────────────────────────────────────────────

/** Which packets a watch entry applies to (all fields optional for flexible matching) */
export interface WatchMatcher {
  protocol?:        string
  src_ip?:          string
  dst_ip?:          string
  src_port?:        number | null
  dst_port?:        number | null
  interpreterName?: string
}

/** A single watched decoded field */
export interface WatchEntry {
  id:        string          // crypto.randomUUID()
  label:     string          // user-facing display name
  matcher:   WatchMatcher    // packet source filter
  fieldPath: string          // dot-separated decoded field path (e.g. "status.code")
  group?:    string          // grouping label (defaults to interpreterName)
}

/** Runtime state per watch entry (NOT persisted) */
export interface WatchValue {
  entryId:        string
  current:        string | null   // stringified extracted value
  previous:       string | null   // previous value for change detection
  changed:        boolean         // true when current !== previous (false on first acquisition)
  lastUpdate:     number | null   // ms timestamp of last value change
  sourcePacketId: number | null   // ID of the packet that supplied the current value
  prevPacketId:   number | null   // ID of the packet that supplied the previous value
}

// ── Address book ──────────────────────────────────────────────────────────────

export interface AddressBookEntry {
  id:      string
  address: string   // "ip" (e.g. "192.168.1.1") or "ip:port" (e.g. "192.168.1.1:9001")
  name:    string
  notes?:  string
}

// ── Capture profile ───────────────────────────────────────────────────────────

export interface CaptureProfile {
  id:          string
  name:        string
  description: string
  interface:   string    // network interface to bind when this profile is active
  filter:      string    // Python-style capture filter (backend pre-filter)
  bpf_filter?: string    // kernel-level BPF filter (Npcap mode only)
  inject?:     boolean   // true = use WS injection mode (/ws/inject) instead of a real interface
  builtin?:    boolean   // true for built-in defaults — read-only
}

// ── Packet ────────────────────────────────────────────────────────────────────

export interface Packet {
  id: number
  timestamp: string
  abs_time?: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string
  length: number
  info: string
  raw_hex?: string
  decoded?: DecodedFrame   // set by backend when an interpreter matches
  warnings?: string[]      // checksum failures or other network-level issues
}

export interface NetworkInterface {
  name: string
  description?: string
}

export interface Stats {
  total_packets: number
  total_bytes: number
  packets_per_sec: number
  bytes_per_sec: number
  protocol_counts: Record<string, number>
}

export interface ChartPoint {
  time: string
  packets: number
  bytes: number
}

export type CaptureMode = 'idle' | 'scapy' | 'real' | 'listen' | 'error'

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

export type WsMessage =
  | { type: 'status'; data: { running: boolean; mode: CaptureMode } }
  | { type: 'packet'; data: Packet }
  | { type: 'batch';  data: Packet[] }
  | { type: 'stats';  data: Stats }
