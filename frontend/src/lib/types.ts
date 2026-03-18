// ── Interpreter / translation layer ──────────────────────────────────────────

export type DecodedValue =
  | string | number | boolean
  | DecodedValue[]
  | { [k: string]: DecodedValue }

export interface DecodedField {
  key:   string
  value: DecodedValue
  type:  string   // 'u8' | 'u16' | 'u32' | 'f32' | 'str' | 'bool' | 'list' | 'dict'
}

export interface DecodedFrame {
  interpreterName: string
  fields: DecodedField[]
  error?: string
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
  interface:   string   // network interface to bind when this profile is active
  filter:      string   // whitespace-separated OR filter terms
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
