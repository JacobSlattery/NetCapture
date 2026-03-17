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

export type CaptureMode = 'idle' | 'real' | 'listen' | 'error'

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

export type WsMessage =
  | { type: 'status'; data: { running: boolean; mode: CaptureMode } }
  | { type: 'packet'; data: Packet }
  | { type: 'batch';  data: Packet[] }
  | { type: 'stats';  data: Stats }
