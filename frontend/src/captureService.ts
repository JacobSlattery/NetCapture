/**
 * captureService.ts — module-level singleton
 *
 * Owns the WebSocket connection and all capture-related state.
 * Defined at module scope so it persists across page navigations in the
 * parent SPA — capture keeps running even when the capture page is unmounted.
 *
 * Exports: startCapture, stopCapture, clearCapture, fetchInterfaces
 * Drives:  packets, stats, chartHistory, isCapturing, captureMode,
 *          connectionStatus  (all from stores.ts)
 */

import {
  packets, stats, chartHistory,
  isCapturing, captureMode, connectionStatus,
} from './stores'
import type { Packet, ChartPoint, NetworkInterface, WsMessage } from './types'

const MAX_PACKETS      = 10_000
const MAX_CHART_POINTS = 50

// ── Module-level state ────────────────────────────────────────────────────────

let ws:             WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout>  | null = null
let displayTimer:   ReturnType<typeof setInterval> | null = null

let _displayBuf:   Packet[]     = []   // flushed to packets store at 4 Hz
let _lastPacketId: number       = 0    // highest received ID — deduplicates buffer replays
let _trafficHist:  ChartPoint[] = []   // accumulated per-second chart points

// ── Packet ingestion ──────────────────────────────────────────────────────────

function ingest(batch: Packet[]): void {
  // Skip packets the store already has (handles buffer replay on reconnect)
  const fresh = batch.filter(p => p.id > _lastPacketId)
  if (!fresh.length) return
  for (const p of fresh) {
    if (p.id > _lastPacketId) _lastPacketId = p.id
  }
  for (const p of fresh) _displayBuf.push(p)
}

// ── Display tick (4 Hz) ───────────────────────────────────────────────────────

function startDisplayTick(): void {
  if (displayTimer) return
  displayTimer = setInterval(() => {
    if (!_displayBuf.length) return
    const batch = _displayBuf.splice(0)
    packets.update(list => {
      const next = list.concat(batch)
      return next.length > MAX_PACKETS ? next.slice(-MAX_PACKETS) : next
    })
  }, 250)
}

function stopDisplayTick(): void {
  clearInterval(displayTimer ?? undefined)
  displayTimer = null
  _displayBuf  = []
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

function connect(): void {
  if (ws?.readyState === WebSocket.OPEN || ws?.readyState === WebSocket.CONNECTING) return
  clearTimeout(reconnectTimer ?? undefined)
  connectionStatus.set('connecting')

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${proto}//${location.host}/ws/capture`)

  ws.onopen = () => connectionStatus.set('connected')

  ws.onmessage = ({ data }: MessageEvent<string>) => {
    try {
      const msg = JSON.parse(data) as WsMessage
      switch (msg.type) {
        case 'status': {
          const { running, mode } = msg.data
          isCapturing.set(running)
          captureMode.set(running ? mode : 'idle')
          if (running) startDisplayTick()
          break
        }
        case 'packet':
          ingest([msg.data])
          break
        case 'batch':
          ingest(msg.data)
          break
        case 'stats': {
          stats.set(msg.data)
          const now = new Date()
          _trafficHist.push({
            time:    now.toTimeString().slice(0, 8),
            packets: msg.data.packets_per_sec,
            bytes:   msg.data.bytes_per_sec,
          })
          if (_trafficHist.length > MAX_CHART_POINTS) _trafficHist.shift()
          chartHistory.set([..._trafficHist])
          break
        }
      }
    } catch { /* ignore malformed frames */ }
  }

  ws.onerror = () => connectionStatus.set('error')

  ws.onclose = () => {
    connectionStatus.set('disconnected')
    reconnectTimer = setTimeout(connect, 2_000)
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function startCapture(iface = 'any', filter = ''): Promise<void> {
  try {
    const res = await fetch('/api/capture/start', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ interface: iface, filter }),
    })
    if (res.ok) {
      const body = await res.json() as { status: string; message?: string; mode: string }
      if (body.status === 'error') {
        captureMode.set('error')
        console.error('[capture]', body.message)
        return
      }
      isCapturing.set(true)
      captureMode.set(body.mode as import('./types').CaptureMode)
      startDisplayTick()
    }
  } catch {
    connectionStatus.set('error')
  }
}

export async function stopCapture(): Promise<void> {
  try { await fetch('/api/capture/stop', { method: 'POST' }) } catch {}
  isCapturing.set(false)
  captureMode.set('idle')
  stopDisplayTick()
}

export function clearCapture(): void {
  packets.set([])
  _displayBuf   = []
  _lastPacketId = 0
  _trafficHist  = []
  stats.set({ total_packets: 0, total_bytes: 0, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts: {} })
  chartHistory.set([])
  fetch('/api/reset-session', { method: 'POST' }).catch(() => {})
}

export async function fetchInterfaces(): Promise<NetworkInterface[]> {
  try {
    const res = await fetch('/api/interfaces')
    if (!res.ok) return []
    const data = await res.json() as { interfaces?: NetworkInterface[] }
    return data.interfaces ?? []
  } catch {
    return []
  }
}

// Connect as soon as the module is first imported
connect()
