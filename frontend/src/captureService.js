/**
 * captureService.js — module-level singleton
 *
 * Owns the WebSocket connection and all capture-related state.
 * Defined at module scope so it persists across page navigations in the
 * parent SPA — capture keeps running even when the capture page is unmounted.
 *
 * Exports: startCapture, stopCapture, clearCapture, fetchInterfaces
 * Drives:  packets, stats, chartHistory, isCapturing, isMockMode,
 *          connectionStatus  (all from stores.js)
 */

import {
  packets, stats, chartHistory,
  isCapturing, captureMode, connectionStatus,
} from './stores.js'

const MAX_PACKETS      = 10_000
const MAX_CHART_POINTS = 50

// ── Module-level state ────────────────────────────────────────────────────────

let ws             = null
let reconnectTimer = null
let displayTimer   = null

let _displayBuf   = []   // flushed to packets store at 4 Hz
let _lastPacketId = 0    // highest received ID — deduplicates buffer replays
let _trafficHist  = []   // accumulated per-second chart points

// ── Packet ingestion ──────────────────────────────────────────────────────────

function ingest(batch) {
  // Skip packets the store already has (handles buffer replay on reconnect)
  const fresh = batch.filter(p => p.id > _lastPacketId)
  if (!fresh.length) return
  for (const p of fresh) {
    if (p.id > _lastPacketId) _lastPacketId = p.id
  }
  for (const p of fresh) _displayBuf.push(p)
}

// ── Display tick (4 Hz) ───────────────────────────────────────────────────────

function startDisplayTick() {
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

function stopDisplayTick() {
  clearInterval(displayTimer)
  displayTimer = null
  _displayBuf  = []
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

function connect() {
  if (ws?.readyState === WebSocket.OPEN || ws?.readyState === WebSocket.CONNECTING) return
  clearTimeout(reconnectTimer)
  connectionStatus.set('connecting')

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${proto}//${location.host}/ws/capture`)

  ws.onopen = () => connectionStatus.set('connected')

  ws.onmessage = ({ data }) => {
    try {
      const msg = JSON.parse(data)
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

export async function startCapture(iface = 'any', filter = '') {
  try {
    const res = await fetch('/api/capture/start', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ interface: iface, filter }),
    })
    if (res.ok) {
      const body = await res.json()
      if (body.status === 'error') {
        captureMode.set('error')
        console.error('[capture]', body.message)
        return
      }
      isCapturing.set(true)
      captureMode.set(body.mode)
      startDisplayTick()
    }
  } catch {
    connectionStatus.set('error')
  }
}

export async function stopCapture() {
  try { await fetch('/api/capture/stop', { method: 'POST' }) } catch {}
  isCapturing.set(false)
  captureMode.set('idle')
  stopDisplayTick()
}

export function clearCapture() {
  packets.set([])
  _displayBuf   = []
  _lastPacketId = 0
  _trafficHist  = []
  stats.set({ total_packets: 0, total_bytes: 0, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts: {} })
  chartHistory.set([])
  fetch('/api/reset-session', { method: 'POST' }).catch(() => {})
}

export async function fetchInterfaces() {
  try {
    const res = await fetch('/api/interfaces')
    if (!res.ok) return []
    const data = await res.json()
    return data.interfaces ?? []
  } catch {
    return []
  }
}

// Connect as soon as the module is first imported
connect()
