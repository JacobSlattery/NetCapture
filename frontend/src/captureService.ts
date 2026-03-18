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
  isCapturing, captureMode, connectionStatus, selectedPacket,
  trackMode, trackFingerprint, trackPrev, captureFilter,
} from './stores'
import type { Packet, ChartPoint, NetworkInterface, CaptureProfile, WsMessage, TrackFingerprint } from './types'
import { parseFilter, matchesFilter, type ParseResult } from './lib/filter'

const MAX_PACKETS      = 10_000
const MAX_CHART_POINTS = 50

// ── Module-level state ────────────────────────────────────────────────────────

let ws:             WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout>  | null = null
let displayTimer:   ReturnType<typeof setInterval> | null = null

let _displayBuf:   Packet[]     = []   // flushed to packets store at 4 Hz
let _lastPacketId: number       = 0    // highest received ID — deduplicates buffer replays
let _trafficHist:  ChartPoint[] = []   // accumulated per-second chart points

// ── Active filter mirror ──────────────────────────────────────────────────────
let _filterResult: ParseResult = { valid: true }
captureFilter.subscribe(raw => { _filterResult = parseFilter(raw) })

// ── Track mode mirrors + persistence ─────────────────────────────────────────
let _trackMode:   boolean             = false
let _fingerprint: TrackFingerprint | null = null

// Skip the first (initialisation) call so we don't wipe localStorage on load
;{
  let first = true
  trackMode.subscribe(v => {
    _trackMode = v
    if (first) { first = false; return }
    if (v) localStorage.setItem('nc:trackMode', 'true')
    else   localStorage.removeItem('nc:trackMode')
  })
}
;{
  let first = true
  trackFingerprint.subscribe(v => {
    _fingerprint = v
    if (first) { first = false; return }
    if (v) localStorage.setItem('nc:trackFingerprint', JSON.stringify(v))
    else   localStorage.removeItem('nc:trackFingerprint')
  })
}
// Persist selected packet ID so the detail panel survives a page reload
;{
  let first = true
  selectedPacket.subscribe((p: Packet | null) => {
    if (first) { first = false; return }
    if (p) localStorage.setItem('nc:selectedPacketId', String(p.id))
    else   localStorage.removeItem('nc:selectedPacketId')
  })
}

function matchesFingerprint(pkt: Packet, fp: TrackFingerprint): boolean {
  return pkt.protocol === fp.protocol
    && pkt.src_ip    === fp.src_ip
    && pkt.dst_ip    === fp.dst_ip
    && pkt.src_port  === fp.src_port
    && pkt.dst_port  === fp.dst_port
    && (fp.interpreterName == null || pkt.decoded?.interpreterName === fp.interpreterName)
}

function applyTracking(batch: Packet[]): void {
  if (!_trackMode || !_fingerprint) return
  const match = [...batch].reverse().find(p =>
    matchesFingerprint(p, _fingerprint!) && matchesFilter(p, _filterResult)
  )
  if (!match) return
  let cur: Packet | null = null
  const unsub = selectedPacket.subscribe((p: Packet | null) => { cur = p })
  unsub()
  if (cur === null || (cur as Packet).id !== match.id) {
    trackPrev.set(cur)
    selectedPacket.set(match)
  }
}

// ── Stats helper ──────────────────────────────────────────────────────────────

function recomputeStats(pkts: Packet[]): void {
  const protocol_counts: Record<string, number> = {}
  let total_bytes = 0
  for (const p of pkts) {
    total_bytes += p.length ?? 0
    protocol_counts[p.protocol] = (protocol_counts[p.protocol] ?? 0) + 1
  }
  stats.set({ total_packets: pkts.length, total_bytes, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts })
}

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
    applyTracking(batch)
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
        case 'batch': {
          ingest(msg.data)
          // Buffer replay — flush directly without waiting for the display tick
          // (tick only runs during live capture), then recompute stats.
          if (_displayBuf.length) {
            const snap = _displayBuf.splice(0)
            let merged: Packet[] = []
            packets.update(list => {
              merged = list.concat(snap)
              return merged.length > MAX_PACKETS ? merged.slice(-MAX_PACKETS) : merged
            })
            recomputeStats(merged)

            // Restore previously selected packet by ID
            const savedId = Number(localStorage.getItem('nc:selectedPacketId'))
            if (savedId) {
              const hit = merged.find(p => p.id === savedId)
              if (hit) selectedPacket.set(hit)
            }

            applyTracking(snap)
          }
          break
        }
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
          localStorage.setItem('nc:trafficHist', JSON.stringify(_trafficHist))
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
  trackMode.set(false)
  trackFingerprint.set(null)
  trackPrev.set(null)
  selectedPacket.set(null)
  localStorage.removeItem('nc:trackMode')
  localStorage.removeItem('nc:trackFingerprint')
  localStorage.removeItem('nc:selectedPacketId')
  packets.set([])
  _displayBuf   = []
  _lastPacketId = 0
  _trafficHist  = []
  localStorage.removeItem('nc:trafficHist')
  localStorage.removeItem('nc:chartLegend')
  stats.set({ total_packets: 0, total_bytes: 0, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts: {} })
  chartHistory.set([])
  fetch('/api/reset-session', { method: 'POST' }).catch(() => {})
}

export function exportCapture(): void {
  let snap: Packet[] = []
  const unsub = packets.subscribe(p => { snap = p })
  unsub()
  if (!snap.length) return

  const ts   = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')
  const blob = new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `netcapture-${ts}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export async function importCapture(file: File): Promise<void> {
  const text = await file.text()
  const data = JSON.parse(text)
  if (!Array.isArray(data)) throw new Error('Expected a JSON array of packets')

  const imported = data as Packet[]

  // Recompute stats from the imported packet list
  const protocol_counts: Record<string, number> = {}
  let total_bytes = 0
  for (const p of imported) {
    total_bytes += p.length ?? 0
    protocol_counts[p.protocol] = (protocol_counts[p.protocol] ?? 0) + 1
  }

  // Reset module state, then load
  _displayBuf   = []
  _trafficHist  = []
  localStorage.removeItem('nc:trafficHist')
  _lastPacketId = imported.reduce((m, p) => Math.max(m, p.id ?? 0), 0)

  selectedPacket.set(null)
  chartHistory.set([])
  stats.set({ total_packets: imported.length, total_bytes, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts })
  packets.set(imported)
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

export async function fetchProfiles(): Promise<CaptureProfile[]> {
  try {
    const res = await fetch('/api/profiles')
    if (!res.ok) return []
    const data = await res.json() as { profiles?: CaptureProfile[] }
    return data.profiles ?? []
  } catch {
    return []
  }
}

// Restore persisted chart history so the chart is populated before any new stats arrive
try {
  const saved = localStorage.getItem('nc:trafficHist')
  if (saved) {
    _trafficHist = JSON.parse(saved) as ChartPoint[]
    chartHistory.set([..._trafficHist])
  }
} catch { /* ignore corrupt data */ }

// Restore track mode — sets mirror vars and stores so applyTracking works immediately
try {
  if (localStorage.getItem('nc:trackMode') === 'true') {
    const raw = localStorage.getItem('nc:trackFingerprint')
    if (raw) {
      const fp = JSON.parse(raw) as TrackFingerprint
      _fingerprint = fp
      trackFingerprint.set(fp)
      _trackMode = true
      trackMode.set(true)
    }
  }
} catch { /* ignore corrupt data */ }

// Connect as soon as the module is first imported
connect()
