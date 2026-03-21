/**
 * captureService.ts — module-level singleton
 *
 * Owns the WebSocket connection and all capture-related state.
 * Call initCaptureService(wsUrl, apiBase) once before using.
 *
 * When embedded in a larger app pass explicit URLs:
 *   initCaptureService('wss://host/netcapture/ws/capture', '/netcapture')
 *
 * In standalone mode leave both empty — they are auto-detected from location.
 */

import {
  packets, stats, chartHistory,
  isCapturing, captureMode, connectionStatus, selectedPacket,
  trackMode, trackFingerprint, trackPrev, addressBook, trackLastUpdate, trackStrictness,
  captureFilter,
  maxPackets, capturePacketLimit, ringBuffer, dnsCache, npcapAvailable, profiles,
} from './stores'
import type { Packet, ChartPoint, NetworkInterface, CaptureProfile, WsMessage, TrackFingerprint, AddressBookEntry } from './types'
import type { ColumnVisibility } from './stores'
import { setAddressBook, parseFilter, matchesFilter } from './filter'
import type { ParseResult } from './filter'

// Keep filter's address book mirror in sync with the store
addressBook.subscribe(book => setAddressBook(book))

const MAX_CHART_POINTS = 50

let _maxPackets          = 10_000
let _capturePacketLimit  = 0
let _ringBuffer          = true
maxPackets.subscribe(v => { _maxPackets = v })
capturePacketLimit.subscribe(v => { _capturePacketLimit = v })
ringBuffer.subscribe(v => { _ringBuffer = v })

// ── Module-level state ────────────────────────────────────────────────────────

let ws:              WebSocket | null = null
let reconnectTimer:  ReturnType<typeof setTimeout>  | null = null
let displayTimer:    ReturnType<typeof setInterval> | null = null
let reacquireTimer:  ReturnType<typeof setInterval> | null = null

let _displayBuf:   Packet[]     = []
let _lastPacketId: number       = 0
let _trafficHist:  ChartPoint[] = []

// ── URL configuration ─────────────────────────────────────────────────────────

let _wsUrl   = ''   // empty = auto-detect from window.location
let _apiBase = ''   // empty = relative paths (/api/...)

function resolveWsUrl(): string {
  if (_wsUrl) return _wsUrl
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}/ws/capture`
}

// ── Track mode mirrors + persistence ─────────────────────────────────────────
// ── Adaptive display-tick state ───────────────────────────────────────────────
// The display tick runs at 32 ms (≈30 fps) so light traffic feels smooth.
// When the buffer contains ≥ FLUSH_HEAVY_THRESHOLD packets the flush is
// throttled to FLUSH_HEAVY_MS (250 ms / 4 Hz) to prevent DOM thrashing under
// heavy capture load.
const FLUSH_HEAVY_THRESHOLD = 20
const FLUSH_HEAVY_MS        = 250
let   _lastFlushMs           = 0

let _trackMode:        boolean              = false
let _fingerprint:      TrackFingerprint | null = null
let _trackLastUpdateMs: number | null      = null   // mirror of trackLastUpdate store
let _trackStrictness:  'strict' | 'loose'  = 'strict'
let _filterResult:     ParseResult         = { valid: true }  // mirror of captureFilter store
const TRACK_WAITING_THRESHOLD = 5_000  // ms before considered "no signal"

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
trackLastUpdate.subscribe(v => { _trackLastUpdateMs = v })
trackStrictness.subscribe(v => { _trackStrictness = v })
captureFilter.subscribe(v => { _filterResult = parseFilter(v) })
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

// Looser match for re-acquisition: drops src_port and interpreter.
// src_port is omitted because TCP reconnects allocate a new ephemeral port, and
// many UDP senders also change source port on restart. dst_port (the service port)
// is kept because it identifies the stream.
function matchesFingerprintLoose(pkt: Packet, fp: TrackFingerprint): boolean {
  return pkt.protocol === fp.protocol
    && pkt.src_ip  === fp.src_ip
    && pkt.dst_ip  === fp.dst_ip
    && pkt.dst_port === fp.dst_port
}

function applyTracking(batch: Packet[]): void {
  if (!_trackMode || !_fingerprint) return
  // Match on fingerprint only — display filter is for the table, not for tracking.
  // This prevents a display filter mismatch from permanently killing re-acquisition.
  const rev   = batch.filter(p => matchesFilter(p, _filterResult)).reverse()
  const fn    = _trackStrictness === 'strict' ? matchesFingerprint : matchesFingerprintLoose
  const match = rev.find(p => fn(p, _fingerprint!))
  if (!match) return

  // Always refresh the "active" timestamp whenever a matching packet arrives,
  // regardless of whether the detail panel actually re-renders.
  const now = Date.now()
  trackLastUpdate.set(now)

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
  const fresh = batch.filter(p => p.id > _lastPacketId)
  if (!fresh.length) return
  for (const p of fresh) {
    if (p.id > _lastPacketId) _lastPacketId = p.id
  }
  for (const p of fresh) _displayBuf.push(p)
}

// ── Re-acquisition scanner ────────────────────────────────────────────────────
// Runs on a 1 Hz interval independently of the display tick.  When tracking has
// been in "waiting / no signal" state for longer than the threshold it scans the
// tail of the stored packet list for a match.  This catches cases where the batch
// path missed a match (interpreter not yet applied, src_port changed, etc.) because
// those packets are already sitting in the packets store and visible in the table.

function reacquireScan(): void {
  if (!_trackMode || !_fingerprint) return
  const now = Date.now()
  // Still receiving recent matches — nothing to do.
  if (_trackLastUpdateMs !== null && now - _trackLastUpdateMs < TRACK_WAITING_THRESHOLD) return

  let stored: Packet[] = []
  const unsub = packets.subscribe(p => { stored = p })
  unsub()
  if (!stored.length) return

  // Search the most recent 200 packets, newest first.
  const tail  = stored.slice(-200).filter(p => matchesFilter(p, _filterResult)).reverse()
  const fn    = _trackStrictness === 'strict' ? matchesFingerprint : matchesFingerprintLoose
  const match = tail.find(p => fn(p, _fingerprint!))
  if (!match) return

  trackLastUpdate.set(now)
  _trackLastUpdateMs = now

  let cur: Packet | null = null
  const unsub2 = selectedPacket.subscribe((p: Packet | null) => { cur = p })
  unsub2()
  if (cur === null || (cur as Packet).id !== match.id) {
    trackPrev.set(cur)
    selectedPacket.set(match)
  }
}

function startReacquireTimer(): void {
  if (reacquireTimer) return
  reacquireTimer = setInterval(reacquireScan, 1_000)
}

function stopReacquireTimer(): void {
  clearInterval(reacquireTimer ?? undefined)
  reacquireTimer = null
}

// ── Display tick (4 Hz) ───────────────────────────────────────────────────────

function startDisplayTick(): void {
  if (displayTimer) return
  startReacquireTimer()
  displayTimer = setInterval(() => {
    if (!_displayBuf.length) return
    const now = Date.now()
    if (_displayBuf.length >= FLUSH_HEAVY_THRESHOLD && now - _lastFlushMs < FLUSH_HEAVY_MS) return
    _lastFlushMs = now
    const batch = _displayBuf.splice(0)
    let newTotal = 0
    packets.update(list => {
      const next = list.concat(batch)
      const result = (_ringBuffer && next.length > _maxPackets) ? next.slice(-_maxPackets) : next
      newTotal = result.length
      return result
    })
    applyTracking(batch)
    // Trigger DNS resolution for new IPs
    const ips = batch.map(p => [p.src_ip, p.dst_ip]).flat().filter(Boolean) as string[]
    if (ips.length) resolveIps([...new Set(ips)])
    if (_capturePacketLimit > 0 && newTotal >= _capturePacketLimit) {
      isCapturing.set(false)
      captureMode.set('idle')
      stopDisplayTick()
      fetch(`${_apiBase}/api/capture/stop`, { method: 'POST' }).catch(() => {})
    }
  }, 32)
}

function stopDisplayTick(): void {
  clearInterval(displayTimer ?? undefined)
  displayTimer = null
  stopReacquireTimer()
  if (_displayBuf.length) {
    const snap = _displayBuf.splice(0)
    packets.update(list => {
      const next = list.concat(snap)
      return (_ringBuffer && next.length > _maxPackets) ? next.slice(-_maxPackets) : next
    })
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

function connect(): void {
  if (ws?.readyState === WebSocket.OPEN || ws?.readyState === WebSocket.CONNECTING) return
  clearTimeout(reconnectTimer ?? undefined)
  connectionStatus.set('connecting')

  ws = new WebSocket(resolveWsUrl())

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
          // During active capture, leave packets in _displayBuf for the 4Hz
          // display tick to render — prevents rapid-fire Svelte store updates
          // from blocking the JS event loop under heavy traffic.
          // When not capturing (reconnect replay), drain immediately.
          if (_displayBuf.length && !displayTimer) {
            const snap = _displayBuf.splice(0)
            let merged: Packet[] = []
            packets.update(list => {
              merged = list.concat(snap)
              return (_ringBuffer && merged.length > _maxPackets) ? merged.slice(-_maxPackets) : merged
            })
            recomputeStats(merged)

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
    reconnectTimer = setTimeout(connect, 1_000)
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialise the service with explicit URLs.
 *
 * @param wsUrl   Full WebSocket URL, e.g. 'wss://host/netcapture/ws/capture'.
 *                Leave empty to auto-detect from window.location.
 * @param apiBase Path prefix for REST calls, e.g. '/netcapture'.
 *                Leave empty for relative /api/... paths (standalone mode).
 */
export function initCaptureService(wsUrl: string, apiBase = ''): void {
  _wsUrl   = wsUrl
  _apiBase = apiBase
  connect()
}

export async function startCapture(iface = 'any', filter = '', bpfFilter = ''): Promise<void> {
  try {
    const res = await fetch(`${_apiBase}/api/capture/start`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ interface: iface, filter, bpf_filter: bpfFilter }),
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
  try { await fetch(`${_apiBase}/api/capture/stop`, { method: 'POST' }) } catch {}
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
  fetch(`${_apiBase}/api/reset-session`, { method: 'POST' }).catch(() => {})
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

  const protocol_counts: Record<string, number> = {}
  let total_bytes = 0
  for (const p of imported) {
    total_bytes += p.length ?? 0
    protocol_counts[p.protocol] = (protocol_counts[p.protocol] ?? 0) + 1
  }

  _displayBuf   = []
  _trafficHist  = []
  localStorage.removeItem('nc:trafficHist')
  _lastPacketId = imported.reduce((m, p) => Math.max(m, p.id ?? 0), 0)

  selectedPacket.set(null)
  chartHistory.set([])
  stats.set({ total_packets: imported.length, total_bytes, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts })
  packets.set(imported)
}

// ── DNS Resolution ────────────────────────────────────────────────────────────

const _dnsInflight = new Set<string>()
const _DNS_CONCURRENCY = 5
let _dnsQueue: string[] = []
let _dnsRunning = 0

function _processDnsQueue(): void {
  while (_dnsRunning < _DNS_CONCURRENCY && _dnsQueue.length) {
    const ip = _dnsQueue.shift()!
    _dnsRunning++
    fetch(`${_apiBase}/api/dns/resolve?ip=${encodeURIComponent(ip)}`)
      .then(r => r.json() as Promise<{ ip: string; hostname: string | null }>)
      .then(({ ip: resolvedIp, hostname }) => {
        dnsCache.update(m => ({ ...m, [resolvedIp]: hostname }))
      })
      .catch(() => {
        dnsCache.update(m => ({ ...m, [ip]: null }))
      })
      .finally(() => {
        _dnsInflight.delete(ip)
        _dnsRunning--
        _processDnsQueue()
      })
  }
}

export function resolveIps(ips: string[]): void {
  let cache: Record<string, string | null> = {}
  const unsub = dnsCache.subscribe(v => { cache = v })
  unsub()
  for (const ip of ips) {
    if (ip in cache || _dnsInflight.has(ip)) continue
    _dnsInflight.add(ip)
    _dnsQueue.push(ip)
  }
  _processDnsQueue()
}

// ── PCAP Export / Import ──────────────────────────────────────────────────────

export async function exportPcap(): Promise<void> {
  try {
    const res = await fetch(`${_apiBase}/api/capture/export/pcap`)
    if (!res.ok) return
    const blob = await res.blob()
    const ts   = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `netcapture-${ts}.pcap`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch { /* ignore */ }
}

export async function importPcap(file: File): Promise<void> {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${_apiBase}/api/capture/import/pcap`, { method: 'POST', body: form })
  const body = await res.json() as { status: string; count?: number; message?: string }
  if (body.status !== 'ok') throw new Error(body.message ?? 'Import failed')
  // The backend broadcasts a 'batch' message to all WS subscribers, so the
  // frontend will receive it through the existing WebSocket handler.
  // We just need to reset local state:
  _displayBuf   = []
  _lastPacketId = 0
  _trafficHist  = []
  selectedPacket.set(null)
  chartHistory.set([])
  stats.set({ total_packets: body.count ?? 0, total_bytes: 0, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts: {} })
}

export async function importCsv(file: File): Promise<void> {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${_apiBase}/api/capture/import/csv`, { method: 'POST', body: form })
  const body = await res.json() as { status: string; count?: number; message?: string }
  if (body.status !== 'ok') throw new Error(body.message ?? 'CSV import failed')
  _displayBuf   = []
  _lastPacketId = 0
  _trafficHist  = []
  selectedPacket.set(null)
  chartHistory.set([])
  stats.set({ total_packets: body.count ?? 0, total_bytes: 0, packets_per_sec: 0, bytes_per_sec: 0, protocol_counts: {} })
}

// ── CSV Export ────────────────────────────────────────────────────────────────

export function exportCsv(filteredPkts: Packet[], colVis: ColumnVisibility, tsMode: 'relative' | 'absolute', dnsCacheMap: Map<string, string | null>): void {
  if (!filteredPkts.length) return

  function csvCell(v: string | number | null | undefined): string {
    const s = String(v ?? '')
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }

  const headers: string[] = []
  const rows: string[][] = []

  if (colVis.no)          headers.push('No.')
  if (colVis.time)        headers.push('Time')
  if (colVis.source)      headers.push('Source')
  if (colVis.destination) headers.push('Destination')
  if (colVis.proto)       headers.push('Protocol')
  if (colVis.length)      headers.push('Length')
  if (colVis.info)        headers.push('Info')

  for (const pkt of filteredPkts) {
    const srcHost = dnsCacheMap.get(pkt.src_ip)
    const dstHost = dnsCacheMap.get(pkt.dst_ip)
    const srcDisplay = srcHost ?? (pkt.src_port != null ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip)
    const dstDisplay = dstHost ?? (pkt.dst_port != null ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip)

    const row: string[] = []
    if (colVis.no)          row.push(csvCell(pkt.id))
    if (colVis.time)        row.push(csvCell(tsMode === 'absolute' ? (pkt.abs_time ?? pkt.timestamp) : pkt.timestamp))
    if (colVis.source)      row.push(csvCell(srcDisplay))
    if (colVis.destination) row.push(csvCell(dstDisplay))
    if (colVis.proto)       row.push(csvCell(pkt.protocol))
    if (colVis.length)      row.push(csvCell(pkt.length))
    if (colVis.info)        row.push(csvCell(pkt.info))
    rows.push(row)
  }

  const csv = '\uFEFF' + [headers, ...rows].map(r => r.join(',')).join('\r\n')
  const ts   = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `netcapture-${ts}.csv`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export async function fetchInterfaces(): Promise<NetworkInterface[]> {
  try {
    const res = await fetch(`${_apiBase}/api/interfaces`)
    if (!res.ok) return []
    const data = await res.json() as { interfaces?: NetworkInterface[] }
    return data.interfaces ?? []
  } catch {
    return []
  }
}

export async function fetchCapabilities(): Promise<void> {
  try {
    const res = await fetch(`${_apiBase}/api/capture/capabilities`)
    if (!res.ok) return
    const data = await res.json() as { npcap: boolean }
    npcapAvailable.set(data.npcap ?? false)
  } catch { /* ignore — npcapAvailable stays false */ }
}

export async function fetchProfiles(): Promise<CaptureProfile[]> {
  try {
    const res = await fetch(`${_apiBase}/api/profiles`)
    if (!res.ok) return []
    const data = await res.json() as { profiles?: CaptureProfile[] }
    return data.profiles ?? []
  } catch {
    return []
  }
}

async function _refreshProfiles(): Promise<void> {
  profiles.set(await fetchProfiles())
}

export async function createProfile(
  data: Omit<CaptureProfile, 'id' | 'builtin'>,
): Promise<CaptureProfile | null> {
  try {
    const res = await fetch(`${_apiBase}/api/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!res.ok) return null
    const json = await res.json() as { profile?: CaptureProfile }
    await _refreshProfiles()
    return json.profile ?? null
  } catch {
    return null
  }
}

export async function updateProfile(
  id: string,
  data: Omit<CaptureProfile, 'id' | 'builtin'>,
): Promise<CaptureProfile | null> {
  try {
    const res = await fetch(`${_apiBase}/api/profiles/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!res.ok) return null
    const json = await res.json() as { profile?: CaptureProfile }
    await _refreshProfiles()
    return json.profile ?? null
  } catch {
    return null
  }
}

export async function deleteProfile(id: string): Promise<boolean> {
  try {
    const res = await fetch(`${_apiBase}/api/profiles/${id}`, { method: 'DELETE' })
    if (!res.ok) return false
    await _refreshProfiles()
    return true
  } catch {
    return false
  }
}

export async function fetchAddressBook(): Promise<AddressBookEntry[]> {
  try {
    const res = await fetch(`${_apiBase}/api/address-book`)
    if (!res.ok) return []
    const data = await res.json() as { entries?: AddressBookEntry[] }
    return data.entries ?? []
  } catch {
    return []
  }
}

export async function saveAddressBook(entries: AddressBookEntry[]): Promise<void> {
  try {
    await fetch(`${_apiBase}/api/address-book`, {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ entries }),
    })
  } catch { /* ignore */ }
}

// ── Restore persisted state at module load ────────────────────────────────────

try {
  const saved = localStorage.getItem('nc:trafficHist')
  if (saved) {
    _trafficHist = JSON.parse(saved) as ChartPoint[]
    chartHistory.set([..._trafficHist])
  }
} catch { /* ignore corrupt data */ }

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

// NOTE: connect() is NOT called here — it is called by initCaptureService().
