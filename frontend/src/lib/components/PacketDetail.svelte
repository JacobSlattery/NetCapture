<script lang="ts">
  import { createEventDispatcher, onDestroy, onMount } from 'svelte'
  import { selectedPacket, trackMode, trackFingerprint, trackPrev, isCapturing, connectionStatus, trackLastUpdate, trackStrictness } from '../stores'
  import type { Packet, TrackFingerprint, DecodedValue } from '../types'
  import FieldValue from './FieldValue.svelte'
  import ContextMenu from './ContextMenu.svelte'

  const dispatch = createEventDispatcher<{ watch: { packet: Packet; fieldKey: string } }>()

  // ── Field context menu ────────────────────────────────────────────────────
  type MenuItem = { label: string; sub?: string; action: () => void } | { separator: true }
  let fieldCtxMenu: { x: number; y: number; items: MenuItem[] } | null = null

  function copyText(text: string): void {
    navigator.clipboard.writeText(text).catch(() => {})
  }

  function valueToString(v: DecodedValue): string {
    if (v === null || v === undefined) return ''
    if (typeof v === 'object') return JSON.stringify(v)
    return String(v)
  }

  function valueToHex(v: DecodedValue): string {
    const s = valueToString(v)
    return [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join(' ')
  }

  function valueToBinary(v: DecodedValue): string {
    const s = valueToString(v)
    return [...new TextEncoder().encode(s)].map(b => b.toString(2).padStart(8, '0')).join(' ')
  }

  function openFieldMenu(e: MouseEvent, fieldKey: string, fieldValue: DecodedValue, pathPrefix: string = ''): void {
    e.preventDefault()
    const fullPath = pathPrefix ? `${pathPrefix}.${fieldKey}` : fieldKey
    const strVal = valueToString(fieldValue)
    const items: MenuItem[] = [
      { label: 'Add to Watchlist', sub: fullPath, action: () => { if (p) dispatch('watch', { packet: p, fieldKey: fullPath }) } },
    ]

    // For objects: add sub-items for each key
    if (fieldValue !== null && typeof fieldValue === 'object' && !Array.isArray(fieldValue)) {
      const obj = fieldValue as Record<string, DecodedValue>
      const keys = Object.keys(obj)
      if (keys.length > 0 && keys.length <= 20) {
        items.push({ separator: true })
        for (const k of keys) {
          const subPath = `${fullPath}.${k}`
          const subStr = valueToString(obj[k] as DecodedValue)
          items.push({
            label: `Watch ${k}`,
            sub: subStr.length > 20 ? subStr.slice(0, 20) + '…' : subStr,
            action: () => { if (p) dispatch('watch', { packet: p, fieldKey: subPath }) },
          })
        }
      }
    }

    // For arrays: add sub-items for each index (capped at 20)
    if (Array.isArray(fieldValue)) {
      const arr = fieldValue as DecodedValue[]
      const limit = Math.min(arr.length, 20)
      if (limit > 0) {
        items.push({ separator: true })
        for (let i = 0; i < limit; i++) {
          const subPath = `${fullPath}.${i}`
          const subStr = valueToString(arr[i] as DecodedValue)
          items.push({
            label: `Watch [${i}]`,
            sub: subStr.length > 20 ? subStr.slice(0, 20) + '…' : subStr,
            action: () => { if (p) dispatch('watch', { packet: p, fieldKey: subPath }) },
          })
        }
      }
    }

    items.push({ separator: true })
    items.push({ label: 'Copy value', sub: strVal.length > 30 ? strVal.slice(0, 30) + '...' : strVal, action: () => copyText(strVal) })
    items.push({ label: 'Copy as hex', action: () => copyText(valueToHex(fieldValue)) })
    items.push({ label: 'Copy as binary', action: () => copyText(valueToBinary(fieldValue)) })

    fieldCtxMenu = { x: e.clientX, y: e.clientY, items }
  }

  // ── Track state ────────────────────────────────────────────────────────────
  // Tick every second so the "waiting" threshold updates in real-time
  const WAITING_THRESHOLD_MS = 5_000

  let _now = Date.now()
  const _ticker = setInterval(() => { _now = Date.now() }, 1_000)
  onDestroy(() => clearInterval(_ticker))

  type TrackState = 'off' | 'active' | 'waiting' | 'offline'

  $: trackState = ((): TrackState => {
    if (!$trackMode) return 'off'
    if (!$isCapturing || $connectionStatus === 'disconnected' || $connectionStatus === 'error') return 'offline'
    if ($trackLastUpdate === null || _now - $trackLastUpdate > WAITING_THRESHOLD_MS) return 'waiting'
    return 'active'
  })()

  const TRACK_DOT: Record<TrackState, string> = {
    off:     '',
    active:  'bg-[var(--nc-status-ok)] animate-pulse',
    waiting: 'bg-amber-400 animate-pulse',
    offline: 'bg-[var(--nc-status-err)]',
  }
  const TRACK_TEXT: Record<TrackState, string> = {
    off:     '',
    active:  'Tracking',
    waiting: 'No signal',
    offline: 'Offline',
  }

  $: trackLabel = trackState === 'off' ? '' :
    `${TRACK_TEXT[trackState]} [${$trackStrictness}]`
  const TRACK_COLOR: Record<TrackState, string> = {
    off:     '',
    active:  'var(--nc-status-ok)',
    waiting: 'rgb(251 191 36)',   // amber-400
    offline: 'var(--nc-status-err)',
  }

  // ── Layer colour definitions ───────────────────────────────────────────────
  // bg and dot use CSS vars so they track the active theme automatically.
  // color-mix() blends the protocol colour with transparent for the cell tints.
  const LAYER = {
    eth:     { bg: 'var(--nc-p-tcp-tint)',   dot: 'var(--nc-proto-eth)',     label: 'Ethernet'  },
    ip:      { bg: 'var(--nc-p-udp-tint)',   dot: 'var(--nc-proto-ip)',      label: 'IPv4'      },
    trans:   { bg: 'var(--nc-p-icmp-tint)',  dot: 'var(--nc-proto-trans)',   label: 'Transport' },
    payload: { bg: 'var(--nc-p-dns-tint)',   dot: 'var(--nc-proto-payload)', label: 'Payload'   },
  }

  const BADGE_VAR: Record<string, string> = {
    TCP: '--nc-p-tcp', UDP: '--nc-p-udp', DNS: '--nc-p-dns',
    ICMP: '--nc-p-icmp', HTTP: '--nc-p-http', HTTPS: '--nc-p-https',
    TLS: '--nc-p-https', ARP: '--nc-p-arp',
  }
  const badge = (p: string): string =>
    `background-color: var(${BADGE_VAR[p] ?? '--nc-p-default'})`

  // ── Hex string → byte array ────────────────────────────────────────────────
  function toBytes(hex: string | undefined): number[] {
    if (!hex) return []
    const out: number[] = []
    for (let i = 0; i + 1 < hex.length; i += 2)
      out.push(parseInt(hex.slice(i, i + 2), 16))
    return out
  }

  // ── Detect whether raw_hex starts with an Ethernet header or an IP header ──
  // Ethernet:  bytes[0] is a MAC octet — first nibble is never 4 or 6
  // IPv4:      bytes[0] >> 4 === 4
  // IPv6:      bytes[0] >> 4 === 6
  type LayerKey = keyof typeof LAYER | null
  type HexCell = { hex: string; ascii: string; bg: string | null; tip: string; layer: LayerKey } | null

  function hasEthHeader(bytes: number[]): boolean {
    if (!bytes.length) return false
    const v = bytes[0] >> 4
    return v !== 4 && v !== 6
  }

  // ── Assign a layer key to every byte index ─────────────────────────────────
  function layerMap(bytes: number[]): LayerKey[] {
    const m: LayerKey[] = new Array(bytes.length).fill(null)
    if (!bytes.length) return m

    let off = 0

    if (hasEthHeader(bytes)) {
      if (bytes.length < 14) return m
      for (let i = 0; i < 14; i++) m[i] = 'eth'
      off = 14

      const et = (bytes[12] << 8) | bytes[13]
      if (et === 0x0806) {                        // ARP — rest is transport
        for (let i = off; i < bytes.length; i++) m[i] = 'trans'
        return m
      }
      if (et !== 0x0800) return m               // non-IPv4, leave uncoloured
    }

    if (bytes.length < off + 20) return m

    const ihl     = (bytes[off] & 0x0f) * 4
    const ipProto = bytes[off + 9]
    for (let i = off; i < off + ihl; i++) m[i] = 'ip'
    off += ihl

    const tLen = ipProto === 6  ? ((bytes[off + 12] >> 4) & 0xf) * 4
               : ipProto === 17 ? 8
               : ipProto === 1  ? 8
               : 0
    for (let i = off; i < Math.min(off + tLen, bytes.length); i++) m[i] = 'trans'
    off += tLen

    for (let i = off; i < bytes.length; i++) m[i] = 'payload'
    return m
  }

  // ── JSON sub-field byte scanner ───────────────────────────────────────────
  // Parses JSON objects/arrays to find character-offset ranges for each key or index,
  // then stamps those byte ranges in the field map with sub-path IDs like "decoded:meta.fw".

  function _skipJsonValue(s: string, i: number): number {
    if (i >= s.length) return i
    const c = s[i]
    if (c === '"') {
      i++
      while (i < s.length) {
        if (s[i] === '\\') { i += 2; continue }
        if (s[i] === '"')  { i++; break }
        i++
      }
    } else if (c === '{' || c === '[') {
      const close = c === '{' ? '}' : ']'
      let d = 1; i++
      while (i < s.length && d > 0) {
        if (s[i] === '"') { i = _skipJsonValue(s, i); continue }
        if (s[i] === c)     d++
        else if (s[i] === close) d--
        i++
      }
    } else {
      while (i < s.length && s[i] !== ',' && s[i] !== '}' && s[i] !== ']') i++
    }
    return i
  }

  /** Returns Map<key, [pairCharStart, pairCharEnd)> for a JSON object string */
  function _jsonObjectRanges(s: string): Map<string, [number, number]> {
    const out = new Map<string, [number, number]>()
    let i = 0
    while (i < s.length && s[i] !== '{') i++
    if (i >= s.length) return out
    i++
    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++
      if (s[i] === '}' || i >= s.length) break
      if (s[i] !== '"') break
      const pairStart = i
      i++
      let key = ''
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\') { i++ }
        key += s[i++]
      }
      i++ // closing "
      while (i < s.length && /\s/.test(s[i])) i++
      if (s[i] !== ':') break
      i++ // colon
      while (i < s.length && /\s/.test(s[i])) i++
      i = _skipJsonValue(s, i)
      out.set(key, [pairStart, i])
      while (i < s.length && /\s/.test(s[i])) i++
      if (s[i] === ',') i++
    }
    return out
  }

  /** Returns Map<index, [itemCharStart, itemCharEnd)> for a JSON array string */
  function _jsonArrayRanges(s: string): Map<string, [number, number]> {
    const out = new Map<string, [number, number]>()
    let i = 0
    while (i < s.length && s[i] !== '[') i++
    if (i >= s.length) return out
    i++
    let idx = 0
    while (i < s.length) {
      while (i < s.length && /\s/.test(s[i])) i++
      if (s[i] === ']' || i >= s.length) break
      const start = i
      i = _skipJsonValue(s, i)
      out.set(String(idx++), [start, i])
      while (i < s.length && /\s/.test(s[i])) i++
      if (s[i] === ',') i++
    }
    return out
  }

  /** Recursively stamp sub-path field IDs onto bytes[] starting at byteBase.
   *  Structural bytes (braces, brackets, commas, whitespace between items) are
   *  stamped with `prefix.__struct` so they can be matched independently. */
  function _applyJsonSubMapping(
    bytes: number[], m: string[],
    byteBase: number, jsonStr: string, prefix: string,
  ): void {
    const tr = jsonStr.trimStart()
    const trim = jsonStr.length - tr.length
    const base = byteBase + trim

    const ranges = tr.startsWith('{') ? _jsonObjectRanges(tr)
                 : tr.startsWith('[') ? _jsonArrayRanges(tr)
                 : null
    if (!ranges) return

    for (const [key, [cs, ce]] of ranges) {
      const subId = `${prefix}.${key}`
      for (let i = base + cs; i < base + ce && i < bytes.length; i++) m[i] = subId

      // Find where the value starts within this pair (skip past key + colon for objects)
      let vi = cs
      if (tr.startsWith('{')) {
        while (vi < tr.length && tr[vi] !== ':') vi++
        vi++ // colon
        while (vi < tr.length && /\s/.test(tr[vi])) vi++
      }
      const valStr = tr.slice(vi, ce).trimStart()
      if (valStr.startsWith('{') || valStr.startsWith('[')) {
        const vTrim = tr.slice(vi, ce).length - valStr.length
        _applyJsonSubMapping(bytes, m, base + vi + vTrim, valStr, subId)
      }
    }

    // Any bytes within the JSON structure that still have `prefix` are structural
    // (braces, brackets, commas, colons, inter-item whitespace) — give them a
    // distinct sub-path so hovering them doesn't light up the sub-item values.
    const structId = `${prefix}.__struct`
    const structEnd = _skipJsonValue(tr, 0)
    for (let i = base; i < base + structEnd && i < bytes.length; i++) {
      if (m[i] === prefix) m[i] = structId
    }
  }

  // ── Byte-to-field mapping for hex highlighting ─────────────────────────────
  // Each byte gets a field ID like "eth:Dst MAC" or "decoded:temperature".
  // Clicking a hex byte highlights the whole range and corresponding tree/decoded field.

  function buildByteFieldMap(bytes: number[], pkt: Packet): string[] {
    const m: string[] = new Array(bytes.length).fill('')
    if (!bytes.length) return m

    let off = 0

    // Ethernet
    if (hasEthHeader(bytes)) {
      if (bytes.length < 14) return m
      for (let i = 0;  i < 6;  i++) m[i]     = 'eth:Dst MAC'
      for (let i = 6;  i < 12; i++) m[i]     = 'eth:Src MAC'
      for (let i = 12; i < 14; i++) m[i]     = 'eth:Type'
      off = 14

      const et = (bytes[12] << 8) | bytes[13]
      if (et === 0x0806 && bytes.length >= off + 28) {
        for (let i = off;    i < off+8;  i++) m[i] = 'arp:Operation'
        for (let i = off+8;  i < off+14; i++) m[i] = 'arp:Sender MAC'
        for (let i = off+14; i < off+18; i++) m[i] = 'arp:Sender IP'
        for (let i = off+18; i < off+24; i++) m[i] = 'arp:Target MAC'
        for (let i = off+24; i < off+28; i++) m[i] = 'arp:Target IP'
        return m
      }
      if (et !== 0x0800) return m
    }

    // IPv4
    if (bytes.length < off + 20) return m
    const ihl = (bytes[off] & 0x0f) * 4
    const ipProto = bytes[off + 9]
    // Map individual IP fields
    m[off]     = 'ip:Version/IHL'
    m[off + 1] = 'ip:DSCP/ECN'
    for (let i = off+2;  i < off+4;  i++) m[i] = 'ip:IP Length'
    for (let i = off+4;  i < off+6;  i++) m[i] = 'ip:Identification'
    for (let i = off+6;  i < off+8;  i++) m[i] = 'ip:Flags/Fragment'
    m[off + 8] = 'ip:TTL'
    m[off + 9] = 'ip:Protocol'
    for (let i = off+10; i < off+12; i++) m[i] = 'ip:Checksum'
    for (let i = off+12; i < off+16; i++) m[i] = 'ip:Source'
    for (let i = off+16; i < off+20; i++) m[i] = 'ip:Dest'
    if (ihl > 20) { for (let i = off+20; i < off+ihl; i++) m[i] = 'ip:Options' }
    off += ihl

    // Transport
    if (ipProto === 17 && bytes.length >= off + 8) {
      for (let i = off;   i < off+2; i++) m[i] = 'trans:Src Port'
      for (let i = off+2; i < off+4; i++) m[i] = 'trans:Dst Port'
      for (let i = off+4; i < off+6; i++) m[i] = 'trans:Length'
      for (let i = off+6; i < off+8; i++) m[i] = 'trans:Checksum'
      off += 8
    } else if (ipProto === 6 && bytes.length >= off + 20) {
      const tcpOff = ((bytes[off+12] >> 4) & 0xf) * 4
      for (let i = off;    i < off+2;  i++) m[i] = 'trans:Src Port'
      for (let i = off+2;  i < off+4;  i++) m[i] = 'trans:Dst Port'
      for (let i = off+4;  i < off+8;  i++) m[i] = 'trans:Seq'
      for (let i = off+8;  i < off+12; i++) m[i] = 'trans:Ack'
      m[off+12] = 'trans:Data Offset'
      m[off+13] = 'trans:Flags'
      for (let i = off+14; i < off+16; i++) m[i] = 'trans:Window'
      for (let i = off+16; i < off+18; i++) m[i] = 'trans:Checksum'
      for (let i = off+18; i < off+20; i++) m[i] = 'trans:Urgent'
      if (tcpOff > 20) { for (let i = off+20; i < Math.min(off+tcpOff, bytes.length); i++) m[i] = 'trans:Options' }
      off += tcpOff
    } else if (ipProto === 1 && bytes.length >= off + 8) {
      m[off]     = 'trans:Type'
      m[off + 1] = 'trans:Code'
      for (let i = off+2; i < off+4; i++) m[i] = 'trans:Checksum'
      for (let i = off+4; i < off+6; i++) m[i] = 'trans:ID'
      for (let i = off+6; i < off+8; i++) m[i] = 'trans:Seq'
      off += 8
    }

    // Payload — try NC-Frame field-level mapping
    if (off < bytes.length && pkt.decoded?.interpreterName === 'NC-Frame') {
      const payStart = off
      // NC-Frame: magic(2) + version(1) + count(1) + fields
      if (bytes.length >= payStart + 4 && bytes[payStart] === 0x4E && bytes[payStart+1] === 0x43) {
        for (let i = payStart; i < payStart + 4; i++) m[i] = 'payload:Header'
        let foff = payStart + 4
        const count = bytes[payStart + 3]
        for (let fi = 0; fi < count && foff < bytes.length; fi++) {
          const fieldStart = foff
          // key_len + key
          const kl = bytes[foff]; foff++
          if (foff + kl > bytes.length) break
          let keyStr = ''
          try { keyStr = new TextDecoder().decode(new Uint8Array(bytes.slice(foff, foff + kl))) } catch { break }
          foff += kl
          // tag
          if (foff >= bytes.length) break
          const tag = bytes[foff]; foff++
          // value width
          let vLen = 0
          if (tag === 0x01 || tag === 0x06 || tag === 0x08) vLen = 1
          else if (tag === 0x02 || tag === 0x09) vLen = 2
          else if (tag === 0x03 || tag === 0x04 || tag === 0x0A) vLen = 4
          else if (tag === 0x0B || tag === 0x0C || tag === 0x0D) vLen = 8
          else if (tag === 0x05) { // str
            if (foff >= bytes.length) break
            vLen = 1 + bytes[foff]
          } else if (tag === 0x07 || tag === 0x0E || tag === 0x0F) { // json, hex, strlong
            if (foff + 1 >= bytes.length) break
            vLen = 2 + ((bytes[foff] << 8) | bytes[foff + 1])
          } else break
          // Capture json content location before advancing foff
          const jsonContentStart = (tag === 0x07) ? foff + 2 : -1
          const jsonContentLen   = (tag === 0x07) ? vLen - 2  : 0
          if (foff + vLen > bytes.length) break
          foff += vLen
          const fieldId = `decoded:${keyStr}`
          for (let i = fieldStart; i < foff; i++) m[i] = fieldId
          // For json fields: override value bytes with per-key sub-path IDs
          if (tag === 0x07 && jsonContentLen > 0) {
            try {
              const js = new TextDecoder('utf-8', { fatal: false }).decode(
                new Uint8Array(bytes.slice(jsonContentStart, jsonContentStart + jsonContentLen))
              )
              _applyJsonSubMapping(bytes, m, jsonContentStart, js, fieldId)
            } catch { /* ignore malformed JSON */ }
          }
        }
      }
    } else if (off < bytes.length) {
      // Generic payload — mark as payload section
      for (let i = off; i < bytes.length; i++) if (!m[i]) m[i] = 'payload:Data'
    }
    return m
  }

  // ── Hex highlight state ──────────────────────────────────────────────────
  let hoveredFieldId: string | null = null

  function handleHexHover(byteIndex: number): void {
    const fieldId = _byteFieldMap[byteIndex] || null
    hoveredFieldId = fieldId
  }

  function handleHexLeave(): void {
    hoveredFieldId = null
  }

  // hoveredFieldId is used directly — tree fields use "sec:label" keys,
  // decoded fields use "decoded:fieldKey" keys, matching buildByteFieldMap()

  // ── Build 16-byte rows for the hex dump ────────────────────────────────────
  function hexRows(bytes: number[], lmap: LayerKey[]): { off: number; cells: HexCell[] }[] {
    const rows: { off: number; cells: HexCell[] }[] = []
    for (let i = 0; i < bytes.length; i += 16) {
      const cells: HexCell[] = bytes.slice(i, i + 16).map((b, j) => ({
        hex:   b.toString(16).padStart(2, '0'),
        ascii: b >= 32 && b < 127 ? String.fromCharCode(b) : '·',
        bg:    lmap[i + j] ? LAYER[lmap[i + j]!]?.bg ?? null : null,
        tip:   lmap[i + j] ? LAYER[lmap[i + j]!]?.label ?? '' : '',
        layer: lmap[i + j],
      }))
      while (cells.length < 16) cells.push(null)   // pad last row
      rows.push({ off: i, cells })
    }
    return rows
  }

  // ── Protocol tree builder ──────────────────────────────────────────────────
  interface TreeSection {
    id: string
    label: string
    color: string
    fields: [string, string][]
  }

  function buildTree(bytes: number[], pkt: Packet): TreeSection[] {
    const S: TreeSection[] = []
    const add = (id: string, label: string, color: string, fields: [string, string][]) =>
      S.push({ id, label, color, fields })

    add('frame', 'Frame', 'text-[var(--nc-fg-1)]', [
      ['Number',   `#${pkt.id}`],
      ['Captured', pkt.abs_time ?? pkt.timestamp],
      ['Wire len', `${pkt.length} bytes`],
    ])

    if (!bytes.length) return S

    let off = 0

    // ── Ethernet layer (only if the frame actually has one) ───────────────────
    if (hasEthHeader(bytes)) {
      if (bytes.length < 14) return S
      const dstMac = bytes.slice(0, 6).map(b => b.toString(16).padStart(2,'0')).join(':')
      const srcMac = bytes.slice(6,12).map(b => b.toString(16).padStart(2,'0')).join(':')
      const et     = (bytes[12] << 8) | bytes[13]
      add('eth', 'Ethernet II', 'text-[var(--nc-proto-eth)]', [
        ['Dst MAC', dstMac],
        ['Src MAC', srcMac],
        ['Type',    `0x${et.toString(16).padStart(4,'0')} (${et===0x0800?'IPv4':et===0x0806?'ARP':et===0x86dd?'IPv6':'?'})`],
      ])
      off = 14

      if (et === 0x0806 && bytes.length >= off + 28) {
        add('arp', 'Address Resolution Protocol', 'text-[var(--nc-proto-trans)]', [
          ['Operation',  bytes[off+7] === 1 ? 'Request' : 'Reply'],
          ['Sender MAC', bytes.slice(off+8, off+14).map(b=>b.toString(16).padStart(2,'0')).join(':')],
          ['Sender IP',  bytes.slice(off+14,off+18).join('.')],
          ['Target IP',  bytes.slice(off+24,off+28).join('.')],
        ])
        return S
      }
      if (et !== 0x0800) return S
    }

    // ── IPv4 layer ────────────────────────────────────────────────────────────
    if (bytes.length < off + 20) return S

    const ihl     = (bytes[off] & 0x0f) * 4
    const ipVer   = bytes[off] >> 4
    const totLen  = (bytes[off+2] << 8) | bytes[off+3]
    const ttl     = bytes[off+8]
    const ipProto = bytes[off+9]
    const srcIp   = bytes.slice(off+12,off+16).join('.')
    const dstIp   = bytes.slice(off+16,off+20).join('.')
    const ipIdent = (bytes[off+4] << 8) | bytes[off+5]
    const ipFlags = (bytes[off+6] << 8) | bytes[off+7]
    const ipCksum = (bytes[off+10] << 8) | bytes[off+11]
    add('ip', `Internet Protocol v${ipVer}`, 'text-[var(--nc-proto-ip)]', [
      ['Version/IHL',    `${ipVer} / ${ihl} bytes`],
      ['DSCP/ECN',       `0x${bytes[off+1].toString(16).padStart(2,'0')}`],
      ['IP Length',      `${totLen} bytes`],
      ['Identification', `0x${ipIdent.toString(16).padStart(4,'0')}`],
      ['Flags/Fragment', `0x${ipFlags.toString(16).padStart(4,'0')}`],
      ['TTL',            String(ttl)],
      ['Protocol',       `${ipProto} (${ipProto===6?'TCP':ipProto===17?'UDP':ipProto===1?'ICMP':'?'})`],
      ['Checksum',       `0x${ipCksum.toString(16).padStart(4,'0')}`],
      ['Source',         srcIp],
      ['Dest',           dstIp],
    ])
    off += ihl

    // ── Transport layer ───────────────────────────────────────────────────────
    if (ipProto === 17 && bytes.length >= off + 8) {
      const sp  = (bytes[off]<<8)|bytes[off+1]
      const dp  = (bytes[off+2]<<8)|bytes[off+3]
      const ul  = (bytes[off+4]<<8)|bytes[off+5]
      const ck  = `0x${((bytes[off+6]<<8)|bytes[off+7]).toString(16).padStart(4,'0')}`
      add('trans', 'User Datagram Protocol', 'text-[var(--nc-proto-trans)]', [
        ['Src Port', String(sp)],
        ['Dst Port', String(dp)],
        ['Length',   `${ul} bytes`],
        ['Checksum', ck],
      ])
      off += 8
    } else if (ipProto === 6 && bytes.length >= off + 20) {
      const sp     = (bytes[off]<<8)|bytes[off+1]
      const dp     = (bytes[off+2]<<8)|bytes[off+3]
      const seq    = ((bytes[off+4]<<24)|(bytes[off+5]<<16)|(bytes[off+6]<<8)|bytes[off+7])>>>0
      const ack    = ((bytes[off+8]<<24)|(bytes[off+9]<<16)|(bytes[off+10]<<8)|bytes[off+11])>>>0
      const fl     = bytes[off+13]
      const fnames = []
      if (fl&0x01) fnames.push('FIN')
      if (fl&0x02) fnames.push('SYN')
      if (fl&0x04) fnames.push('RST')
      if (fl&0x08) fnames.push('PSH')
      if (fl&0x10) fnames.push('ACK')
      if (fl&0x20) fnames.push('URG')
      const win = (bytes[off+14]<<8)|bytes[off+15]
      add('trans', 'Transmission Control Protocol', 'text-[var(--nc-proto-trans)]', [
        ['Src Port', String(sp)],
        ['Dst Port', String(dp)],
        ['Seq',      String(seq)],
        ['Ack',      String(ack)],
        ['Flags',    fnames.join(', ') || '(none)'],
        ['Window',   String(win)],
      ])
      off += ((bytes[off+12] >> 4) & 0xf) * 4
    } else if (ipProto === 1 && bytes.length >= off + 8) {
      const type = bytes[off]
      const code = bytes[off+1]
      const id   = (bytes[off+4]<<8)|bytes[off+5]
      const seq  = (bytes[off+6]<<8)|bytes[off+7]
      add('trans', 'Internet Control Message Protocol', 'text-[var(--nc-proto-trans)]', [
        ['Type', `${type} (${type===8?'Echo Request':type===0?'Echo Reply':'?'})`],
        ['Code', String(code)],
        ['ID',   `0x${id.toString(16).padStart(4,'0')}`],
        ['Seq',  String(seq)],
      ])
      off += 8
    }

    // ── Payload ───────────────────────────────────────────────────────────────
    if (off < bytes.length) {
      const pay = bytes.slice(off)
      const payFields: [string, string][] = [['Length', `${pay.length} bytes`]]
      if (pkt.decoded?.interpreterName === 'NC-Frame' && pay.length >= 4 && pay[0] === 0x4E && pay[1] === 0x43) {
        payFields.push(['Header', `NC-Frame v${pay[2]}, ${pay[3]} field${pay[3] !== 1 ? 's' : ''}`])
      }
      add('payload', `Data (${pay.length} bytes)`, 'text-[var(--nc-proto-payload)]', payFields)
    }
    return S
  }

  // ── Track mode ─────────────────────────────────────────────────────────────
  function enterTrack(): void {
    if (!p) return
    const fp: TrackFingerprint = {
      protocol:        p.protocol,
      src_ip:          p.src_ip,
      dst_ip:          p.dst_ip,
      src_port:        p.src_port,
      dst_port:        p.dst_port,
      interpreterName: p.decoded?.interpreterName,
    }
    trackPrev.set(null)
    trackFingerprint.set(fp)
    trackMode.set(true)
  }

  function exitTrack(): void {
    trackMode.set(false)
    trackFingerprint.set(null)
    trackPrev.set(null)
  }

  // Recursively collect the most-specific changed dot-paths within a value pair.
  // Returns leaf paths (e.g. "meta.fw") rather than parent paths ("meta") when
  // possible, so individual sub-rows can be highlighted instead of the whole dict/list.
  function collectChangedPaths(prev: DecodedValue, curr: DecodedValue, prefix: string): string[] {
    if (JSON.stringify(prev) === JSON.stringify(curr)) return []
    if (prev !== null && curr !== null &&
        typeof prev === 'object' && typeof curr === 'object' &&
        !Array.isArray(prev) && !Array.isArray(curr)) {
      const p = prev as Record<string, DecodedValue>
      const c = curr as Record<string, DecodedValue>
      const paths: string[] = []
      for (const k of new Set([...Object.keys(p), ...Object.keys(c)])) {
        const sub = `${prefix}.${k}`
        if (!(k in p) || !(k in c)) paths.push(sub)
        else paths.push(...collectChangedPaths(p[k], c[k], sub))
      }
      return paths.length ? paths : [prefix]
    }
    if (Array.isArray(prev) && Array.isArray(curr)) {
      const paths: string[] = []
      for (let i = 0; i < Math.max(prev.length, curr.length); i++) {
        const sub = `${prefix}.${i}`
        if (i >= prev.length || i >= curr.length) paths.push(sub)
        else paths.push(...collectChangedPaths(prev[i] as DecodedValue, curr[i] as DecodedValue, sub))
      }
      return paths.length ? paths : [prefix]
    }
    return [prefix]
  }

  // Diff: granular dot-paths whose value changed (e.g. "meta.fw", not just "meta")
  $: diffChanged = (() => {
    if (!$trackMode || !$trackPrev?.decoded || !decoded) return new Set<string>()
    const prevMap = new Map($trackPrev.decoded.fields.map(f => [f.key, f.value]))
    const paths: string[] = []
    for (const f of decoded.fields) {
      if (!prevMap.has(f.key)) continue
      paths.push(...collectChangedPaths(prevMap.get(f.key)!, f.value, f.key))
    }
    return new Set(paths)
  })()

  // New keys: present in current but absent in previous
  $: diffNew = (() => {
    if (!$trackMode || !$trackPrev?.decoded || !decoded) return new Set<string>()
    const prevKeys = new Set($trackPrev.decoded.fields.map(f => f.key))
    return new Set(decoded.fields.filter(f => !prevKeys.has(f.key)).map(f => f.key))
  })()

  // ── Reactive derivations ───────────────────────────────────────────────────
  $: p             = $selectedPacket
  $: bytes         = toBytes(p?.raw_hex ?? '')
  $: lmap          = layerMap(bytes)
  $: rows          = hexRows(bytes, lmap)
  $: tree          = p ? buildTree(bytes, p) : []
  $: decoded       = p?.decoded ?? null
  $: _byteFieldMap = p ? buildByteFieldMap(bytes, p) : []
  // Clear highlight when packet changes
  $: if (p) hoveredFieldId = null

  // Previous packet data for track-mode diffing
  $: prevBytes = $trackPrev ? toBytes($trackPrev.raw_hex ?? '') : []
  $: prevTree  = ($trackMode && $trackPrev) ? buildTree(prevBytes, $trackPrev) : []

  // Byte indices that differ between current and previous raw bytes
  $: changedByteIndices = (() => {
    if (!$trackMode || !$trackPrev || !bytes.length) return new Set<number>()
    const s = new Set<number>()
    for (let i = 0; i < Math.max(bytes.length, prevBytes.length); i++) {
      if (bytes[i] !== prevBytes[i]) s.add(i)
    }
    return s
  })()

  // Protocol-tree field diff: "sectionId:label" -> previous value
  $: prevTreeMap = (() => {
    const m = new Map<string, string>()
    for (const sec of prevTree) {
      for (const [label, value] of sec.fields) {
        m.set(`${sec.id}:${label}`, value)
      }
    }
    return m
  })()
  // Only show toggles for layers that actually appear in this packet's bytes
  $: presentLayers = (Object.keys(LAYER) as (keyof typeof LAYER)[]).filter(k => lmap.includes(k))

  let expanded: Record<string, boolean> = {}

  function toggle(id: string): void { expanded = { ...expanded, [id]: !(expanded[id] ?? true) } }
  $: open = (id: string): boolean => expanded[id] ?? true

  // ── Layer visibility (persists across packet selections) ───────────────────
  // Stored as plain object so Svelte reactivity picks up assignments
  let activeLayers = { eth: true, ip: true, trans: true, payload: true }
  function toggleLayer(key: keyof typeof activeLayers): void {
    activeLayers = { ...activeLayers, [key]: !activeLayers[key] }
  }

  // Helper: style for a hex/ascii cell given current layer visibility
  function cellStyle(cell: HexCell, isActive: boolean): string {
    if (!cell) return ''
    return isActive && cell.bg ? `background:${cell.bg}` : ''
  }

  // Highlight uses the same blue as row selection in the frame table
  const HIGHLIGHT_BG = 'background:var(--nc-row-selected);color:#fff'

  const _STRUCT = '.__struct'

  function fieldMatches(fieldId: string, hovered: string | null): boolean {
    if (!hovered || !fieldId) return false
    if (fieldId === hovered) return true
    // Hovering a parent/name → all child bytes light up (sub-items + .__struct)
    if (fieldId.startsWith(hovered + '.')) return true
    // Hovering structural bytes → also light up the immediate parent name/header bytes
    if (hovered.endsWith(_STRUCT) && fieldId === hovered.slice(0, -_STRUCT.length)) return true
    return false
  }

  function hexCellStyle(cell: HexCell, on: boolean, hexDiff: boolean, byteIdx: number, hovered: string | null): string {
    const fieldId = _byteFieldMap[byteIdx] || ''
    if (fieldMatches(fieldId, hovered)) return HIGHLIGHT_BG
    if (hexDiff) return 'background:color-mix(in srgb,var(--nc-status-err) 28%,transparent)'
    const base = cellStyle(cell, on)
    return !on ? base + ';opacity:0.18' : base
  }

  function asciiCellStyle(cell: HexCell, on: boolean, hexDiff: boolean, byteIdx: number, hovered: string | null): string {
    const fieldId = _byteFieldMap[byteIdx] || ''
    if (fieldMatches(fieldId, hovered)) return HIGHLIGHT_BG
    if (hexDiff) return 'background:color-mix(in srgb,var(--nc-status-err) 28%,transparent)'
    const base = cellStyle(cell, on)
    return !on ? base + ';opacity:0.18' : base
  }

  // ── Panel resize drag (vertical — overall detail panel height) ────────────
  let height:   number  = parseInt(localStorage.getItem('nc:detailHeight') ?? '280', 10)
  let dragging: boolean = false
  let startY:   number  = 0
  let startH:   number  = 0

  function dragStart(e: MouseEvent): void {
    dragging = true
    startY   = e.clientY
    startH   = height
    e.preventDefault()
  }

  function dragMove(e: MouseEvent): void {
    if (dragging) {
      height = Math.max(120, Math.min(window.innerHeight - 120, startH + (startY - e.clientY)))
    }
    if (treeDragging) {
      const dx = e.clientX - treeDragStartX
      treeWidth = Math.max(80, Math.min(600, treeDragStartW + dx))
    }
    if (decodedDragging) {
      const dx = e.clientX - decodedDragStartX
      decodedWidth = Math.max(120, Math.min(600, decodedDragStartW + dx))
    }
    if (_colDragging) {
      const dx = e.clientX - _colDragStartX
      if (_colDragging === 'key')  decColKey  = Math.max(40, Math.min(200, _colDragStartW + dx))
      if (_colDragging === 'type') decColType = Math.max(28, Math.min(100, _colDragStartW + dx))
    }
  }

  function dragEnd() {
    if (dragging) localStorage.setItem('nc:detailHeight', String(height))
    dragging = false
    if (treeDragging) localStorage.setItem('nc:treeWidth', String(treeWidth))
    treeDragging = false
    if (decodedDragging) {
      localStorage.setItem(_DECODED_WIDTH_KEY, String(decodedWidth))
    }
    decodedDragging = false
    if (_colDragging) {
      localStorage.setItem('nc:decColKey',  String(decColKey))
      localStorage.setItem('nc:decColType', String(decColType))
      _colDragging = null
    }
  }

  // ── Protocol tree width drag (horizontal) ──────────────────────────────────
  let treeWidth:      number  = (() => {
    const saved = parseInt(localStorage.getItem('nc:treeWidth') ?? '', 10)
    return isNaN(saved) ? 224 : Math.max(80, Math.min(600, saved))
  })()
  let treeDragging:   boolean = false
  let treeDragStartX: number  = 0
  let treeDragStartW: number  = 0

  function treeDragStart(e: MouseEvent): void {
    treeDragging   = true
    treeDragStartX = e.clientX
    treeDragStartW = treeWidth
    e.preventDefault()
  }

  // ── Decoded panel width drag (horizontal) ──────────────────────────────────
  const _DECODED_WIDTH_KEY = 'nc:decodedWidth'
  let decodedWidth:      number  = (() => {
    const saved = parseInt(localStorage.getItem(_DECODED_WIDTH_KEY) ?? '', 10)
    return isNaN(saved) ? 224 : Math.max(120, Math.min(600, saved))
  })()
  let decodedDragging:   boolean = false
  let decodedDragStartX: number  = 0
  let decodedDragStartW: number  = 0

  function decodedDragStart(e: MouseEvent): void {
    decodedDragging   = true
    decodedDragStartX = e.clientX
    decodedDragStartW = decodedWidth
    e.preventDefault()
  }

  // ── Decoded column widths (key | type | value) ─────────────────────────────
  let decColKey  = Math.max(40,  Math.min(200, parseInt(localStorage.getItem('nc:decColKey')  ?? '72',  10)))
  let decColType = Math.max(28,  Math.min(100, parseInt(localStorage.getItem('nc:decColType') ?? '44',  10)))
  let _colDragging: 'key' | 'type' | null = null
  let _colDragStartX = 0
  let _colDragStartW = 0

  function colDragStart(e: MouseEvent, col: 'key' | 'type'): void {
    _colDragging  = col
    _colDragStartX = e.clientX
    _colDragStartW = col === 'key' ? decColKey : decColType
    e.preventDefault()
  }
</script>

<svelte:window on:mousemove={dragMove} on:mouseup={dragEnd} />

{#if fieldCtxMenu}
  <ContextMenu x={fieldCtxMenu.x} y={fieldCtxMenu.y} items={fieldCtxMenu.items} on:close={() => fieldCtxMenu = null} />
{/if}

{#if p}
<div
  class="shrink-0 flex flex-col border-t border-(--nc-border) bg-(--nc-surface-1) font-mono text-xs"
  style="height:{height}px"
>
  <!-- ── Drag handle ─────────────────────────────────────────────────────── -->
  <button
    class="h-1.5 w-full shrink-0 flex items-center justify-center bg-(--nc-surface)
           cursor-ns-resize hover:bg-(--nc-surface-2) transition-colors group border-none p-0"
    on:mousedown={dragStart}
    aria-label="Drag to resize panel"
  >
    <div class="w-10 h-0.5 rounded-full bg-(--nc-border) group-hover:bg-(--nc-fg-3) transition-colors"></div>
  </button>
  <!-- ── Header ──────────────────────────────────────────────────────────── -->
  <div class="flex items-center gap-2 px-3 py-1.5 bg-(--nc-surface) border-b border-(--nc-border) shrink-0 flex-wrap">
    <span class="text-(--nc-fg-4) text-[10px] uppercase tracking-wider">Frame #{p.id}</span>
    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold text-white"
      style={badge(p.protocol)}>{p.protocol}</span>
    <span class="text-(--nc-fg-4)">{p.abs_time ?? p.timestamp}</span>

    <!-- Track mode controls -->
    {#if $trackMode}
      <div class="flex items-center gap-1.5 ml-1">
        <button
          class="text-[10px] px-1.5 py-0.5 rounded border border-(--nc-border) text-(--nc-fg-3)
                 hover:border-(--nc-status-err) hover:text-(--nc-status-err) transition-colors"
          on:click={exitTrack}
        >Stop</button>
        <div class="w-1.5 h-1.5 rounded-full {TRACK_DOT[trackState]}"></div>
        <span class="text-[10px] font-semibold uppercase tracking-wider"
          style="color:{TRACK_COLOR[trackState]}">{trackLabel}</span>
      </div>
    {:else}
      <button
        class="text-[10px] px-1.5 py-0.5 ml-1 rounded border border-(--nc-border) text-(--nc-fg-3)
               hover:border-(--nc-status-ok) hover:text-(--nc-status-ok) transition-colors"
        on:click={enterTrack}
        title="Auto-select new packets matching this type"
      >Track</button>
    {/if}

    {#if bytes.length > 0}
      <!-- Layer toggle buttons — only for layers present in this packet -->
      <div class="flex items-center gap-1 ml-2">
        {#each presentLayers as key}
          {@const l = LAYER[key]}
          {@const on = activeLayers[key]}
          <button
            class="flex items-center gap-1 px-1.5 py-0.5 rounded border transition-all select-none
                   {on ? 'opacity-100' : 'opacity-35'}"
            style="border-color:{on ? 'color-mix(in srgb,' + l.dot + ' 30%, transparent)' : 'var(--nc-border)'}"
            on:click={() => toggleLayer(key)}
            title="{on ? 'Hide' : 'Show'} {l.label}"
          >
            <div class="w-2 h-2 rounded-sm border shrink-0 transition-all"
              style="background:{on ? l.bg : 'transparent'}; border-color:color-mix(in srgb,{l.dot} 53%, transparent)"></div>
            <span class="text-[10px] text-(--nc-fg-2)">{l.label}</span>
          </button>
        {/each}
      </div>
    {:else}
      <span class="text-(--nc-fg-4) italic ml-2 text-[10px]">
        raw bytes unavailable — backend capture required
      </span>
    {/if}

    <button
      class="ml-auto text-(--nc-fg-4) hover:text-(--nc-fg-2) transition-colors px-1"
      on:click={() => { exitTrack(); selectedPacket.set(null) }}
    >✕</button>
  </div>

  <!-- ── Issue banner (checksum failures, decoder errors) ───────────────── -->
  {#if p.warnings?.length || p.decoded?.error}
    <div class="shrink-0 flex items-start gap-2 px-3 py-1.5 border-b border-(--nc-border)
                bg-[color-mix(in_srgb,var(--nc-status-err)_8%,transparent)]">
      <span class="shrink-0 font-bold text-[11px] leading-tight mt-px
                   {p.decoded?.error ? 'text-(--nc-status-err)' : 'text-amber-400'}">⚠</span>
      <div class="flex flex-col gap-0.5 min-w-0">
        {#each (p.warnings ?? []) as w}
          <span class="text-[10px] text-amber-400">{w}</span>
        {/each}
        {#if p.decoded?.error}
          <span class="text-[10px] text-(--nc-status-err)">Decoder: {p.decoded.error}</span>
        {/if}
      </div>
    </div>
  {/if}

  <!-- ── Body: protocol tree | hex dump ─────────────────────────────────── -->
  <div class="flex flex-1 min-h-0">

    <!-- Protocol tree (left panel) -->
    <div class="shrink-0 overflow-y-auto" style="width:{treeWidth}px">
      {#each tree as sec}
        <div>
          <button
            class="flex w-full items-center gap-1 px-2 py-0.5 hover:bg-(--nc-surface-2) transition-colors text-left"
            on:click={() => toggle(sec.id)}
          >
            <span class="text-(--nc-fg-4) text-[10px] w-3 shrink-0">{open(sec.id) ? '▼' : '▶'}</span>
            <span class="{sec.color} font-semibold truncate text-[11px]">{sec.label}</span>
          </button>
          {#if open(sec.id)}
            <div class="ml-4 border-l border-(--nc-border-2) pl-2 pb-0.5">
              {#each sec.fields as [label, value]}
                {@const prevVal     = prevTreeMap.get(`${sec.id}:${label}`)}
                {@const treeChanged = $trackMode && prevVal !== undefined && prevVal !== value}
                {@const treeFieldId = `${sec.id}:${label}`}
                {@const treeHighlit = hoveredFieldId === treeFieldId}
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <div class="flex gap-1 py-px leading-4"
                  style={treeHighlit ? HIGHLIGHT_BG
                        : treeChanged ? 'background:color-mix(in srgb,var(--nc-status-err) 18%,transparent)' : ''}
                  on:mouseenter={() => { hoveredFieldId = treeFieldId }}
                  on:mouseleave={() => { if (hoveredFieldId === treeFieldId) hoveredFieldId = null }}
>
                  <span class="shrink-0 w-18 truncate" style={treeHighlit ? 'color:#fff' : 'color:var(--nc-fg-3)'}>{label}</span>
                  <span class="break-all" style={treeHighlit ? 'color:#fff' : 'color:var(--nc-fg-1)'}>{value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <!-- Drag handle between tree and decoded/hex panels -->
    <button
      class="w-1 shrink-0 cursor-col-resize hover:bg-blue-500/30 transition-colors bg-(--nc-border) border-none p-0"
      on:mousedown={treeDragStart}
      aria-label="Resize protocol tree panel"
    ></button>

    <!-- Decoded panel — only shown when an interpreter matches -->
    {#if decoded}
      <div class="shrink-0 border-r border-(--nc-border) overflow-y-auto flex flex-col"
        style="width:{decodedWidth}px">
        <!-- Header -->
        <div class="px-2 py-1 bg-(--nc-surface) border-b border-(--nc-border) shrink-0
                    flex items-center gap-1.5 min-w-0">
          <span class="text-(--nc-fg-4) text-[10px] shrink-0">&#9670;</span>
          <span class="text-(--nc-fg-2) text-[10px] font-semibold uppercase tracking-wider truncate">
            {decoded.interpreterName}
          </span>
          {#if decoded.payloadOffset != null}
            <span
              class="ml-auto shrink-0 text-(--nc-fg-2) text-[9px] font-mono
                     bg-(--nc-surface-2) rounded px-1 py-px"
              title="Byte offset in the raw frame where this interpreter's payload starts">
              @ 0x{decoded.payloadOffset.toString(16).padStart(2, '0')}
            </span>
          {/if}
        </div>

        {#if decoded.error}
          <div class="px-2 py-1.5 text-(--nc-status-err) text-[10px] italic">
            {decoded.error}
          </div>
        {:else}
          <div class="flex-1 overflow-y-auto overflow-x-hidden flex flex-col">
            <!-- Column headers -->
            <div class="flex items-center shrink-0 border-b border-(--nc-border) bg-(--nc-surface) sticky top-0 z-10 select-none">
              <span class="shrink-0 px-1.5 py-0.5 text-[9px] text-(--nc-fg-3) uppercase tracking-wider truncate"
                style="width:{decColKey}px">Field</span>
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="w-px self-stretch bg-(--nc-border) shrink-0 cursor-col-resize hover:bg-blue-400/60 transition-colors"
                on:mousedown={(e) => colDragStart(e, 'key')}></div>
              <span class="shrink-0 px-1.5 py-0.5 text-[9px] text-(--nc-fg-3) uppercase tracking-wider truncate"
                style="width:{decColType}px">Type</span>
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="w-px self-stretch bg-(--nc-border) shrink-0 cursor-col-resize hover:bg-blue-400/60 transition-colors"
                on:mousedown={(e) => colDragStart(e, 'type')}></div>
              <span class="px-1.5 py-0.5 text-[9px] text-(--nc-fg-3) uppercase tracking-wider">Value</span>
            </div>
            <!-- Rows -->
            {#each decoded.fields as f}
              {@const changed = diffChanged.has(f.key)}
              {@const isNew   = diffNew.has(f.key)}
              {@const decFieldId = `decoded:${f.key}`}
              {@const decHighlit = hoveredFieldId === decFieldId || hoveredFieldId === decFieldId + '.__struct'}
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="flex items-baseline border-b border-(--nc-border-1) last:border-0 group/field"
                style={decHighlit ? HIGHLIGHT_BG
                      : changed ? 'background:color-mix(in srgb,var(--nc-status-err) 18%,transparent)'
                      : isNew   ? 'background:color-mix(in srgb,var(--nc-status-ok)   14%,transparent)'
                      : ''}
                on:mouseenter={() => { hoveredFieldId = decFieldId }}
                on:mouseleave={() => {
                  if (hoveredFieldId === decFieldId || hoveredFieldId?.startsWith(decFieldId + '.'))
                    hoveredFieldId = null
                }}
                on:contextmenu|stopPropagation={(e) => openFieldMenu(e, f.key, f.value)}>
                <!-- Key -->
                <span class="shrink-0 px-1.5 py-0.5 text-[10px] truncate"
                  style="width:{decColKey}px; {decHighlit ? 'color:#fff' : 'color:var(--nc-fg-3)'}"
                  title={f.key}>{f.key}</span>
                <div class="w-px self-stretch shrink-0" style="background:var(--nc-border-2)"></div>
                <!-- Type -->
                <span class="shrink-0 px-1.5 py-0.5 text-[9px] font-mono truncate"
                  style="width:{decColType}px; {decHighlit ? 'color:#fff' : 'color:var(--nc-fg-3)'}"
                  title={f.type}>{f.type}</span>
                <div class="w-px self-stretch shrink-0" style="background:var(--nc-border-2)"></div>
                <!-- Value -->
                <div class="min-w-0 flex-1 px-1.5 py-0.5">
                  <FieldValue value={f.value} fieldPath={f.key}
                    structMode={hoveredFieldId === decFieldId + '.__struct'}
                    hoveredPath={hoveredFieldId?.startsWith('decoded:') ? hoveredFieldId.slice(8) : null}
                    changedPaths={diffChanged}
                    newPaths={diffNew}
                    onhover={(subPath) => { hoveredFieldId = 'decoded:' + subPath }}
                    onleave={(subPath) => {
                      if (hoveredFieldId === 'decoded:' + subPath) {
                        const dot = subPath.lastIndexOf('.')
                        hoveredFieldId = dot >= 0 ? 'decoded:' + subPath.slice(0, dot) : decFieldId
                      }
                    }}
                    oncontext={(e, subPath, subVal) => openFieldMenu(e, subPath, subVal)} />
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <!-- Drag handle between decoded and hex panels -->
      <button
        class="w-1 shrink-0 cursor-col-resize hover:bg-blue-500/30 transition-colors bg-(--nc-border) border-none p-0"
        on:mousedown={decodedDragStart}
        aria-label="Resize decoded panel"
      ></button>
    {/if}

    <!-- Hex dump panel -->
    <div class="overflow-auto p-2 shrink-0">
      {#if bytes.length > 0}
        <table class="border-separate border-spacing-0 leading-5">
          <tbody>
            {#each rows as row}
              <tr>
                <!-- Offset -->
                <td class="text-(--nc-fg-5) select-none pr-3 text-right whitespace-nowrap">
                  {row.off.toString(16).padStart(4, '0')}
                </td>

                <!-- First 8 hex bytes -->
                {#each row.cells.slice(0, 8) as cell, j}
                  {@const byteIdx = row.off + j}
                  {@const on      = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  {@const hexDiff = $trackMode && changedByteIndices.has(byteIdx)}
                  <!-- svelte-ignore a11y-no-static-element-interactions -->
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style={hexCellStyle(cell, on, hexDiff, byteIdx, hoveredFieldId)}
                    title={cell?.tip ?? ''}
                    on:mouseenter={() => { if (cell) handleHexHover(byteIdx) }}
                    on:mouseleave={handleHexLeave}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- Mid-gap -->
                <td class="w-3"></td>

                <!-- Second 8 hex bytes -->
                {#each row.cells.slice(8, 16) as cell, j}
                  {@const byteIdx = row.off + 8 + j}
                  {@const on      = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  {@const hexDiff = $trackMode && changedByteIndices.has(byteIdx)}
                  <!-- svelte-ignore a11y-no-static-element-interactions -->
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style={hexCellStyle(cell, on, hexDiff, byteIdx, hoveredFieldId)}
                    title={cell?.tip ?? ''}
                    on:mouseenter={() => { if (cell) handleHexHover(byteIdx) }}
                    on:mouseleave={handleHexLeave}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- ASCII column -->
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <td class="pl-4 select-none whitespace-pre tracking-wide" style="color:var(--nc-fg-1)">
                  {#each row.cells as cell, j}
                    {#if cell}
                      {@const byteIdx = row.off + j}
                      {@const on      = cell.layer ? activeLayers[cell.layer] ?? true : true}
                      {@const hexDiff = $trackMode && changedByteIndices.has(byteIdx)}
                      {@const aStyle  = asciiCellStyle(cell, on, hexDiff, byteIdx, hoveredFieldId)}
                      <span style={aStyle} title={cell.tip}
                        on:mouseenter={() => handleHexHover(byteIdx)}
                        on:mouseleave={handleHexLeave}>{cell.ascii}</span>
                    {:else}
                      <span class="invisible">.</span>
                    {/if}
                  {/each}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <div class="flex items-center justify-center h-full text-(--nc-fg-4) italic select-none">
          No raw bytes — start a backend capture to inspect packet data.
        </div>
      {/if}
    </div>
  </div>
</div>
{/if}
