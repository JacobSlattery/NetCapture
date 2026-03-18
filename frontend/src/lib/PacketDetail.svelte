<script lang="ts">
  import { selectedPacket, trackMode, trackFingerprint, trackPrev } from '../stores'
  import type { Packet, TrackFingerprint } from '../types'
  import FieldValue from './FieldValue.svelte'

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
    add('ip', `Internet Protocol v${ipVer}`, 'text-[var(--nc-proto-ip)]', [
      ['Source',    srcIp],
      ['Dest',      dstIp],
      ['TTL',       String(ttl)],
      ['Protocol',  `${ipProto} (${ipProto===6?'TCP':ipProto===17?'UDP':ipProto===1?'ICMP':'?'})`],
      ['IP Length', `${totLen} bytes`],
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
      const pre = pay.slice(0, 24).map(b => b.toString(16).padStart(2,'0')).join(' ')
      add('payload', `Data (${pay.length} bytes)`, 'text-[var(--nc-proto-payload)]', [
        ['Length',  `${pay.length} bytes`],
        ['Preview', pre + (pay.length > 24 ? ' …' : '')],
      ])
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

  // Diff: keys whose value changed from previous tracked packet
  $: diffChanged = (() => {
    if (!$trackMode || !$trackPrev?.decoded || !decoded) return new Set<string>()
    const prevMap = new Map($trackPrev.decoded.fields.map(f => [f.key, f.value]))
    return new Set(
      decoded.fields
        .filter(f => prevMap.has(f.key) && JSON.stringify(prevMap.get(f.key)) !== JSON.stringify(f.value))
        .map(f => f.key)
    )
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

  // ── Panel resize drag (vertical — overall detail panel height) ────────────
  let height:   number  = 280
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
    if (decodedDragging) {
      const dx = e.clientX - decodedDragStartX
      decodedWidth = Math.max(120, Math.min(600, decodedDragStartW + dx))
    }
  }

  function dragEnd() { dragging = false; decodedDragging = false }

  // ── Decoded panel width drag (horizontal) ──────────────────────────────────
  let decodedWidth:      number  = 224   // default = w-56
  let decodedDragging:   boolean = false
  let decodedDragStartX: number  = 0
  let decodedDragStartW: number  = 0

  function decodedDragStart(e: MouseEvent): void {
    decodedDragging   = true
    decodedDragStartX = e.clientX
    decodedDragStartW = decodedWidth
    e.preventDefault()
  }
</script>

<svelte:window on:mousemove={dragMove} on:mouseup={dragEnd} />

{#if p}
<div
  class="shrink-0 flex flex-col border-t border-[var(--nc-border)] bg-[var(--nc-surface-1)] font-mono text-xs"
  style="height:{height}px"
>
  <!-- ── Drag handle ─────────────────────────────────────────────────────── -->
  <button
    class="h-1.5 w-full shrink-0 flex items-center justify-center bg-[var(--nc-surface)]
           cursor-ns-resize hover:bg-[var(--nc-surface-2)] transition-colors group border-none p-0"
    on:mousedown={dragStart}
    aria-label="Drag to resize panel"
  >
    <div class="w-10 h-0.5 rounded-full bg-[var(--nc-border)] group-hover:bg-[var(--nc-fg-3)] transition-colors"></div>
  </button>
  <!-- ── Header ──────────────────────────────────────────────────────────── -->
  <div class="flex items-center gap-2 px-3 py-1.5 bg-[var(--nc-surface)] border-b border-[var(--nc-border)] shrink-0 flex-wrap">
    <span class="text-[var(--nc-fg-4)] text-[10px] uppercase tracking-wider">Frame #{p.id}</span>
    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold text-white"
      style={badge(p.protocol)}>{p.protocol}</span>
    <span class="text-[var(--nc-fg-4)]">{p.abs_time ?? p.timestamp}</span>

    <!-- Track mode controls -->
    {#if $trackMode}
      <div class="flex items-center gap-1.5">
        <div class="w-1.5 h-1.5 rounded-full bg-[var(--nc-status-ok)] animate-pulse"></div>
        <span class="text-[var(--nc-status-ok)] text-[10px] font-semibold uppercase tracking-wider">Tracking</span>
        <button
          class="text-[10px] px-1.5 py-0.5 rounded border border-[var(--nc-border)] text-[var(--nc-fg-3)]
                 hover:border-[var(--nc-status-err)] hover:text-[var(--nc-status-err)] transition-colors"
          on:click={exitTrack}
        >Stop</button>
      </div>
    {:else}
      <button
        class="text-[10px] px-1.5 py-0.5 rounded border border-[var(--nc-border)] text-[var(--nc-fg-3)]
               hover:border-[var(--nc-status-ok)] hover:text-[var(--nc-status-ok)] transition-colors"
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
            <span class="text-[10px] text-[var(--nc-fg-2)]">{l.label}</span>
          </button>
        {/each}
      </div>
    {:else}
      <span class="text-[var(--nc-fg-5)] italic ml-2 text-[10px]">
        raw bytes unavailable — backend capture required
      </span>
    {/if}

    <button
      class="ml-auto text-[var(--nc-fg-5)] hover:text-[var(--nc-fg-2)] transition-colors px-1"
      on:click={() => { exitTrack(); selectedPacket.set(null) }}
    >✕</button>
  </div>

  <!-- ── Body: protocol tree | hex dump ─────────────────────────────────── -->
  <div class="flex flex-1 min-h-0">

    <!-- Protocol tree (left panel) -->
    <div class="w-56 shrink-0 border-r border-[var(--nc-border)] overflow-y-auto">
      {#each tree as sec}
        <div>
          <button
            class="flex w-full items-center gap-1 px-2 py-0.5 hover:bg-[var(--nc-surface-2)] transition-colors text-left"
            on:click={() => toggle(sec.id)}
          >
            <span class="text-[var(--nc-fg-5)] text-[10px] w-3 shrink-0">{open(sec.id) ? '▼' : '▶'}</span>
            <span class="{sec.color} font-semibold truncate text-[11px]">{sec.label}</span>
          </button>
          {#if open(sec.id)}
            <div class="ml-4 border-l border-[var(--nc-border-2)] pl-2 pb-0.5">
              {#each sec.fields as [label, value]}
                {@const prevVal     = prevTreeMap.get(`${sec.id}:${label}`)}
                {@const treeChanged = $trackMode && prevVal !== undefined && prevVal !== value}
                <div class="flex gap-1 py-px leading-4"
                  style={treeChanged ? 'background:color-mix(in srgb,var(--nc-status-err) 18%,transparent)' : ''}>
                  <span class="text-[var(--nc-fg-3)] shrink-0 w-[4.5rem] truncate">{label}</span>
                  <span class="text-[var(--nc-fg-1)] break-all">{value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <!-- Decoded panel — only shown when an interpreter matches -->
    {#if decoded}
      <div class="shrink-0 border-r border-[var(--nc-border)] overflow-y-auto flex flex-col"
        style="width:{decodedWidth}px">
        <!-- Header -->
        <div class="px-2 py-1 bg-[var(--nc-surface)] border-b border-[var(--nc-border)] shrink-0
                    flex items-center gap-1.5">
          <span class="text-[var(--nc-fg-5)] text-[10px]">&#9670;</span>
          <span class="text-[var(--nc-fg-2)] text-[10px] font-semibold uppercase tracking-wider">
            {decoded.interpreterName}
          </span>
        </div>

        {#if decoded.error}
          <div class="px-2 py-1.5 text-[var(--nc-status-err)] text-[10px] italic">
            {decoded.error}
          </div>
        {:else}
          <div class="flex-1 overflow-y-auto">
            {#each decoded.fields as f}
              {@const changed = diffChanged.has(f.key)}
              {@const isNew   = diffNew.has(f.key)}
              <div class="flex items-baseline gap-1 px-2 py-0.5 border-b border-[var(--nc-border-1)] last:border-0"
                style={changed ? 'background:color-mix(in srgb,var(--nc-status-err) 18%,transparent)'
                      : isNew   ? 'background:color-mix(in srgb,var(--nc-status-ok)   14%,transparent)'
                      : ''}>
                <span class="text-[var(--nc-fg-3)] text-[10px] shrink-0 w-[4.5rem] truncate">{f.key}</span>
                <FieldValue value={f.value} />
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <!-- Drag handle between decoded and hex panels -->
      <button
        class="w-1 shrink-0 cursor-col-resize hover:bg-blue-500/30 transition-colors bg-[var(--nc-border)] border-none p-0"
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
                <td class="text-[var(--nc-fg-5)] select-none pr-3 text-right whitespace-nowrap">
                  {row.off.toString(16).padStart(4, '0')}
                </td>

                <!-- First 8 hex bytes -->
                {#each row.cells.slice(0, 8) as cell, j}
                  {@const on      = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  {@const hexDiff = $trackMode && changedByteIndices.has(row.off + j)}
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style="{hexDiff ? 'background:color-mix(in srgb,var(--nc-status-err) 28%,transparent)' : cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
                    title={cell?.tip ?? ''}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- Mid-gap -->
                <td class="w-3"></td>

                <!-- Second 8 hex bytes -->
                {#each row.cells.slice(8, 16) as cell, j}
                  {@const on      = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  {@const hexDiff = $trackMode && changedByteIndices.has(row.off + 8 + j)}
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style="{hexDiff ? 'background:color-mix(in srgb,var(--nc-status-err) 28%,transparent)' : cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
                    title={cell?.tip ?? ''}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- ASCII column -->
                <td class="pl-4 text-[var(--nc-fg-4)] select-none whitespace-pre tracking-wide">
                  {#each row.cells as cell, j}
                    {#if cell}
                      {@const on      = cell.layer ? activeLayers[cell.layer] ?? true : true}
                      {@const hexDiff = $trackMode && changedByteIndices.has(row.off + j)}
                      <span
                        style="{hexDiff ? 'background:color-mix(in srgb,var(--nc-status-err) 28%,transparent)' : cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
                        title={cell.tip}
                      >{cell.ascii}</span>
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
        <div class="flex items-center justify-center h-full text-[var(--nc-fg-5)] italic select-none">
          No raw bytes — start a backend capture to inspect packet data.
        </div>
      {/if}
    </div>
  </div>
</div>
{/if}
