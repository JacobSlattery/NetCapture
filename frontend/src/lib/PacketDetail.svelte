<script lang="ts">
  import { selectedPacket } from '../stores'
  import type { Packet } from '../types'

  // ── Layer colour definitions ───────────────────────────────────────────────
  const LAYER = {
    eth:     { bg: 'rgba(59,130,246,0.20)',  dot: '#3b82f6', label: 'Ethernet'   },
    ip:      { bg: 'rgba(16,185,129,0.20)',  dot: '#10b981', label: 'IPv4'       },
    trans:   { bg: 'rgba(245,158,11,0.20)',  dot: '#f59e0b', label: 'Transport'  },
    payload: { bg: 'rgba(139,92,246,0.20)',  dot: '#8b5cf6', label: 'Payload'    },
  }

  const BADGE = {
    TCP:'bg-blue-600', UDP:'bg-green-600', DNS:'bg-purple-600',
    ICMP:'bg-amber-600', HTTP:'bg-orange-600', HTTPS:'bg-cyan-600',
    TLS:'bg-cyan-600', ARP:'bg-pink-600',
  }
  const badge = (p: string): string => BADGE[p as keyof typeof BADGE] ?? 'bg-gray-600'

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
      add('eth', 'Ethernet II', 'text-blue-300', [
        ['Dst MAC', dstMac],
        ['Src MAC', srcMac],
        ['Type',    `0x${et.toString(16).padStart(4,'0')} (${et===0x0800?'IPv4':et===0x0806?'ARP':et===0x86dd?'IPv6':'?'})`],
      ])
      off = 14

      if (et === 0x0806 && bytes.length >= off + 28) {
        add('arp', 'Address Resolution Protocol', 'text-amber-300', [
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
    add('ip', `Internet Protocol v${ipVer}`, 'text-green-300', [
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
      add('trans', 'User Datagram Protocol', 'text-amber-300', [
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
      add('trans', 'Transmission Control Protocol', 'text-amber-300', [
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
      add('trans', 'Internet Control Message Protocol', 'text-amber-300', [
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
      add('payload', `Data (${pay.length} bytes)`, 'text-purple-300', [
        ['Length',  `${pay.length} bytes`],
        ['Preview', pre + (pay.length > 24 ? ' …' : '')],
      ])
    }
    return S
  }

  // ── Reactive derivations ───────────────────────────────────────────────────
  $: p             = $selectedPacket
  $: bytes         = toBytes(p?.raw_hex ?? '')
  $: lmap          = layerMap(bytes)
  $: rows          = hexRows(bytes, lmap)
  $: tree          = p ? buildTree(bytes, p) : []
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

  // ── Resize drag ────────────────────────────────────────────────────────────
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
    if (!dragging) return
    // Dragging up (negative delta) → panel grows
    height = Math.max(120, Math.min(window.innerHeight - 120, startH + (startY - e.clientY)))
  }

  function dragEnd() { dragging = false }
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
    <span class="px-1.5 py-0.5 rounded text-[10px] font-bold text-white {badge(p.protocol)}">{p.protocol}</span>
    <span class="text-[var(--nc-fg-4)]">{p.abs_time ?? p.timestamp}</span>

    {#if bytes.length > 0}
      <!-- Layer toggle buttons — only for layers present in this packet -->
      <div class="flex items-center gap-1 ml-2">
        {#each presentLayers as key}
          {@const l = LAYER[key]}
          {@const on = activeLayers[key]}
          <button
            class="flex items-center gap-1 px-1.5 py-0.5 rounded border transition-all select-none
                   {on ? 'opacity-100' : 'opacity-35'}"
            style="border-color:{on ? l.dot + '55' : 'var(--nc-border)'}"
            on:click={() => toggleLayer(key)}
            title="{on ? 'Hide' : 'Show'} {l.label}"
          >
            <div class="w-2 h-2 rounded-sm border shrink-0 transition-all"
              style="background:{on ? l.bg : 'transparent'}; border-color:{l.dot}88"></div>
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
      on:click={() => selectedPacket.set(null)}
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
                <div class="flex gap-1 py-px leading-4">
                  <span class="text-[var(--nc-fg-5)] shrink-0 w-[4.5rem] truncate">{label}</span>
                  <span class="text-[var(--nc-fg-1)] break-all">{value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <!-- Hex dump (right panel) -->
    <div class="flex-1 overflow-auto p-2">
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
                {#each row.cells.slice(0, 8) as cell}
                  {@const on = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style="{cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
                    title={cell?.tip ?? ''}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- Mid-gap -->
                <td class="w-3"></td>

                <!-- Second 8 hex bytes -->
                {#each row.cells.slice(8, 16) as cell}
                  {@const on = cell?.layer ? activeLayers[cell.layer] ?? true : true}
                  <td class="w-[1.35rem] text-center transition-opacity"
                    style="{cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
                    title={cell?.tip ?? ''}>
                    {#if cell}{cell.hex}{:else}<span class="invisible">00</span>{/if}
                  </td>
                {/each}

                <!-- ASCII column -->
                <td class="pl-4 text-[var(--nc-fg-4)] select-none whitespace-pre tracking-wide">
                  {#each row.cells as cell}
                    {#if cell}
                      {@const on = cell.layer ? activeLayers[cell.layer] ?? true : true}
                      <span
                        style="{cellStyle(cell, on)}{!on ? ';opacity:0.18' : ''}"
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
