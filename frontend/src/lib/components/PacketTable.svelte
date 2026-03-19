<script lang="ts">
  import { afterUpdate, tick } from 'svelte'
  import {
    filteredPackets, selectedPacket, isCapturing, trackMode, trackFingerprint, trackPrev,
    captureFilter, addressBook, addressBookPrefill, timestampMode,
    autoScrollEnabled, columnVisibility, scrollToSelectedTick, dnsCache, followStreamPacket,
  } from '../stores'
  import type { Packet, AddressBookEntry } from '../types'
  import type { ColumnVisibility } from '../stores'
  import ContextMenu from './ContextMenu.svelte'

  function copyText(text: string): void {
    navigator.clipboard.writeText(text).catch(() => {})
  }

  function copyFrame(pkt: Packet): void {
    copyText(JSON.stringify(pkt, null, 2))
  }

  // ── Column resize ──────────────────────────────────────────────────────────

  type ColKey = keyof ColumnVisibility

  const COL_KEYS: ColKey[] = ['no', 'time', 'source', 'destination', 'proto', 'length', 'info']

  function defaultWidths(): Record<ColKey, number> {
    return { no: 52, time: 90, source: 172, destination: 172, proto: 72, length: 58, info: 200 }
  }

  let colWidths: Record<ColKey, number> = (() => {
    try { return { ...defaultWidths(), ...JSON.parse(localStorage.getItem('nc:colWidths') ?? 'null') } }
    catch { return defaultWidths() }
  })()

  $: COLS = (() => {
    const vis  = $columnVisibility
    const keys = COL_KEYS.filter(k => vis[k])
    return keys.map((k, i) => {
      const isLast = i === keys.length - 1
      if (k === 'info' || isLast) return '1fr'
      return `${colWidths[k]}px`
    }).join(' ')
  })()

  function startResize(e: MouseEvent, key: ColKey): void {
    if (key === 'info') return
    e.preventDefault()
    e.stopPropagation()
    const startX = e.clientX
    const startW = colWidths[key]
    document.body.style.cursor     = 'col-resize'
    document.body.style.userSelect = 'none'
    function onMove(me: MouseEvent) {
      colWidths = { ...colWidths, [key]: Math.max(40, startW + me.clientX - startX) }
    }
    function onUp() {
      document.body.style.cursor     = ''
      document.body.style.userSelect = ''
      localStorage.setItem('nc:colWidths', JSON.stringify(colWidths))
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  // ── Virtual scroll constants ───────────────────────────────────────────────
  const ROW_H  = 29
  const RENDER = 250
  const BUFFER = 40

  // ── State ──────────────────────────────────────────────────────────────────
  let bodyEl:    HTMLDivElement
  let nearBottom = true
  let scrollTop  = 0
  let padTop     = 0
  let padBottom  = 0

  $: liveFollow = $autoScrollEnabled && nearBottom

  // ── Address resolution ─────────────────────────────────────────────────────

  function resolveName(ip: string, port: number | null, book: AddressBookEntry[]): string {
    if (port != null) {
      const key = `${ip}:${port}`.toLowerCase()
      const hit = book.find(e => e.address.toLowerCase() === key)
      if (hit) return hit.name
    }
    const hit = book.find(e => e.address.toLowerCase() === ip?.toLowerCase())
    return hit?.name ?? ip
  }

  function displayAddr(ip: string, port: number | null, book: AddressBookEntry[]): string {
    const name = resolveName(ip, port, book)
    if (name !== ip) return name
    return port != null ? `${ip}:${port}` : ip
  }

  function hasName(ip: string, port: number | null, book: AddressBookEntry[]): boolean {
    return resolveName(ip, port, book) !== ip
  }

  // ── Protocol colour tables ─────────────────────────────────────────────────
  const ROW_TINT: Record<string, string> = {
    TCP:  'nc-tint-tcp',  UDP:  'nc-tint-udp',
    DNS:  'nc-tint-dns',  ICMP: 'nc-tint-icmp',
    HTTP: 'nc-tint-http', HTTPS:'nc-tint-https',
    TLS:  'nc-tint-https',ARP:  'nc-tint-arp',
  }
  const BADGE_VAR: Record<string, string> = {
    TCP:  '--nc-p-tcp',  UDP:  '--nc-p-udp',
    DNS:  '--nc-p-dns',  ICMP: '--nc-p-icmp',
    HTTP: '--nc-p-http', HTTPS:'--nc-p-https',
    TLS:  '--nc-p-https',ARP:  '--nc-p-arp',
  }

  function rowClass(pkt: Packet, isSelected: boolean): string {
    if (isSelected) return 'bg-blue-900/50 border-l-2 border-blue-400'
    return `${ROW_TINT[pkt.protocol] ?? ''} border-l-2 border-transparent hover:bg-[var(--nc-row-hover)] hover:border-blue-400/60 cursor-pointer`
  }
  function badgeStyle(proto: string): string {
    return `background-color: var(${BADGE_VAR[proto] ?? '--nc-p-default'})`
  }

  // ── Filter append helper ───────────────────────────────────────────────────

  function appendFilter(clause: string): void {
    captureFilter.update(cur => {
      const t = cur.trim()
      return t ? `(${t}) and ${clause}` : clause
    })
  }

  // ── Context menu ───────────────────────────────────────────────────────────

  type MenuItem = { label: string; sub?: string; action: () => void } | { separator: true }

  let ctxMenu: { x: number; y: number; items: MenuItem[] } | null = null

  function openSrcMenu(e: MouseEvent, pkt: Packet): void {
    e.preventDefault()
    const ip      = pkt.src_ip
    const port    = pkt.src_port
    const name    = resolveName(ip, port, $addressBook)
    const isNamed = name !== ip
    const display = displayAddr(ip, port, $addressBook)

    const items: MenuItem[] = [
      { label: 'Filter for source',  sub: `ip.src == ${ip}`, action: () => appendFilter(`ip.src == ${ip}`) },
      { label: 'Exclude source',     sub: `not ip.src == ${ip}`, action: () => appendFilter(`not ip.src == ${ip}`) },
    ]
    if (isNamed) {
      items.push({ separator: true })
      items.push({ label: 'Filter by name',  sub: `src_name == "${name}"`, action: () => appendFilter(`src_name == "${name}"`) })
      items.push({ label: 'Exclude by name', sub: `not src_name == "${name}"`, action: () => appendFilter(`not src_name == "${name}"`) })
    }
    if (port != null) {
      items.push({ separator: true })
      items.push({ label: 'Filter source port', sub: `src.port == ${port}`, action: () => appendFilter(`src.port == ${port}`) })
    }
    items.push({ separator: true })
    items.push({ label: 'Copy value', sub: display,  action: () => copyText(display) })
    items.push({ label: 'Copy frame', sub: 'JSON',   action: () => copyFrame(pkt) })
    if (!isNamed) {
      items.push({ separator: true })
      items.push({ label: 'Add IP to address book',         sub: ip,              action: () => addressBookPrefill.set(ip) })
      if (port != null) {
        items.push({ label: `Add IP:Port to address book`,  sub: `${ip}:${port}`, action: () => addressBookPrefill.set(`${ip}:${port}`) })
      }
    }
    ctxMenu = { x: e.clientX, y: e.clientY, items }
  }

  function openDstMenu(e: MouseEvent, pkt: Packet): void {
    e.preventDefault()
    const ip      = pkt.dst_ip
    const port    = pkt.dst_port
    const name    = resolveName(ip, port, $addressBook)
    const isNamed = name !== ip
    const display = displayAddr(ip, port, $addressBook)

    const items: MenuItem[] = [
      { label: 'Filter for destination', sub: `ip.dst == ${ip}`, action: () => appendFilter(`ip.dst == ${ip}`) },
      { label: 'Exclude destination',    sub: `not ip.dst == ${ip}`, action: () => appendFilter(`not ip.dst == ${ip}`) },
    ]
    if (isNamed) {
      items.push({ separator: true })
      items.push({ label: 'Filter by name',  sub: `dst_name == "${name}"`, action: () => appendFilter(`dst_name == "${name}"`) })
      items.push({ label: 'Exclude by name', sub: `not dst_name == "${name}"`, action: () => appendFilter(`not dst_name == "${name}"`) })
    }
    if (port != null) {
      items.push({ separator: true })
      items.push({ label: 'Filter dest port', sub: `dst.port == ${port}`, action: () => appendFilter(`dst.port == ${port}`) })
    }
    items.push({ separator: true })
    items.push({ label: 'Copy value', sub: display, action: () => copyText(display) })
    items.push({ label: 'Copy frame', sub: 'JSON',  action: () => copyFrame(pkt) })
    if (!isNamed) {
      items.push({ separator: true })
      items.push({ label: 'Add IP to address book',        sub: ip,              action: () => addressBookPrefill.set(ip) })
      if (port != null) {
        items.push({ label: `Add IP:Port to address book`, sub: `${ip}:${port}`, action: () => addressBookPrefill.set(`${ip}:${port}`) })
      }
    }
    ctxMenu = { x: e.clientX, y: e.clientY, items }
  }

  function openProtoMenu(e: MouseEvent, pkt: Packet): void {
    e.preventDefault()
    const proto = pkt.protocol
    const items: MenuItem[] = [
      { label: 'Filter for protocol', sub: `proto == ${proto}`, action: () => appendFilter(`proto == ${proto}`) },
      { label: 'Exclude protocol',    sub: `not proto == ${proto}`, action: () => appendFilter(`not proto == ${proto}`) },
      { separator: true },
      { label: 'Copy value', sub: proto, action: () => copyText(proto) },
      { label: 'Copy frame', sub: 'JSON', action: () => copyFrame(pkt) },
    ]
    if (pkt.src_port != null && pkt.dst_port != null) {
      items.push({ separator: true })
      items.push({ label: `Follow ${pkt.protocol.split('/')[0]} Stream`, action: () => followStreamPacket.set(pkt) })
    }
    ctxMenu = { x: e.clientX, y: e.clientY, items }
  }

  // ── Scroll handling ────────────────────────────────────────────────────────
  function handleScroll(e: Event): void {
    const el = e.target as HTMLElement
    scrollTop  = el.scrollTop
    nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60
  }

  function handleWheel(e: WheelEvent): void {
    if (!($isCapturing && liveFollow)) return
    if (e.deltaY >= 0) return
    e.preventDefault()
    const dy = e.deltaMode === 1 ? e.deltaY * ROW_H : e.deltaY
    const viewportRows = Math.floor((bodyEl?.clientHeight ?? 600) / ROW_H)
    const target = Math.max(0, Math.max(0, total - viewportRows) * ROW_H + dy)
    nearBottom = false
    scrollTop  = target
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = target })
  }

  function jumpToLive() {
    autoScrollEnabled.set(true)
    nearBottom = true
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight })
  }

  function selectAndPin(pkt: Packet): void {
    if ($trackMode && $selectedPacket?.id !== pkt.id) {
      trackMode.set(false)
      trackFingerprint.set(null)
      trackPrev.set(null)
    }
    selectedPacket.set(pkt)
    if (!($isCapturing && liveFollow)) return

    const idx = $filteredPackets.findIndex(p => p.id === pkt.id)
    if (idx === -1) return
    const viewportRows = Math.floor((bodyEl?.clientHeight ?? 600) / ROW_H)
    const target = Math.max(0, (idx - Math.floor(viewportRows / 2)) * ROW_H)
    nearBottom = false
    scrollTop  = target
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = target })
  }

  // ── Virtual display window ─────────────────────────────────────────────────
  $: total = $filteredPackets.length

  let display: Packet[] = []

  $: {
    if ($isCapturing && liveFollow) {
      display   = $filteredPackets.slice(-200)
      padTop    = 0
      padBottom = 0
    } else {
      const visStart = Math.max(0, Math.floor(scrollTop / ROW_H) - BUFFER)
      const visEnd   = Math.min(total, visStart + RENDER)
      display   = $filteredPackets.slice(visStart, visEnd)
      padTop    = visStart * ROW_H
      padBottom = Math.max(0, total - visEnd) * ROW_H
    }
  }

  let prevCapturing = false
  $: {
    if (prevCapturing && !$isCapturing && nearBottom) {
      tick().then(() => { if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight })
    }
    prevCapturing = $isCapturing
  }

  $: if ($scrollToSelectedTick && $selectedPacket && bodyEl) {
    const idx = $filteredPackets.findIndex(p => p.id === $selectedPacket!.id)
    if (idx >= 0) {
      bodyEl.scrollTop = Math.max(0, idx * ROW_H - bodyEl.clientHeight / 2)
    }
  }

  afterUpdate(() => {
    if (liveFollow && $isCapturing && bodyEl)
      bodyEl.scrollTop = bodyEl.scrollHeight
  })
</script>

{#if ctxMenu}
  <ContextMenu x={ctxMenu.x} y={ctxMenu.y} items={ctxMenu.items} on:close={() => ctxMenu = null} />
{/if}

<div class="flex flex-col flex-1 min-h-0 font-mono text-xs">
  <!-- Header row -->
  <div
    class="grid shrink-0 text-[10px] font-semibold text-[var(--nc-fg-4)] uppercase tracking-widest
           bg-[var(--nc-surface-1)] border-b border-[var(--nc-border)] z-10"
    style="grid-template-columns:{COLS}"
  >
    {#if $columnVisibility.no}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        No.
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'no')}></div>
      </div>
    {/if}
    {#if $columnVisibility.time}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        Time
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'time')}></div>
      </div>
    {/if}
    {#if $columnVisibility.source}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        Source
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'source')}></div>
      </div>
    {/if}
    {#if $columnVisibility.destination}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        Destination
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'destination')}></div>
      </div>
    {/if}
    {#if $columnVisibility.proto}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        Proto
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'proto')}></div>
      </div>
    {/if}
    {#if $columnVisibility.length}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="px-3 py-2 relative group/rh select-none" on:mousedown|stopPropagation>
        Len
        <div class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100 hover:bg-blue-400/40 transition-opacity"
          on:mousedown|stopPropagation={(e) => startResize(e, 'length')}></div>
      </div>
    {/if}
    {#if $columnVisibility.info}
      <div class="px-3 py-2 select-none">Info</div>
    {/if}
  </div>

  <!-- Scrollable rows -->
  <div
    bind:this={bodyEl}
    on:scroll={handleScroll}
    on:wheel={handleWheel}
    class="flex-1 overflow-x-hidden"
    style="overflow-y: {$isCapturing && liveFollow ? 'hidden' : 'auto'}"
  >
    {#if padTop > 0}
      <div style="height:{padTop}px" aria-hidden="true"></div>
    {/if}

    {#each display as pkt (pkt.id)}
      <!-- svelte-ignore a11y-click-events-have-key-events -->
      <!-- svelte-ignore a11y-interactive-supports-focus -->
      <div
        class="grid items-center border-b border-[var(--nc-border-1)] {rowClass(pkt, $selectedPacket?.id === pkt.id)} transition-colors duration-75"
        style="grid-template-columns:{COLS}"
        on:click={() => selectAndPin(pkt)}
        role="row"
      >
        {#if $columnVisibility.no}
          <div class="px-3 py-1.5 text-[var(--nc-fg-4)] tabular-nums">{pkt.id}</div>
        {/if}
        {#if $columnVisibility.time}
          <div class="px-3 py-1.5 text-[var(--nc-fg-3)] tabular-nums">
            {$timestampMode === 'absolute' ? (pkt.abs_time ?? pkt.timestamp) : pkt.timestamp}
          </div>
        {/if}
        {#if $columnVisibility.source}
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div
            class="px-3 py-1.5 truncate {hasName(pkt.src_ip, pkt.src_port, $addressBook) || $dnsCache[pkt.src_ip] != null ? 'text-blue-300' : 'text-[var(--nc-fg-1)]'}"
            on:contextmenu|stopPropagation={(e) => openSrcMenu(e, pkt)}
            title="{pkt.src_ip}{pkt.src_port != null ? ':' + pkt.src_port : ''}"
          >
            {#if hasName(pkt.src_ip, pkt.src_port, $addressBook)}
              {displayAddr(pkt.src_ip, pkt.src_port, $addressBook)}
            {:else if $dnsCache[pkt.src_ip] != null}
              {$dnsCache[pkt.src_ip]}{pkt.src_port != null ? ':' + pkt.src_port : ''}
            {:else}
              {displayAddr(pkt.src_ip, pkt.src_port, $addressBook)}
            {/if}
          </div>
        {/if}
        {#if $columnVisibility.destination}
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div
            class="px-3 py-1.5 truncate {hasName(pkt.dst_ip, pkt.dst_port, $addressBook) || $dnsCache[pkt.dst_ip] != null ? 'text-blue-300' : 'text-[var(--nc-fg-1)]'}"
            on:contextmenu|stopPropagation={(e) => openDstMenu(e, pkt)}
            title="{pkt.dst_ip}{pkt.dst_port != null ? ':' + pkt.dst_port : ''}"
          >
            {#if hasName(pkt.dst_ip, pkt.dst_port, $addressBook)}
              {displayAddr(pkt.dst_ip, pkt.dst_port, $addressBook)}
            {:else if $dnsCache[pkt.dst_ip] != null}
              {$dnsCache[pkt.dst_ip]}{pkt.dst_port != null ? ':' + pkt.dst_port : ''}
            {:else}
              {displayAddr(pkt.dst_ip, pkt.dst_port, $addressBook)}
            {/if}
          </div>
        {/if}
        {#if $columnVisibility.proto}
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div
            class="px-3 py-1.5"
            on:contextmenu|stopPropagation={(e) => openProtoMenu(e, pkt)}
          >
            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold text-white"
              style={badgeStyle(pkt.protocol)}>
              {pkt.protocol}
            </span>
          </div>
        {/if}
        {#if $columnVisibility.length}
          <div class="px-3 py-1.5 text-[var(--nc-fg-3)] tabular-nums">{pkt.length}</div>
        {/if}
        {#if $columnVisibility.info}
          <div class="px-3 py-1.5 text-[var(--nc-fg-2)] truncate">{pkt.info}</div>
        {/if}
      </div>
    {:else}
      <div class="flex items-center justify-center h-32 text-[var(--nc-fg-5)] select-none">
        {#if $isCapturing}Waiting for packets…{:else}Press Start to begin capturing.{/if}
      </div>
    {/each}

    {#if padBottom > 0}
      <div style="height:{padBottom}px" aria-hidden="true"></div>
    {/if}
  </div>

  <!-- "Jump to live" banner -->
  {#if $isCapturing && !liveFollow}
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-interactive-supports-focus -->
    <div
      class="shrink-0 flex items-center justify-center gap-2 py-1.5
             bg-blue-950/80 border-t border-blue-800/50 cursor-pointer
             text-[11px] text-blue-100 hover:text-blue-300 hover:bg-blue-950/60
             transition-colors duration-100 select-none"
      on:click={jumpToLive}
      role="button"
    >
      <span>&#9660;</span>
      <span>{total.toLocaleString()} packets captured — click to jump to live</span>
      <span>&#9660;</span>
    </div>
  {/if}

  <!-- Footer: packet count when stopped with data -->
  {#if !$isCapturing && total > 0}
    <div class="shrink-0 text-center py-1 text-[10px] text-[var(--nc-fg-5)] bg-[var(--nc-surface)] border-t border-[var(--nc-border-1)] select-none">
      {total.toLocaleString()} packets — scroll to browse
    </div>
  {/if}
</div>
