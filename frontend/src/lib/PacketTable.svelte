<script lang="ts">
  import { afterUpdate, tick } from 'svelte'
  import { filteredPackets, selectedPacket, isCapturing, trackMode, trackFingerprint, trackPrev } from './stores'
  import type { Packet } from './types'

  // ── Virtual scroll constants ───────────────────────────────────────────────
  // ROW_H must match the actual rendered row height:
  //   py-1.5 (6px×2) + text-xs line-height (16px) + border-b (1px) = 29 px
  const ROW_H  = 29
  const RENDER = 250   // rows in the virtual window
  const BUFFER = 40    // extra rows rendered above/below the visible area

  // ── State ──────────────────────────────────────────────────────────────────
  let bodyEl:    HTMLDivElement
  let autoScroll = true
  let scrollTop  = 0
  let padTop     = 0
  let padBottom  = 0

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

  // ── Scroll handling ────────────────────────────────────────────────────────
  function handleScroll(e: Event): void {
    const el = e.target as HTMLElement
    scrollTop  = el.scrollTop
    autoScroll = el.scrollHeight - el.scrollTop - el.clientHeight < 60
  }

  // In live mode the scroll container has overflow:hidden so the user can't
  // scroll manually. We intercept wheel events instead and use them to switch
  // to browse mode, remapping the wheel delta to the correct position in the
  // full virtual layout (relative to the tail, not the 200-row DOM window).
  function handleWheel(e: WheelEvent): void {
    if (!($isCapturing && autoScroll)) return   // already in browse mode — ignore
    if (e.deltaY >= 0) return                   // scrolling down while live — ignore
    e.preventDefault()

    // Normalize to pixels (deltaMode 1 = lines)
    const dy = e.deltaMode === 1 ? e.deltaY * ROW_H : e.deltaY

    // Position the virtual window so the bottom of the list is in view,
    // then apply the wheel delta upward from there.
    const viewportRows = Math.floor((bodyEl?.clientHeight ?? 600) / ROW_H)
    const target = Math.max(0, Math.max(0, total - viewportRows) * ROW_H + dy)

    autoScroll = false
    scrollTop  = target    // drives reactive block to the right slice immediately
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = target })
  }

  function jumpToLive() {
    autoScroll = true
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight })
  }

  function selectAndPin(pkt: Packet): void {
    // If the user explicitly clicks a different packet, stop tracking
    if ($trackMode && $selectedPacket?.id !== pkt.id) {
      trackMode.set(false)
      trackFingerprint.set(null)
      trackPrev.set(null)
    }
    selectedPacket.set(pkt)
    if (!($isCapturing && autoScroll)) return  // already in browse mode, nothing extra

    // Find the packet's position in the full list and center it in the viewport
    const idx = $filteredPackets.findIndex(p => p.id === pkt.id)
    if (idx === -1) return

    const viewportRows = Math.floor((bodyEl?.clientHeight ?? 600) / ROW_H)
    const target = Math.max(0, (idx - Math.floor(viewportRows / 2)) * ROW_H)

    autoScroll = false
    scrollTop  = target
    tick().then(() => { if (bodyEl) bodyEl.scrollTop = target })
  }

  // ── Virtual display window ─────────────────────────────────────────────────
  $: total = $filteredPackets.length

  let display: Packet[] = []

  $: {
    if ($isCapturing && autoScroll) {
      // Live tail mode: pin to the last 200 rows, zero virtual overhead
      display   = $filteredPackets.slice(-200)
      padTop    = 0
      padBottom = 0
    } else {
      // Browse mode: virtual window driven by scroll position.
      // Used both when stopped AND when capturing but the user has scrolled up.
      const visStart = Math.max(0, Math.floor(scrollTop / ROW_H) - BUFFER)
      const visEnd   = Math.min(total, visStart + RENDER)
      display   = $filteredPackets.slice(visStart, visEnd)
      padTop    = visStart * ROW_H
      padBottom = Math.max(0, total - visEnd) * ROW_H
    }
  }

  // When capture stops while in live mode, scroll to bottom so the virtual
  // window aligns correctly with the new phantom spacers.
  // If the user was already browsing, leave their position alone.
  let prevCapturing = false
  $: {
    if (prevCapturing && !$isCapturing && autoScroll) {
      tick().then(() => { if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight })
    }
    prevCapturing = $isCapturing
  }

  afterUpdate(() => {
    if (autoScroll && $isCapturing && bodyEl)
      bodyEl.scrollTop = bodyEl.scrollHeight
  })

  const COLS = '52px 90px 172px 172px 72px 58px 1fr'
</script>

<div class="flex flex-col flex-1 min-h-0 font-mono text-xs">
  <!-- Header row -->
  <div
    class="grid shrink-0 text-[10px] font-semibold text-[var(--nc-fg-4)] uppercase tracking-widest
           bg-[var(--nc-surface-1)] border-b border-[var(--nc-border)] z-10"
    style="grid-template-columns:{COLS}"
  >
    <div class="px-3 py-2">No.</div>
    <div class="px-3 py-2">Time</div>
    <div class="px-3 py-2">Source</div>
    <div class="px-3 py-2">Destination</div>
    <div class="px-3 py-2">Proto</div>
    <div class="px-3 py-2">Len</div>
    <div class="px-3 py-2">Info</div>
  </div>

  <!-- Scrollable rows -->
  <!-- overflow:hidden in live mode removes the scrollbar and prevents drag-scrolling;
       wheel events are intercepted above to trigger the browse-mode transition. -->
  <div
    bind:this={bodyEl}
    on:scroll={handleScroll}
    on:wheel={handleWheel}
    class="flex-1 overflow-x-hidden"
    style="overflow-y: {$isCapturing && autoScroll ? 'hidden' : 'auto'}"
  >
    <!-- Phantom spacer — represents packets above the virtual window -->
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
        <div class="px-3 py-1.5 text-[var(--nc-fg-4)] tabular-nums">{pkt.id}</div>
        <div class="px-3 py-1.5 text-[var(--nc-fg-3)] tabular-nums">{pkt.timestamp}</div>
        <div class="px-3 py-1.5 text-[var(--nc-fg-1)] truncate">
          {pkt.src_ip}{pkt.src_port != null ? ':' + pkt.src_port : ''}
        </div>
        <div class="px-3 py-1.5 text-[var(--nc-fg-1)] truncate">
          {pkt.dst_ip}{pkt.dst_port != null ? ':' + pkt.dst_port : ''}
        </div>
        <div class="px-3 py-1.5">
          <span class="px-1.5 py-0.5 rounded text-[10px] font-bold text-white"
            style={badgeStyle(pkt.protocol)}>
            {pkt.protocol}
          </span>
        </div>
        <div class="px-3 py-1.5 text-[var(--nc-fg-3)] tabular-nums">{pkt.length}</div>
        <div class="px-3 py-1.5 text-[var(--nc-fg-2)] truncate">{pkt.info}</div>
      </div>
    {:else}
      <div class="flex items-center justify-center h-32 text-[var(--nc-fg-5)] select-none">
        {#if $isCapturing}Waiting for packets…{:else}Press Start to begin capturing.{/if}
      </div>
    {/each}

    <!-- Phantom spacer — represents packets below the virtual window -->
    {#if padBottom > 0}
      <div style="height:{padBottom}px" aria-hidden="true"></div>
    {/if}
  </div>

  <!-- "Jump to live" banner — shown when capturing but the user has scrolled away -->
  {#if $isCapturing && !autoScroll}
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
