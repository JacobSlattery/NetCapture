<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { get } from 'svelte/store'
  import {
    interfaces, selectedInterface, captureFilter, profiles, activeProfile, addressBook,
    isCapturing, selectedPacket, filteredPackets, filterFocusTick, scrollToSelectedTick,
    bpfFilter, followStreamPacket, watchlistOpen, watchEntries,
  } from './stores'
  import { initCaptureService, startCapture, stopCapture, clearCapture, fetchInterfaces, fetchProfiles, fetchAddressBook, fetchWatchlists, syncWatchlists, exportCapture, fetchCapabilities, seedWatchEntry } from './captureService'
  import Toolbar      from './components/Toolbar.svelte'
  import StatsBar     from './components/StatsBar.svelte'
  import PacketTable  from './components/PacketTable.svelte'
  import PacketDetail from './components/PacketDetail.svelte'
  import FollowStream from './components/FollowStream.svelte'
  import Watchlist    from './components/Watchlist.svelte'
  import WatchlistEditor from './components/WatchlistEditor.svelte'
  import type { Packet, WatchEntry } from './types'

  // ── Watchlist panel width (drag-adjustable, persisted) ─────────────────────
  const _WL_WIDTH_KEY = 'nc:watchlistWidth'
  let watchlistWidth: number = (() => {
    const saved = parseInt(localStorage.getItem(_WL_WIDTH_KEY) ?? '', 10)
    const max = Math.floor(window.innerWidth / 2)
    return isNaN(saved) ? 260 : Math.max(160, Math.min(max, saved))
  })()
  let wlDragging = false
  let wlDragStartX = 0
  let wlDragStartW = 0

  function wlDragStart(e: MouseEvent): void {
    wlDragging    = true
    wlDragStartX  = e.clientX
    wlDragStartW  = watchlistWidth
    e.preventDefault()
  }
  function wlDragMove(e: MouseEvent): void {
    if (!wlDragging) return
    const dx = wlDragStartX - e.clientX
    watchlistWidth = Math.max(160, Math.min(Math.floor(window.innerWidth / 2), wlDragStartW + dx))
  }
  function wlDragEnd(): void {
    if (wlDragging) {
      localStorage.setItem(_WL_WIDTH_KEY, String(watchlistWidth))
    }
    wlDragging = false
  }

  // ── Watchlist editor state ──────────────────────────────────────────────────
  let showWatchEditor       = false
  let watchEditorEntry: WatchEntry | null = null
  let watchEditorPrefillPkt: Packet | null = null
  let watchEditorPrefillKey: string | null = null

  function openWatchEditor(prefillPkt: Packet | null = null, prefillKey: string | null = null, editEntry: WatchEntry | null = null) {
    watchEditorPrefillPkt = prefillPkt
    watchEditorPrefillKey = prefillKey
    watchEditorEntry      = editEntry
    showWatchEditor       = true
  }

  function closeWatchEditor() {
    showWatchEditor       = false
    watchEditorEntry      = null
    watchEditorPrefillPkt = null
    watchEditorPrefillKey = null
  }

  /**
   * Full WebSocket URL to the NetCapture backend.
   * e.g. 'wss://yourhost/netcapture/ws/capture'
   * Leave empty to auto-detect from window.location (standalone mode).
   */
  export let wsUrl: string = ''

  /**
   * Path prefix for all REST API calls.
   * e.g. '/netcapture'  when the backend router is mounted at that prefix.
   * Leave empty for relative /api/... paths (standalone mode).
   */
  export let apiBase: string = ''

  /**
   * Color theme applied to the component wrapper.
   * 'dark'  — dark surfaces (sets data-theme="dark" on the wrapper div)
   * 'light' — light surfaces (default)
   * ''      — inherits data-theme from an ancestor element
   *
   * In standalone mode the outer <html> element controls the theme;
   * when embedded, pass this prop so the component manages its own theme
   * without touching the parent page.
   */
  export let theme: 'light' | 'dark' | '' = ''

  let showCharts: boolean = localStorage.getItem('nc:showCharts') === 'true'
  let ChartsComponent: typeof import('./components/Charts.svelte').default | null = null

  async function openCharts() {
    if (!ChartsComponent) {
      const mod = await import('./components/Charts.svelte')
      ChartsComponent = mod.default
    }
    showCharts = true
    localStorage.setItem('nc:showCharts', 'true')
  }

  function closeCharts() {
    showCharts = false
    localStorage.setItem('nc:showCharts', 'false')
  }

  function handleKeydown(e: KeyboardEvent) {
    const tag = (e.target as HTMLElement).tagName
    const inInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'

    // Space = toggle capture (not in input)
    if (e.code === 'Space' && !inInput) {
      e.preventDefault()
      if (get(isCapturing)) stopCapture()
      else startCapture(get(selectedInterface), get(activeProfile)?.filter ?? get(captureFilter), get(bpfFilter))
      return
    }

    // Ctrl+E = export JSON capture
    if (e.key === 'e' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      exportCapture()
      return
    }

    // F = focus filter (not in input)
    if (e.key === 'f' && !inInput) {
      e.preventDefault()
      filterFocusTick.update(n => n + 1)
      return
    }

    // Escape = clear filter if filter focused, else deselect packet
    if (e.key === 'Escape') {
      if (document.activeElement?.closest('[data-filter-input]')) {
        captureFilter.set('')
        ;(document.activeElement as HTMLElement).blur()
      } else {
        selectedPacket.set(null)
      }
      return
    }

    // W = toggle watchlist panel (not in input)
    if (e.key === 'w' && !inInput) {
      e.preventDefault()
      watchlistOpen.update(v => !v)
      return
    }

    // J = next packet, K = prev packet (not in input)
    if ((e.key === 'j' || e.key === 'k') && !inInput) {
      e.preventDefault()
      const pkts = get(filteredPackets)
      if (!pkts.length) return
      const cur  = get(selectedPacket)
      const idx  = cur ? pkts.findIndex(p => p.id === cur.id) : -1
      let next: number
      if (e.key === 'j') next = idx < 0 ? 0 : Math.min(idx + 1, pkts.length - 1)
      else               next = idx < 0 ? pkts.length - 1 : Math.max(idx - 1, 0)
      selectedPacket.set(pkts[next])
      scrollToSelectedTick.update(n => n + 1)
      return
    }
  }

  onMount(async () => {
    // Connect the WebSocket — must be called before any captures start
    initCaptureService(wsUrl, apiBase)

    window.addEventListener('keydown', handleKeydown)
    window.addEventListener('mousemove', wlDragMove)
    window.addEventListener('mouseup', wlDragEnd)

    const savedIfaceName = localStorage.getItem('nc:selectedInterface') ?? ''
    const savedProfileId = localStorage.getItem('nc:activeProfileId')

    const [ifaces, profs, book, serverWatchlists] = await Promise.all([fetchInterfaces(), fetchProfiles(), fetchAddressBook(), fetchWatchlists(), fetchCapabilities()])
    if (ifaces.length) interfaces.set(ifaces)
    profiles.set(profs)
    addressBook.set(book)

    // Merge server-provided watchlists with locally-persisted ones
    if (serverWatchlists.length) {
      watchEntries.update(local => {
        const localIds = new Set(local.map(e => e.id))
        const newEntries = serverWatchlists.filter(e => !localIds.has(e.id))
        return newEntries.length ? [...local, ...newEntries] : local
      })
    }

    const savedProf = savedProfileId ? (profs.find(p => p.id === savedProfileId) ?? null) : null
    if (savedProf) {
      activeProfile.set(savedProf)
      selectedInterface.set(savedProf.interface)
    } else if (ifaces.length) {
      const valid = ifaces.some(i => i.name === savedIfaceName)
      selectedInterface.set(valid ? savedIfaceName : ifaces[0].name)
    }

    if (showCharts) {
      const mod = await import('./components/Charts.svelte')
      ChartsComponent = mod.default
    }
  })

  // Sync watchlist changes to backend (debounced, skip first emission)
  let _wlSyncTimer: ReturnType<typeof setTimeout> | null = null
  let _wlSkipFirst = true
  const _wlUnsub = watchEntries.subscribe(() => {
    if (_wlSkipFirst) { _wlSkipFirst = false; return }
    if (_wlSyncTimer) clearTimeout(_wlSyncTimer)
    _wlSyncTimer = setTimeout(() => { syncWatchlists(get(watchEntries)) }, 500)
  })

  onDestroy(() => {
    window.removeEventListener('keydown', handleKeydown)
    window.removeEventListener('mousemove', wlDragMove)
    window.removeEventListener('mouseup', wlDragEnd)
    _wlUnsub()
    if (_wlSyncTimer) clearTimeout(_wlSyncTimer)
  })
  // Note: capture persists when this component unmounts.
  // captureService owns the WS and all state at module scope.
</script>

<div
  class="flex flex-col h-full overflow-hidden bg-(--nc-surface)"
  data-theme={theme || undefined}
>
  <Toolbar
    onstart={() => startCapture($selectedInterface, $activeProfile?.filter ?? $captureFilter, $bpfFilter)}
    onstop={stopCapture}
    onclear={clearCapture}
  />
  <StatsBar />

  {#if showCharts && ChartsComponent}
    <svelte:component this={ChartsComponent} />
  {/if}

  <button
    on:click={() => showCharts ? closeCharts() : openCharts()}
    class="shrink-0 text-[10px] text-(--nc-fg-5) hover:text-(--nc-fg-2) py-0.5 border-b border-(--nc-border-1)
           bg-(--nc-surface) transition-colors tracking-widest uppercase"
  >
    {showCharts ? '▲ hide charts' : '▼ show charts'}
  </button>

  <!-- Main content area: packet table/detail + optional watchlist on right -->
  <div class="flex flex-1 min-h-0 overflow-hidden">
    <!-- Left: packet table + detail (takes remaining space) -->
    <div class="flex flex-col flex-1 min-w-0 min-h-0">
      <PacketTable />
      <PacketDetail onwatch={({ packet, fieldKey }) => openWatchEditor(packet, fieldKey)} />
    </div>

    <!-- Right: watchlist panel with drag handle -->
    {#if $watchlistOpen}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="shrink-0 flex items-stretch h-full cursor-col-resize"
        on:mousedown={wlDragStart}>
        <div class="w-1 bg-(--nc-border) hover:bg-blue-500/30 transition-colors"></div>
      </div>
      <div class="shrink-0 h-full overflow-hidden" style="width:{watchlistWidth}px">
        <Watchlist onadd={() => openWatchEditor()} onedit={(entry) => openWatchEditor(null, null, entry)} />
      </div>
    {/if}
  </div>
</div>

{#if $followStreamPacket}
  <FollowStream anchor={$followStreamPacket} onclose={() => followStreamPacket.set(null)} />
{/if}

{#if showWatchEditor}
  <WatchlistEditor
    editEntry={watchEditorEntry}
    prefillFromPacket={watchEditorPrefillPkt}
    prefillFieldKey={watchEditorPrefillKey}
    onclose={closeWatchEditor}
    onsave={(entry) => {
      watchEntries.update(list => {
        const idx = list.findIndex(x => x.id === entry.id)
        if (idx >= 0) { list[idx] = entry; return [...list] }
        return [...list, entry]
      })
      if (watchEditorPrefillPkt) seedWatchEntry(entry, watchEditorPrefillPkt)
      if (!$watchlistOpen) watchlistOpen.set(true)
      closeWatchEditor()
    }}
  />
{/if}
