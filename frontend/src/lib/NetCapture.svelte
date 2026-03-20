<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import { get } from 'svelte/store'
  import {
    interfaces, selectedInterface, captureFilter, profiles, activeProfile, addressBook,
    isCapturing, selectedPacket, filteredPackets, filterFocusTick, scrollToSelectedTick,
    bpfFilter, followStreamPacket,
  } from './stores'
  import { initCaptureService, startCapture, stopCapture, clearCapture, fetchInterfaces, fetchProfiles, fetchAddressBook, exportCapture, fetchCapabilities } from './captureService'
  import Toolbar      from './components/Toolbar.svelte'
  import StatsBar     from './components/StatsBar.svelte'
  import PacketTable  from './components/PacketTable.svelte'
  import PacketDetail from './components/PacketDetail.svelte'
  import FollowStream from './components/FollowStream.svelte'

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

    const savedIfaceName = localStorage.getItem('nc:selectedInterface') ?? ''
    const savedProfileId = localStorage.getItem('nc:activeProfileId')

    const [ifaces, profs, book] = await Promise.all([fetchInterfaces(), fetchProfiles(), fetchAddressBook(), fetchCapabilities()])
    if (ifaces.length) interfaces.set(ifaces)
    profiles.set(profs)
    addressBook.set(book)

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

  onDestroy(() => {
    window.removeEventListener('keydown', handleKeydown)
  })
  // Note: capture persists when this component unmounts.
  // captureService owns the WS and all state at module scope.
</script>

<div
  class="flex flex-col h-full overflow-hidden bg-(--nc-surface)"
  data-theme={theme || undefined}
>
  <Toolbar
    on:start={() => startCapture($selectedInterface, $activeProfile?.filter ?? $captureFilter, $bpfFilter)}
    on:stop={stopCapture}
    on:clear={clearCapture}
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

  <PacketTable />
  <PacketDetail />
</div>

{#if $followStreamPacket}
  <FollowStream anchor={$followStreamPacket} on:close={() => followStreamPacket.set(null)} />
{/if}
