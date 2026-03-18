<script lang="ts">
  import { onMount } from 'svelte'
  import { interfaces, selectedInterface, captureFilter, profiles, activeProfile, addressBook } from './stores'
  import { initCaptureService, startCapture, stopCapture, clearCapture, fetchInterfaces, fetchProfiles, fetchAddressBook } from './captureService'
  import Toolbar      from './components/Toolbar.svelte'
  import StatsBar     from './components/StatsBar.svelte'
  import PacketTable  from './components/PacketTable.svelte'
  import PacketDetail from './components/PacketDetail.svelte'

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

  onMount(async () => {
    // Connect the WebSocket — must be called before any captures start
    initCaptureService(wsUrl, apiBase)

    const savedIfaceName = localStorage.getItem('nc:selectedInterface') ?? ''
    const savedProfileId = localStorage.getItem('nc:activeProfileId')

    const [ifaces, profs, book] = await Promise.all([fetchInterfaces(), fetchProfiles(), fetchAddressBook()])
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

  // No onDestroy — capture persists when this component unmounts.
  // captureService owns the WS and all state at module scope.
</script>

<div class="flex flex-col h-screen overflow-hidden bg-[var(--nc-surface)]">
  <Toolbar
    on:start={() => startCapture($selectedInterface, $activeProfile?.filter ?? $captureFilter)}
    on:stop={stopCapture}
    on:clear={clearCapture}
  />
  <StatsBar />

  {#if showCharts && ChartsComponent}
    <svelte:component this={ChartsComponent} />
  {/if}

  <button
    on:click={() => showCharts ? closeCharts() : openCharts()}
    class="shrink-0 text-[10px] text-[var(--nc-fg-5)] hover:text-[var(--nc-fg-2)] py-0.5 border-b border-[var(--nc-border-1)]
           bg-[var(--nc-surface)] transition-colors tracking-widest uppercase"
  >
    {showCharts ? '▲ hide charts' : '▼ show charts'}
  </button>

  <PacketTable />
  <PacketDetail />
</div>
