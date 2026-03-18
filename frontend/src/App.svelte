<script lang="ts">
  import { onMount } from 'svelte'
  import { interfaces, selectedInterface, captureFilter, profiles, activeProfile } from './stores'
  import { startCapture, stopCapture, clearCapture, fetchInterfaces, fetchProfiles } from './captureService'
  import Toolbar     from './lib/Toolbar.svelte'
  import StatsBar    from './lib/StatsBar.svelte'
  import PacketTable from './lib/PacketTable.svelte'
  import PacketDetail from './lib/PacketDetail.svelte'

  let showCharts: boolean = localStorage.getItem('nc:showCharts') === 'true'
  let ChartsComponent: typeof import('./lib/Charts.svelte').default | null = null

  async function openCharts() {
    if (!ChartsComponent) {
      const mod = await import('./lib/Charts.svelte')
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
    const savedIfaceName = localStorage.getItem('nc:selectedInterface') ?? ''
    const savedProfileId = localStorage.getItem('nc:activeProfileId')

    const [ifaces, profs] = await Promise.all([fetchInterfaces(), fetchProfiles()])
    if (ifaces.length) interfaces.set(ifaces)
    profiles.set(profs)

    // Restore active profile first — it takes priority over the bare interface
    const savedProf = savedProfileId ? (profs.find(p => p.id === savedProfileId) ?? null) : null
    if (savedProf) {
      activeProfile.set(savedProf)
      selectedInterface.set(savedProf.interface)
    } else if (ifaces.length) {
      const valid = ifaces.some(i => i.name === savedIfaceName)
      selectedInterface.set(valid ? savedIfaceName : ifaces[0].name)
    }

    if (showCharts) {
      const mod = await import('./lib/Charts.svelte')
      ChartsComponent = mod.default
    }
  })

  // No onDestroy — capture persists when this component unmounts.
  // captureService.js owns the WS and all state at module scope.
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
