<script lang="ts">
  import { onMount } from 'svelte'
  import { interfaces, selectedInterface, captureFilter } from './stores'
  import { startCapture, stopCapture, clearCapture, fetchInterfaces } from './captureService'
  import Toolbar     from './lib/Toolbar.svelte'
  import StatsBar    from './lib/StatsBar.svelte'
  import Charts      from './lib/Charts.svelte'
  import PacketTable from './lib/PacketTable.svelte'
  import PacketDetail from './lib/PacketDetail.svelte'

  let showCharts: boolean = false

  onMount(async () => {
    const ifaces = await fetchInterfaces()
    if (ifaces.length) {
      interfaces.set(ifaces)
      selectedInterface.set(ifaces[0].name)
    }
  })

  // No onDestroy — capture persists when this component unmounts.
  // captureService.js owns the WS and all state at module scope.
</script>

<div class="flex flex-col h-screen overflow-hidden bg-[var(--nc-surface)]">
  <Toolbar
    on:start={() => startCapture($selectedInterface, $captureFilter)}
    on:stop={stopCapture}
    on:clear={clearCapture}
  />
  <StatsBar />

  {#if showCharts}
    <Charts />
  {/if}

  <button
    on:click={() => (showCharts = !showCharts)}
    class="shrink-0 text-[10px] text-[var(--nc-fg-5)] hover:text-[var(--nc-fg-2)] py-0.5 border-b border-[var(--nc-border-1)]
           bg-[var(--nc-surface)] transition-colors tracking-widest uppercase"
  >
    {showCharts ? '▲ hide charts' : '▼ show charts'}
  </button>

  <PacketTable />
  <PacketDetail />
</div>
