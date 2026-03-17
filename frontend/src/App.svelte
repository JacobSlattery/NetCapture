<script>
  import { onMount } from 'svelte'
  import { interfaces, selectedInterface, captureFilter } from './stores.js'
  import { startCapture, stopCapture, clearCapture, fetchInterfaces } from './captureService.js'
  import Toolbar     from './lib/Toolbar.svelte'
  import StatsBar    from './lib/StatsBar.svelte'
  import Charts      from './lib/Charts.svelte'
  import PacketTable from './lib/PacketTable.svelte'
  import PacketDetail from './lib/PacketDetail.svelte'

  let showCharts = false

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

<div class="flex flex-col h-screen overflow-hidden bg-[#0d1117]">
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
    class="shrink-0 text-[10px] text-gray-700 hover:text-gray-400 py-0.5 border-b border-[#21262d]
           bg-[#0d1117] transition-colors tracking-widest uppercase"
  >
    {showCharts ? '▲ hide charts' : '▼ show charts'}
  </button>

  <PacketTable />
  <PacketDetail />
</div>
