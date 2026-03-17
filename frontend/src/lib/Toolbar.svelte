<script>
  import { createEventDispatcher } from 'svelte'
  import {
    isCapturing, connectionStatus, selectedInterface,
    interfaces, captureFilter, captureMode,
  } from '../stores.js'

  const dispatch = createEventDispatcher()

  $: dotClass = {
    connected:    'bg-green-400 animate-pulse',
    connecting:   'bg-yellow-400 animate-pulse',
    error:        'bg-red-400',
    disconnected: 'bg-gray-600',
  }[$connectionStatus] ?? 'bg-gray-600'

  const MODE_LABEL = { real: 'Raw', listen: 'Listen', error: 'No capture' }
  const MODE_CLASS = {
    real:    'text-green-400 border-green-800',
    listen:  'text-blue-400  border-blue-800',
    error:   'text-red-400   border-red-800',
  }
  $: modeLabel = MODE_LABEL[$captureMode] ?? null
  $: modeClass = MODE_CLASS[$captureMode] ?? ''
</script>

<header class="flex flex-wrap items-center gap-2 px-4 py-2 bg-[#161b22] border-b border-[#30363d] select-none shrink-0">
  <!-- Brand -->
  <div class="flex items-center gap-2 mr-1">
    <div class="w-2.5 h-2.5 rounded-full {dotClass}"></div>
    <span class="text-white font-bold text-base tracking-tight">NetCapture</span>
  </div>

  <!-- Interface selector -->
  <select
    bind:value={$selectedInterface}
    disabled={$isCapturing}
    class="bg-[#0d1117] text-gray-300 border border-[#30363d] rounded px-2 py-1 text-xs
           focus:outline-none focus:border-blue-500 disabled:opacity-40 cursor-pointer"
  >
    {#each $interfaces as iface}
      <option value={iface.name}>
        {iface.name}{iface.description ? ` — ${iface.description}` : ''}
      </option>
    {/each}
  </select>

  <!-- Start / Stop -->
  {#if !$isCapturing}
    <button
      on:click={() => dispatch('start')}
      class="flex items-center gap-1.5 bg-green-700 hover:bg-green-600 text-white
             px-3 py-1 rounded text-xs font-semibold transition-colors"
    >
      <!-- play icon -->
      <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
        <path d="M6.3 2.841A1.5 1.5 0 004 4.11V15.89a1.5 1.5 0 002.3 1.269l9.344-5.89a1.5 1.5 0 000-2.538L6.3 2.84z"/>
      </svg>
      Start
    </button>
  {:else}
    <button
      on:click={() => dispatch('stop')}
      class="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 text-white
             px-3 py-1 rounded text-xs font-semibold transition-colors"
    >
      <!-- stop icon -->
      <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M2 10a8 8 0 1116 0 8 8 0 01-16 0zm5-2.25A.75.75 0 017.75 7h4.5a.75.75 0 01.75.75v4.5a.75.75 0 01-.75.75h-4.5a.75.75 0 01-.75-.75v-4.5z" clip-rule="evenodd"/>
      </svg>
      Stop
    </button>
  {/if}

  <!-- Clear -->
  <button
    on:click={() => dispatch('clear')}
    disabled={$isCapturing}
    class="flex items-center gap-1.5 bg-[#21262d] hover:bg-[#30363d] text-gray-300
           px-3 py-1 rounded text-xs border border-[#30363d] transition-colors disabled:opacity-40"
  >
    <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z" clip-rule="evenodd"/>
    </svg>
    Clear
  </button>

  <!-- Capture mode badge -->
  {#if modeLabel}
    <span class="px-2 py-0.5 rounded border text-[10px] font-semibold tracking-wide select-none {modeClass}">
      {modeLabel}
    </span>
  {/if}

  <!-- Filter — pushed right -->
  <div class="flex items-center gap-2 ml-auto">
    <span class="text-gray-600 text-xs">Filter:</span>
    <input
      type="text"
      bind:value={$captureFilter}
      placeholder="ip, protocol, port…"
      class="bg-[#0d1117] text-gray-200 border border-[#30363d] rounded px-3 py-1 text-xs w-52
             focus:outline-none focus:border-blue-500 placeholder-gray-700"
    />
  </div>
</header>
