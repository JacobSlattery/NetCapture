<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import {
    isCapturing, connectionStatus, selectedInterface,
    interfaces, captureFilter, captureMode, profiles, activeProfile,
  } from '../stores'
  import type { CaptureProfile } from '../types'
  import { exportCapture, importCapture } from '../captureService'

  let fileInput: HTMLInputElement

  async function handleImport(e: Event): Promise<void> {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    try {
      await importCapture(file)
    } catch (err) {
      console.error('[import]', err)
    } finally {
      // Reset input so the same file can be re-imported
      fileInput.value = ''
    }
  }

  const dispatch = createEventDispatcher()

  // ── Profile / interface selection ──────────────────────────────────────────
  // The dropdown encodes its value as "iface:<name>" or "profile:<id>" so
  // both interfaces and profiles can share a single <select> binding.

  $: selectionKey = $activeProfile
    ? `profile:${$activeProfile.id}`
    : `iface:${$selectedInterface}`

  function handleSelectionChange(e: Event): void {
    const val = (e.target as HTMLSelectElement).value
    if (val.startsWith('profile:')) {
      const id   = val.slice('profile:'.length)
      const prof = $profiles.find((p: CaptureProfile) => p.id === id) ?? null
      activeProfile.set(prof)
      if (prof) {
        selectedInterface.set(prof.interface)
      }
    } else {
      activeProfile.set(null)
      selectedInterface.set(val.slice('iface:'.length))
    }
  }

  $: statusDotStyle = ({
    connected:    'background-color: var(--nc-status-ok)',
    connecting:   'background-color: var(--nc-status-warn)',
    error:        'background-color: var(--nc-status-err)',
    disconnected: 'background-color: var(--nc-status-off)',
  } as Record<string, string>)[$connectionStatus] ?? 'background-color: var(--nc-status-off)'
  $: statusPulse = $connectionStatus === 'connected' || $connectionStatus === 'connecting'

  const MODE_LABEL = { scapy: 'Npcap', real: 'Raw', listen: 'Listen', error: 'No capture' }
  const MODE_STYLE: Record<string, string> = {
    scapy:  'color: var(--nc-p-dns);       border-color: color-mix(in srgb, var(--nc-p-dns)       35%, transparent)',
    real:   'color: var(--nc-status-ok);   border-color: color-mix(in srgb, var(--nc-status-ok)   35%, transparent)',
    listen: 'color: var(--nc-p-tcp);       border-color: color-mix(in srgb, var(--nc-p-tcp)       35%, transparent)',
    error:  'color: var(--nc-status-err);  border-color: color-mix(in srgb, var(--nc-status-err)  35%, transparent)',
  }
  $: modeLabel = (MODE_LABEL as Record<string, string>)[$captureMode] ?? null
  $: modeStyle = MODE_STYLE[$captureMode] ?? ''
</script>

<header class="flex flex-wrap items-center gap-2 px-4 py-2 bg-[var(--nc-surface-1)] border-b border-[var(--nc-border)] select-none shrink-0">
  <!-- Brand -->
  <div class="flex items-center gap-2 mr-1">
    <div class="w-2.5 h-2.5 rounded-full {statusPulse ? 'animate-pulse' : ''}"
      style={statusDotStyle}></div>
    <span class="text-[var(--nc-fg)] font-bold text-base tracking-tight">NetCapture</span>
  </div>

  <!-- Interface / profile selector -->
  <select
    value={selectionKey}
    on:change={handleSelectionChange}
    disabled={$isCapturing}
    class="bg-[var(--nc-surface)] text-[var(--nc-fg-1)] border border-[var(--nc-border)] rounded px-2 py-1 text-xs
           w-72 focus:outline-none focus:border-blue-500 disabled:opacity-40 cursor-pointer"
  >
    <optgroup label="Interfaces">
      {#each $interfaces as iface}
        <option value="iface:{iface.name}">
          {iface.description ?? iface.name}
        </option>
      {/each}
    </optgroup>

    {#if $profiles.length}
      <optgroup label="Capture Profiles">
        {#each $profiles as prof}
          <option value="profile:{prof.id}" title={prof.description}>
            {prof.name}
          </option>
        {/each}
      </optgroup>
    {/if}
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
    class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
           px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40"
  >
    <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
      <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z" clip-rule="evenodd"/>
    </svg>
    Clear
  </button>

  <!-- Export -->
  <button
    on:click={exportCapture}
    disabled={$isCapturing}
    class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
           px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40"
  >
    <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
      <path d="M10.75 2.75a.75.75 0 00-1.5 0v8.614L6.295 8.235a.75.75 0 10-1.09 1.03l4.25 4.5a.75.75 0 001.09 0l4.25-4.5a.75.75 0 00-1.09-1.03l-2.955 3.129V2.75z"/>
      <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
    </svg>
    Export
  </button>

  <!-- Import -->
  <input
    bind:this={fileInput}
    type="file"
    accept=".json"
    class="hidden"
    on:change={handleImport}
  />
  <button
    on:click={() => fileInput.click()}
    disabled={$isCapturing}
    class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
           px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40"
  >
    <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
      <path d="M9.25 13.25a.75.75 0 001.5 0V4.636l2.955 3.129a.75.75 0 001.09-1.03l-4.25-4.5a.75.75 0 00-1.09 0l-4.25 4.5a.75.75 0 101.09 1.03L9.25 4.636v8.614z"/>
      <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
    </svg>
    Import
  </button>

  <!-- Capture mode badge -->
  {#if modeLabel}
    <span class="px-2 py-0.5 rounded border text-[10px] font-semibold tracking-wide select-none"
      style={modeStyle}>
      {modeLabel}
    </span>
  {/if}

  <!-- Filter — pushed right -->
  <div class="flex items-center gap-2 ml-auto">
    <span class="text-[var(--nc-fg-4)] text-xs">Filter:</span>
    <input
      type="text"
      bind:value={$captureFilter}
      placeholder="ip, protocol, port…"
      class="bg-[var(--nc-surface)] text-[var(--nc-fg)] border border-[var(--nc-border)] rounded px-3 py-1 text-xs w-52
             focus:outline-none focus:border-blue-500 placeholder-[var(--nc-fg-4)]"
    />
  </div>
</header>
