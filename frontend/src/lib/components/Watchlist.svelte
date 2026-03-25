<script lang="ts">
  import { onDestroy } from 'svelte'
  import { watchEntries, watchValues, watchlistOpen, selectedPacket, scrollToSelectedTick, packets, trackMode, trackFingerprint, trackPrev } from '../stores'
  import { get } from 'svelte/store'
  import type { WatchEntry, WatchValue } from '../types'

  export let onadd: (() => void) | undefined = undefined
  export let onedit: ((entry: WatchEntry) => void) | undefined = undefined

  // 1 Hz tick for change-indicator fade (3 s window)
  const CHANGE_FLASH_MS = 3_000
  let _now = Date.now()
  const _ticker = setInterval(() => { _now = Date.now() }, 1_000)
  onDestroy(() => clearInterval(_ticker))

  // ── Column widths (persisted, drag-adjustable) ────────────────────────────
  const _COL_KEY = 'nc:watchlistCols'
  type ColWidths = { label: number; value: number; prev: number }

  function loadCols(): ColWidths {
    try {
      const raw = localStorage.getItem(_COL_KEY)
      if (raw) {
        const parsed = JSON.parse(raw) as ColWidths
        return {
          label: Math.max(40, Math.min(300, parsed.label)),
          value: Math.max(40, Math.min(300, parsed.value)),
          prev:  Math.max(40, Math.min(300, parsed.prev)),
        }
      }
    } catch {}
    return { label: 80, value: 90, prev: 70 }
  }

  let cols: ColWidths = loadCols()

  let colDrag: { col: keyof ColWidths; startX: number; startW: number } | null = null

  function colDragStart(e: MouseEvent, col: keyof ColWidths): void {
    colDrag = { col, startX: e.clientX, startW: cols[col] }
    e.preventDefault()
  }

  function colDragMove(e: MouseEvent): void {
    if (!colDrag) return
    const dx = e.clientX - colDrag.startX
    cols = { ...cols, [colDrag.col]: Math.max(40, Math.min(300, colDrag.startW + dx)) }
  }

  function colDragEnd(): void {
    if (colDrag) {
      localStorage.setItem(_COL_KEY, JSON.stringify(cols))
      colDrag = null
    }
  }

  // Group entries by their group label
  $: grouped = (() => {
    const map = new Map<string, { entry: WatchEntry; value: WatchValue | null }[]>()
    for (const entry of $watchEntries) {
      const key = entry.group || entry.matcher.interpreterName || 'Ungrouped'
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push({ entry, value: $watchValues[entry.id] ?? null })
    }
    return map
  })()

  $: entryCount = $watchEntries.length

  function isRecentChange(val: WatchValue | null): boolean {
    if (!val?.changed || !val.lastUpdate) return false
    return _now - val.lastUpdate < CHANGE_FLASH_MS
  }

  function navigateToPacket(packetId: number | null) {
    if (!packetId) return
    const pkts = get(packets)
    const pkt = pkts.find(p => p.id === packetId)
    if (pkt) {
      trackMode.set(false)
      trackFingerprint.set(null)
      trackPrev.set(null)
      selectedPacket.set(pkt)
      scrollToSelectedTick.update(n => n + 1)
    }
  }

  function removeEntry(id: string) {
    watchEntries.update(list => list.filter(e => e.id !== id))
  }

  // ── Row context menu ─────────────────────────────────────────────────────
  let ctxEntry: WatchEntry | null = null
  let ctxX = 0, ctxY = 0

  function openCtx(e: MouseEvent, entry: WatchEntry) {
    e.preventDefault()
    ctxEntry = entry
    ctxX = e.clientX
    ctxY = e.clientY
  }

  function closeCtx() { ctxEntry = null }

  function clearAll() {
    watchEntries.set([])
    watchValues.set({})
  }
</script>

<svelte:window on:mousemove={colDragMove} on:mouseup={colDragEnd} on:click={closeCtx} />

<div class="flex flex-col h-full bg-(--nc-surface) overflow-hidden border-l border-(--nc-border)">

  <!-- Header -->
  <div class="flex items-center gap-2 px-3 py-1.5 border-b border-(--nc-border-1) bg-(--nc-surface-1) shrink-0">
    <span class="text-[10px] font-semibold uppercase tracking-wider text-(--nc-fg-4)">Watchlist</span>
    {#if entryCount > 0}
      <span class="text-[9px] bg-(--nc-surface-2) text-(--nc-fg-3) rounded-full px-1.5 py-px">{entryCount}</span>
    {/if}

    <button
      on:click={() => onadd?.()}
      class="text-[10px] px-1.5 py-0.5 rounded border border-(--nc-border)
             text-(--nc-fg-4) hover:text-(--nc-fg-2) hover:bg-(--nc-surface-2) transition-colors ml-1"
      title="Add watch entry"
    >+ Add</button>

    {#if entryCount > 0}
      <button on:click={clearAll}
        class="text-[10px] px-1.5 py-0.5 rounded border border-(--nc-border)
               text-(--nc-fg-4) hover:text-red-400 hover:border-red-400/40 transition-colors"
        title="Remove all watch entries">Clear</button>
    {/if}

    <button on:click={() => watchlistOpen.set(false)}
      class="ml-auto text-(--nc-fg-4) hover:text-(--nc-fg-2) transition-colors px-1"
      title="Close watchlist panel">&times;</button>
  </div>

  <!-- Table -->
  <div class="flex-1 overflow-auto min-h-0">
    {#if entryCount === 0}
      <div class="px-4 py-4 text-center text-(--nc-fg-5) text-[10px]">
        No watched values. Click <strong>+ Add</strong> or right-click a decoded field.
      </div>
    {:else}
      <table class="w-full border-collapse text-[10px]">
        <!-- Column header with drag-resizable borders -->
        <thead class="sticky top-0 z-10 bg-(--nc-surface-1)">
          <tr class="border-b border-(--nc-border-1)">
            <!-- Dot column (fixed tiny) -->
            <th class="w-4 shrink-0"></th>
            <!-- Label -->
            <th class="text-left text-(--nc-fg-4) font-semibold uppercase tracking-wider py-1 relative select-none"
              style="width:{cols.label}px;min-width:{cols.label}px;max-width:{cols.label}px">
              <span class="px-1">Field</span>
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="absolute right-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-blue-500/40 transition-colors"
                on:mousedown={(e) => colDragStart(e, 'label')}></div>
            </th>
            <!-- Value -->
            <th class="text-left text-(--nc-fg-4) font-semibold uppercase tracking-wider py-1 relative select-none"
              style="width:{cols.value}px;min-width:{cols.value}px;max-width:{cols.value}px">
              <span class="px-1">Value</span>
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="absolute right-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-blue-500/40 transition-colors"
                on:mousedown={(e) => colDragStart(e, 'value')}></div>
            </th>
            <!-- Previous -->
            <th class="text-left text-(--nc-fg-4) font-semibold uppercase tracking-wider py-1 relative select-none"
              style="width:{cols.prev}px;min-width:{cols.prev}px;max-width:{cols.prev}px">
              <span class="px-1">Previous</span>
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div class="absolute right-0 top-0 bottom-0 w-1 cursor-col-resize hover:bg-blue-500/40 transition-colors"
                on:mousedown={(e) => colDragStart(e, 'prev')}></div>
            </th>
            <!-- Remove col (fixed tiny) -->
            <th class="w-5"></th>
          </tr>
        </thead>
        <tbody>
          {#each [...grouped] as [groupName, items]}
            <!-- Group header row -->
            <tr>
              <td colspan="5" class="px-1 pt-1.5 pb-0.5">
                <span class="text-[9px] text-(--nc-fg-4) uppercase tracking-wider font-semibold">{groupName}</span>
              </td>
            </tr>
            {#each items as { entry, value }}
              {@const recent = isRecentChange(value)}
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <tr class="group hover:bg-(--nc-surface-2) transition-colors
                {recent ? 'bg-[color-mix(in_srgb,var(--nc-status-err)_8%,transparent)]' : ''}"
                on:contextmenu={(e) => openCtx(e, entry)}>
                <!-- Dot -->
                <td class="text-center py-px">
                  <div class="w-1.5 h-1.5 rounded-full mx-auto transition-all
                    {recent ? 'bg-(--nc-status-err) animate-pulse' : value?.current != null ? 'bg-(--nc-status-ok)' : 'bg-(--nc-fg-5) opacity-30'}">
                  </div>
                </td>
                <!-- Label -->
                <td class="py-px overflow-hidden"
                  style="width:{cols.label}px;min-width:{cols.label}px;max-width:{cols.label}px">
                  <span class="block truncate px-1 text-(--nc-fg-3)" title={entry.label}>{entry.label}</span>
                </td>
                <!-- Value -->
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <td class="py-px overflow-hidden"
                  style="width:{cols.value}px;min-width:{cols.value}px;max-width:{cols.value}px"
                  on:click={() => navigateToPacket(value?.sourcePacketId ?? null)}>
                  <span class="block truncate px-1 font-mono text-[11px] cursor-pointer hover:underline
                    {recent ? 'text-(--nc-fg-1) font-bold' : 'text-(--nc-fg-1)'}"
                    title={value?.current ?? '(no value)'}>{value?.current ?? '—'}</span>
                </td>
                <!-- Previous -->
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <td class="py-px overflow-hidden"
                  style="width:{cols.prev}px;min-width:{cols.prev}px;max-width:{cols.prev}px"
                  on:click={() => navigateToPacket(value?.prevPacketId ?? null)}>
                  <span class="block truncate px-1 font-mono italic text-[11px]
                    {value?.prevPacketId ? 'text-(--nc-fg-3) cursor-pointer hover:underline' : 'text-(--nc-fg-5)'}"
                    title={value?.previous ?? ''}>{value?.previous ?? '—'}</span>
                </td>
                <!-- Remove -->
                <td class="py-px align-middle text-center">
                  <button on:click={() => removeEntry(entry.id)}
                    class="opacity-0 group-hover:opacity-100 text-(--nc-fg-3) hover:text-red-400 transition-all
                           flex items-center justify-center w-full h-full"
                    title="Remove">
                    <svg class="w-3 h-3 block" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M5.5 5.5A.5.5 0 016 6v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm2.5 0a.5.5 0 01.5.5v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm3 .5a.5.5 0 00-1 0v6a.5.5 0 001 0V6z"/>
                      <path fill-rule="evenodd" d="M14.5 3a1 1 0 01-1 1H13v9a2 2 0 01-2 2H5a2 2 0 01-2-2V4h-.5a1 1 0 010-2h3a1 1 0 011-1h2a1 1 0 011 1h3a1 1 0 011 1zM4.118 4L4 4.059V13a1 1 0 001 1h6a1 1 0 001-1V4.059L11.882 4H4.118zM2.5 3h11a.5.5 0 000-1h-11a.5.5 0 000 1z" clip-rule="evenodd"/>
                    </svg>
                  </button>
                </td>
              </tr>
            {/each}
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<!-- Row context menu -->
{#if ctxEntry}
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <div class="fixed z-200 min-w-36 bg-(--nc-surface-1) border border-(--nc-border)
              rounded shadow-lg py-1 text-xs"
    style="left:{ctxX}px;top:{ctxY}px"
    on:click|stopPropagation
    on:contextmenu|preventDefault|stopPropagation>
    <button on:click={() => { if (ctxEntry) onedit?.(ctxEntry); closeCtx() }}
      class="w-full text-left flex items-center gap-2 px-3 py-1.5
             text-(--nc-fg-2) hover:bg-(--nc-surface-2) hover:text-(--nc-fg) transition-colors">
      <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 16 16" fill="currentColor">
        <path d="M12.146.146a.5.5 0 01.708 0l3 3a.5.5 0 010 .708l-10 10a.5.5 0 01-.168.11l-5 2a.5.5 0 01-.65-.65l2-5a.5.5 0 01.11-.168l10-10zM11.207 2.5L13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 01.5.5v.5h.5a.5.5 0 01.5.5v.5h.293l6.5-6.5zm-9.761 5.175l-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 015 12.5V12h-.5a.5.5 0 01-.5-.5V11h-.5a.5.5 0 01-.468-.325z"/>
      </svg>
      Edit
    </button>
    <div class="border-t border-(--nc-border) my-1"></div>
    <button on:click={() => { removeEntry(ctxEntry!.id); closeCtx() }}
      class="w-full text-left flex items-center gap-2 px-3 py-1.5
             text-(--nc-fg-2) hover:bg-(--nc-surface-2) hover:text-red-400 transition-colors">
      <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 16 16" fill="currentColor">
        <path d="M5.5 5.5A.5.5 0 016 6v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm2.5 0a.5.5 0 01.5.5v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm3 .5a.5.5 0 00-1 0v6a.5.5 0 001 0V6z"/>
        <path fill-rule="evenodd" d="M14.5 3a1 1 0 01-1 1H13v9a2 2 0 01-2 2H5a2 2 0 01-2-2V4h-.5a1 1 0 010-2h3a1 1 0 011-1h2a1 1 0 011 1h3a1 1 0 011 1zM4.118 4L4 4.059V13a1 1 0 001 1h6a1 1 0 001-1V4.059L11.882 4H4.118zM2.5 3h11a.5.5 0 000-1h-11a.5.5 0 000 1z" clip-rule="evenodd"/>
      </svg>
      Remove
    </button>
  </div>
{/if}
