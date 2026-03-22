<script lang="ts">
  import { createEventDispatcher, tick } from 'svelte'
  import { addressBook } from '../stores'
  import { saveAddressBook } from '../captureService'
  import type { AddressBookEntry } from '../types'

  /** When set, pre-fills the new-entry row with this address so the user just types a name. */
  export let prefill: string = ''

  const dispatch = createEventDispatcher()

  // Work on a local copy so Cancel reverts all changes
  let entries: AddressBookEntry[] = $addressBook.map(e => ({ ...e }))

  let newAddress = prefill
  let newName    = ''
  let newNotes   = ''
  let nameInputEl: HTMLInputElement

  // Auto-focus name input when opened with a prefill so user only needs to type the name
  $: if (prefill && nameInputEl) tick().then(() => nameInputEl?.focus())
  let saving     = false
  let dirty      = false

  function markDirty() { dirty = true }

  function addEntry() {
    const addr = newAddress.trim()
    const name = newName.trim()
    if (!addr || !name) return
    entries = [...entries, {
      id:      crypto.randomUUID(),
      address: addr,
      name,
      notes:   newNotes.trim() || undefined,
    }]
    newAddress = ''
    newName    = ''
    newNotes   = ''
    dirty = true
  }

  function removeEntry(id: string) {
    entries = entries.filter(e => e.id !== id)
    dirty = true
  }

  function handleNewKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') addEntry()
  }

  async function save() {
    // Filter out entries with empty address or name to prevent blank matches
    entries = entries.filter(e => e.address.trim() && e.name.trim())
    saving = true
    await saveAddressBook(entries)
    addressBook.set(entries)
    saving = false
    dirty  = false
    dispatch('close')
  }

  function cancel() {
    dispatch('close')
  }

  // ── Column resize ──────────────────────────────────────────────────────────
  let colWidths = { address: 192, name: 160 }  // notes col is flex remainder

  let resizingCol: keyof typeof colWidths | null = null
  let resizeStartX = 0
  let resizeStartW = 0

  function startResize(e: MouseEvent, col: keyof typeof colWidths) {
    resizingCol  = col
    resizeStartX = e.clientX
    resizeStartW = colWidths[col]
    document.body.style.cursor = 'col-resize'
    window.addEventListener('mousemove', onResizeMove)
    window.addEventListener('mouseup',   onResizeUp)
    e.preventDefault()
  }

  function onResizeMove(e: MouseEvent) {
    if (!resizingCol) return
    const delta = e.clientX - resizeStartX
    colWidths[resizingCol] = Math.max(80, resizeStartW + delta)
    colWidths = colWidths  // trigger reactivity
  }

  function onResizeUp() {
    resizingCol = null
    document.body.style.cursor = ''
    window.removeEventListener('mousemove', onResizeMove)
    window.removeEventListener('mouseup',   onResizeUp)
  }
</script>

<div class="fixed inset-0 z-100 flex items-center justify-center bg-black/60">
  <div
    class="flex flex-col rounded-lg shadow-2xl bg-(--nc-surface-1) border border-(--nc-border)"
    style="width: 680px; height: 520px; min-width: 420px; min-height: 280px; resize: both; overflow: hidden;"
  >
    <!-- Header -->
    <div class="flex items-center justify-between px-5 py-3 border-b border-(--nc-border) shrink-0">
      <div>
        <div class="font-semibold text-sm text-(--nc-fg)">Address Book</div>
        <div class="text-[10px] text-(--nc-fg-4) mt-0.5">
          Requires an IP address; port is optional (e.g. <span class="font-mono">192.168.1.1</span> or <span class="font-mono">192.168.1.1:9001</span>).
          Filter by name using <span class="font-mono">src_name</span>, <span class="font-mono">dst_name</span>, or <span class="font-mono">ip.src == "MyDevice"</span>.
        </div>
      </div>
      <button
        on:click={cancel}
        class="text-(--nc-fg-4) hover:text-(--nc-fg) transition-colors p-1"
        title="Close"
      >
        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/>
        </svg>
      </button>
    </div>

    <!-- Table -->
    <div class="flex-1 overflow-y-auto min-h-0">
      <table class="w-full text-xs border-collapse" style="table-layout: fixed;">
        <colgroup>
          <col style="width: {colWidths.address}px" />
          <col style="width: {colWidths.name}px" />
          <col />
          <col style="width: 32px" />
        </colgroup>
        <thead class="sticky top-0 bg-(--nc-surface-1) z-10">
          <tr class="text-[10px] uppercase tracking-wider text-(--nc-fg-4) border-b border-(--nc-border)">
            <th class="text-left px-4 py-2 font-semibold relative group/rh select-none">
              IP or IP:Port
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div
                class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100
                       hover:bg-blue-500/40 transition-opacity"
                on:mousedown={(e) => startResize(e, 'address')}
              ></div>
            </th>
            <th class="text-left px-4 py-2 font-semibold relative group/rh select-none">
              Name
              <!-- svelte-ignore a11y-no-static-element-interactions -->
              <div
                class="absolute right-0 top-0 h-full w-1.5 cursor-col-resize opacity-0 group-hover/rh:opacity-100
                       hover:bg-blue-500/40 transition-opacity"
                on:mousedown={(e) => startResize(e, 'name')}
              ></div>
            </th>
            <th class="text-left px-4 py-2 font-semibold">Notes</th>
            <th class="w-8"></th>
          </tr>
        </thead>
        <tbody>
          {#each entries as entry (entry.id)}
            <tr class="border-b border-(--nc-border-1) hover:bg-(--nc-surface-2) group">
              <td class="px-4 py-1.5 truncate">
                <input
                  bind:value={entry.address}
                  on:input={markDirty}
                  class="w-full bg-transparent text-(--nc-fg) font-mono focus:outline-none
                         focus:bg-(--nc-surface) rounded px-1 -mx-1"
                  placeholder="192.168.1.1"
                />
              </td>
              <td class="px-4 py-1.5 truncate">
                <input
                  bind:value={entry.name}
                  on:input={markDirty}
                  class="w-full bg-transparent text-(--nc-fg) focus:outline-none
                         focus:bg-(--nc-surface) rounded px-1 -mx-1"
                  placeholder="My Device"
                />
              </td>
              <td class="px-4 py-1.5 truncate">
                <input
                  bind:value={entry.notes}
                  on:input={markDirty}
                  class="w-full bg-transparent text-(--nc-fg-3) focus:outline-none
                         focus:bg-(--nc-surface) rounded px-1 -mx-1"
                  placeholder="Optional notes"
                />
              </td>
              <td class="pr-3 text-center">
                <button
                  on:click={() => removeEntry(entry.id)}
                  class="opacity-0 group-hover:opacity-100 text-(--nc-fg-4) hover:text-red-400 transition-all"
                  title="Remove"
                >
                  <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z" clip-rule="evenodd"/>
                  </svg>
                </button>
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="4" class="px-4 py-6 text-center text-(--nc-fg-5) text-xs">
                No entries yet. Add one below.
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- Add new entry row -->
    <div class="shrink-0 border-t border-(--nc-border) px-4 py-3 bg-(--nc-surface)">
      <div class="flex items-center gap-2">
        <input
          bind:value={newAddress}
          on:keydown={handleNewKeydown}
          class="w-48 bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border)
                 rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
          placeholder="192.168.1.1"
        />
        <input
          bind:this={nameInputEl}
          bind:value={newName}
          on:keydown={handleNewKeydown}
          class="w-36 bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border)
                 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
          placeholder="Name"
        />
        <input
          bind:value={newNotes}
          on:keydown={handleNewKeydown}
          class="flex-1 bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border)
                 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
          placeholder="Notes (optional)"
        />
        <button
          on:click={addEntry}
          disabled={!newAddress.trim() || !newName.trim()}
          class="shrink-0 bg-blue-700 hover:bg-blue-600 disabled:opacity-40 disabled:cursor-not-allowed
                 text-white px-3 py-1 rounded text-xs font-semibold transition-colors"
        >
          Add
        </button>
      </div>
    </div>

    <!-- Footer -->
    <div class="shrink-0 flex items-center justify-end gap-2 px-5 py-3 border-t border-(--nc-border)">
      <button
        on:click={cancel}
        class="px-3 py-1 rounded text-xs border border-(--nc-border)
               text-(--nc-fg-2) hover:bg-(--nc-surface-2) transition-colors"
      >
        Cancel
      </button>
      <button
        on:click={save}
        disabled={saving}
        class="px-3 py-1 rounded text-xs bg-blue-700 hover:bg-blue-600 disabled:opacity-50
               text-white font-semibold transition-colors"
      >
        {saving ? 'Saving…' : 'Save'}
      </button>
    </div>
  </div>
</div>
