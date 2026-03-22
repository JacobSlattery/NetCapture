<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import type { Packet, WatchEntry, WatchMatcher } from '../types'

  export let editEntry: WatchEntry | null = null
  export let prefillFromPacket: Packet | null = null
  export let prefillFieldKey: string | null = null

  const dispatch = createEventDispatcher()

  // ── Form state ────────────────────────────────────────────────────────────
  let label     = editEntry?.label     ?? prefillFieldKey ?? ''
  let fieldPath = editEntry?.fieldPath ?? prefillFieldKey ?? ''
  let group     = editEntry?.group     ?? prefillFromPacket?.decoded?.interpreterName ?? ''

  // Matcher fields — pre-fill from packet context or edit entry
  let mProtocol        = editEntry?.matcher.protocol        ?? prefillFromPacket?.protocol ?? ''
  let mSrcIp           = editEntry?.matcher.src_ip          ?? prefillFromPacket?.src_ip ?? ''
  let mDstIp           = editEntry?.matcher.dst_ip          ?? prefillFromPacket?.dst_ip ?? ''
  let mSrcPort: string = editEntry?.matcher.src_port != null ? String(editEntry.matcher.src_port)
                        : prefillFromPacket?.src_port != null ? String(prefillFromPacket.src_port) : ''
  let mDstPort: string = editEntry?.matcher.dst_port != null ? String(editEntry.matcher.dst_port)
                        : prefillFromPacket?.dst_port != null ? String(prefillFromPacket.dst_port) : ''

  let mInterpreter     = editEntry?.matcher.interpreterName ?? prefillFromPacket?.decoded?.interpreterName ?? ''

  // Available decoded field keys from the prefill packet (for autocomplete hints)
  $: availableFields = prefillFromPacket?.decoded?.fields.map(f => f.key) ?? []

  function save() {
    const trimLabel = label.trim()
    const trimPath  = fieldPath.trim()
    if (!trimLabel || !trimPath) return

    const matcher: WatchMatcher = {}
    if (mProtocol.trim())    matcher.protocol        = mProtocol.trim()
    if (mSrcIp.trim())       matcher.src_ip          = mSrcIp.trim()
    if (mDstIp.trim())       matcher.dst_ip          = mDstIp.trim()
    if (mSrcPort.trim())     matcher.src_port = Number(mSrcPort.trim()) || null
    if (mDstPort.trim())     matcher.dst_port = Number(mDstPort.trim()) || null
    if (mInterpreter.trim()) matcher.interpreterName  = mInterpreter.trim()

    const entry: WatchEntry = {
      id:        editEntry?.id ?? crypto.randomUUID(),
      label:     trimLabel,
      matcher,
      fieldPath: trimPath,
      group:     group.trim() || undefined,
    }

    dispatch('save', entry)
  }

  function cancel() {
    dispatch('close')
  }

  function handleKey(e: KeyboardEvent) {
    if (e.key === 'Escape') cancel()
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) save()
  }
</script>

<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
<!-- svelte-ignore a11y-interactive-supports-focus -->
<div class="fixed inset-0 z-100 flex items-center justify-center bg-black/60" on:keydown={handleKey} role="dialog">
  <div class="rounded-lg shadow-2xl bg-(--nc-surface-1) border border-(--nc-border)"
    style="width: 480px; max-height: 90vh; overflow-y: auto;">

    <!-- Header -->
    <div class="flex items-center justify-between px-5 py-3 border-b border-(--nc-border)">
      <div>
        <div class="font-semibold text-sm text-(--nc-fg)">
          {editEntry ? 'Edit Watch Entry' : 'Add Watch Entry'}
        </div>
        <div class="text-[10px] text-(--nc-fg-4) mt-0.5">
          Watch a specific decoded field across matching packets.
        </div>
      </div>
      <button on:click={cancel} aria-label="Close" class="text-(--nc-fg-4) hover:text-(--nc-fg) transition-colors p-1">
        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/>
        </svg>
      </button>
    </div>

    <!-- Form -->
    <div class="px-5 py-4 space-y-4">

      <!-- Label & Field path -->
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="block text-[10px] text-(--nc-fg-4) uppercase tracking-wider mb-1" for="wl-label">Label</label>
          <input id="wl-label" bind:value={label}
            class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                   rounded px-2 py-1.5 text-xs focus:outline-none focus:border-blue-500"
            placeholder="e.g. Temperature" />
        </div>
        <div>
          <label class="block text-[10px] text-(--nc-fg-4) uppercase tracking-wider mb-1" for="wl-field">Field path</label>
          <input id="wl-field" bind:value={fieldPath} list="wl-field-hints"
            class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                   rounded px-2 py-1.5 text-xs font-mono focus:outline-none focus:border-blue-500"
            placeholder="e.g. temperature or status.code" />
          {#if availableFields.length > 0}
            <datalist id="wl-field-hints">
              {#each availableFields as f}
                <option value={f}></option>
              {/each}
            </datalist>
          {/if}
        </div>
      </div>

      <!-- Group -->
      <div>
        <label class="block text-[10px] text-(--nc-fg-4) uppercase tracking-wider mb-1" for="wl-group">Group (optional)</label>
        <input id="wl-group" bind:value={group}
          class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                 rounded px-2 py-1.5 text-xs focus:outline-none focus:border-blue-500"
          placeholder="Defaults to interpreter name" />
      </div>

      <!-- Matcher section -->
      <div>
        <div class="text-[10px] text-(--nc-fg-4) uppercase tracking-wider mb-2">
          Packet matcher
          <span class="normal-case tracking-normal text-(--nc-fg-5)"> — leave fields empty to match any</span>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-proto">Protocol</label>
            <input id="wl-proto" bind:value={mProtocol}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500"
              placeholder="e.g. UDP" />
          </div>
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-interp">Interpreter</label>
            <input id="wl-interp" bind:value={mInterpreter}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              placeholder="e.g. nc-frame" />
          </div>
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-srcip">Source IP</label>
            <input id="wl-srcip" bind:value={mSrcIp}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              placeholder="e.g. 192.168.1.1" />
          </div>
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-dstip">Dest IP</label>
            <input id="wl-dstip" bind:value={mDstIp}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              placeholder="e.g. 10.0.0.1" />
          </div>
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-srcport">Source port</label>
            <input id="wl-srcport" bind:value={mSrcPort}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              placeholder="Any" />
          </div>
          <div>
            <label class="block text-[9px] text-(--nc-fg-5) mb-0.5" for="wl-dstport">Dest port</label>
            <input id="wl-dstport" bind:value={mDstPort}
              class="w-full bg-(--nc-surface) text-(--nc-fg) border border-(--nc-border)
                     rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500"
              placeholder="Any" />
          </div>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <div class="flex items-center justify-end gap-2 px-5 py-3 border-t border-(--nc-border)">
      <button on:click={cancel}
        class="px-3 py-1.5 rounded text-xs border border-(--nc-border)
               text-(--nc-fg-2) hover:bg-(--nc-surface-2) transition-colors">
        Cancel
      </button>
      <button on:click={save}
        disabled={!label.trim() || !fieldPath.trim()}
        class="px-3 py-1.5 rounded text-xs bg-blue-700 hover:bg-blue-600
               disabled:opacity-40 disabled:cursor-not-allowed
               text-white font-semibold transition-colors">
        {editEntry ? 'Update' : 'Add to Watchlist'}
      </button>
    </div>
  </div>
</div>
