<script lang="ts">
  import { interfaces } from '../stores'
  import type { CaptureProfile } from '../types'

  export let profiles: CaptureProfile[] = []
  type ProfileData = Omit<CaptureProfile, 'id' | 'builtin'>

  export let onclose: (() => void) | undefined = undefined
  export let oncreate: ((data: ProfileData) => void) | undefined = undefined
  export let onupdate: ((payload: { id: string; data: ProfileData }) => void) | undefined = undefined
  export let ondelete: ((id: string) => void) | undefined = undefined

  // ── Form state ─────────────────────────────────────────────────────────────
  let editingId: string | null = null

  let form = emptyForm()

  function emptyForm() {
    return { name: '', description: '', interface: 'any', filter: '', bpf_filter: '', inject: false }
  }

  function startEdit(p: CaptureProfile): void {
    editingId = p.id
    form = {
      name:        p.name,
      description: p.description ?? '',
      interface:   p.interface,
      filter:      p.filter ?? '',
      bpf_filter:  p.bpf_filter ?? '',
      inject:      p.inject ?? false,
    }
  }

  function cancelEdit(): void {
    editingId = null
    form = emptyForm()
  }

  function save(): void {
    if (!form.name.trim()) return
    if (editingId !== null) {
      onupdate?.({ id: editingId, data: { ...form } })
    } else {
      oncreate?.({ ...form })
    }
    cancelEdit()
  }

  function remove(id: string): void {
    ondelete?.(id)
    if (editingId === id) cancelEdit()
  }

  function handleKey(e: KeyboardEvent): void {
    if (e.key === 'Enter') save()
    if (e.key === 'Escape') cancelEdit()
  }

  $: formTitle = editingId !== null ? 'Edit Profile' : 'New Profile'
  $: saveLabel = editingId !== null ? 'Save Changes' : 'Add Profile'
  $: canSave   = form.name.trim().length > 0
</script>

<div class="fixed inset-0 z-100 flex items-center justify-center bg-black/60">
  <div
    class="flex flex-col rounded-lg shadow-2xl bg-(--nc-surface-1) border border-(--nc-border)"
    style="width: 760px; height: 600px; min-width: 420px; min-height: 300px; resize: both; overflow: hidden;"
  >

    <!-- Header -->
    <div class="flex items-center justify-between px-5 py-3 border-b border-(--nc-border) shrink-0">
      <div>
        <div class="font-semibold text-sm text-(--nc-fg)">Capture Profiles</div>
        <div class="text-[10px] text-(--nc-fg-4) mt-0.5">
          Built-in profiles are read-only. User-created profiles persist across sessions.
        </div>
      </div>
      <button on:click={() => onclose?.()} aria-label="Close"
        class="text-(--nc-fg-4) hover:text-(--nc-fg) transition-colors p-1">
        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
          <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/>
        </svg>
      </button>
    </div>

    <!-- Profile list -->
    <div class="flex-1 overflow-y-auto min-h-0">
      <table class="w-full text-xs border-collapse" style="table-layout: fixed;">
        <colgroup>
          <col style="width: 160px" />
          <col style="width: 110px" />
          <col />
          <col style="width: 160px" />
          <col style="width: 56px" />
        </colgroup>
        <thead class="sticky top-0 bg-(--nc-surface-1) z-10">
          <tr class="text-[10px] uppercase tracking-wider text-(--nc-fg-4) border-b border-(--nc-border)">
            <th class="text-left px-4 py-2 font-semibold">Name</th>
            <th class="text-left px-3 py-2 font-semibold">Interface</th>
            <th class="text-left px-3 py-2 font-semibold">Capture Filter</th>
            <th class="text-left px-3 py-2 font-semibold">BPF Filter</th>
            <th class="w-14"></th>
          </tr>
        </thead>
        <tbody>
          {#each profiles as prof}
            {@const isEditing = editingId === prof.id}
            <tr
              class="border-b border-(--nc-border-1) group transition-colors
                     {isEditing ? 'bg-(--nc-surface-2)' : 'hover:bg-(--nc-surface-2)'}
                     {prof.builtin ? 'opacity-70' : ''}"
            >
              <td class="px-4 py-2 truncate">
                <div class="flex items-center gap-1.5">
                  {#if prof.builtin}
                    <!-- Lock icon for built-ins -->
                    <svg class="w-3 h-3 shrink-0 text-(--nc-fg-4)" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clip-rule="evenodd"/>
                    </svg>
                  {/if}
                  <span class="truncate text-(--nc-fg-1)" title={prof.description || prof.name}>
                    {prof.name}
                  </span>
                </div>
              </td>
              <td class="px-3 py-2 text-(--nc-fg-2)">
                <div class="flex items-center gap-1.5 min-w-0">
                  {#if prof.inject}
                    <span class="shrink-0 text-[9px] px-1 py-0.5 rounded bg-blue-900/40 text-blue-300 font-sans leading-none">INJ</span>
                  {/if}
                  <span class="font-mono truncate">{prof.interface || (prof.inject ? '—' : 'any')}</span>
                </div>
              </td>
              <td class="px-3 py-2 truncate font-mono text-(--nc-fg-2)">{prof.filter || '—'}</td>
              <td class="px-3 py-2 truncate font-mono text-(--nc-fg-2)">{prof.bpf_filter || '—'}</td>
              <td class="pr-3 text-center">
                {#if !prof.builtin}
                  <div class="flex items-center justify-center gap-1
                              opacity-0 group-hover:opacity-100 transition-opacity">
                    <button on:click={() => startEdit(prof)} title="Edit"
                      class="text-(--nc-fg-4) hover:text-blue-400 transition-colors p-0.5">
                      <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
                        <path d="M2.695 14.763l-1.262 3.154a.5.5 0 00.65.65l3.155-1.262a4 4 0 001.343-.885L17.5 5.5a2.121 2.121 0 00-3-3L3.58 13.42a4 4 0 00-.885 1.343z"/>
                      </svg>
                    </button>
                    <button on:click={() => remove(prof.id)} title="Delete"
                      class="text-(--nc-fg-4) hover:text-red-400 transition-colors p-0.5">
                      <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z" clip-rule="evenodd"/>
                      </svg>
                    </button>
                  </div>
                {/if}
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="5" class="px-4 py-6 text-center text-(--nc-fg-5) text-xs">
                No profiles yet.
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- Add / edit form -->
    <div class="shrink-0 border-t border-(--nc-border) bg-(--nc-surface) px-5 py-4">
      <div class="text-[10px] uppercase tracking-wider text-(--nc-fg-4) font-semibold mb-3">
        {formTitle}
      </div>

      <!-- Row 1: name + description -->
      <div class="grid grid-cols-2 gap-3 mb-3">
        <label class="flex flex-col gap-1">
          <span class="text-[10px] text-(--nc-fg-4)">Name <span class="text-red-400">*</span></span>
          <input bind:value={form.name} on:keydown={handleKey} placeholder="My Device"
            class="bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border) rounded
                   px-2 py-1 text-xs focus:outline-none focus:border-blue-500" />
        </label>
        <label class="flex flex-col gap-1">
          <span class="text-[10px] text-(--nc-fg-4)">Description</span>
          <input bind:value={form.description} on:keydown={handleKey} placeholder="Optional notes"
            class="bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border) rounded
                   px-2 py-1 text-xs focus:outline-none focus:border-blue-500" />
        </label>
      </div>

      <!-- Row 2: interface (combo) + inject toggle -->
      <div class="flex flex-col gap-1 mb-3">
        <div class="flex items-center justify-between">
          <span class="text-[10px] text-(--nc-fg-4)">
            Interface
            <span class="text-(--nc-fg-5) ml-1">— leave empty for {form.inject ? 'inject-only' : '"any"'}; comma-separate for multiple (npcap only)</span>
          </span>
          <label class="flex items-center gap-1.5 cursor-pointer select-none"
            title="Accept packets via /ws/inject alongside real capture, or as the sole source when no interface is set">
            <input type="checkbox" bind:checked={form.inject} class="accent-blue-500 w-3 h-3" />
            <span class="text-[10px] text-(--nc-fg-3)">Enable injection</span>
          </label>
        </div>
        <input
          bind:value={form.interface}
          on:keydown={handleKey}
          list="nc-profile-ifaces"
          placeholder={form.inject && !form.interface.trim() ? '(none — injection only)' : 'any'}
          class="bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border) rounded
                 px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500 w-full"
        />
        <datalist id="nc-profile-ifaces">
          {#each $interfaces as iface}
            <option value={iface.name}>{iface.description ?? iface.name}</option>
          {/each}
        </datalist>
      </div>

      <!-- Row 3: capture filter + BPF filter -->
      <div class="grid grid-cols-2 gap-3 mb-4">
        <label class="flex flex-col gap-1">
          <span class="text-[10px] text-(--nc-fg-4)">
            Capture Filter
            <span class="text-(--nc-fg-5) ml-1">— Python syntax: port == 9001</span>
          </span>
          <input bind:value={form.filter} on:keydown={handleKey}
            placeholder="port == 9001"
            class="bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border) rounded
                   px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500" />
        </label>
        <label class="flex flex-col gap-1">
          <span class="text-[10px] text-(--nc-fg-4)">
            BPF Filter
            <span class="text-(--nc-fg-5) ml-1">— npcap only: udp port 9001</span>
          </span>
          <input bind:value={form.bpf_filter} on:keydown={handleKey}
            placeholder="udp port 9001"
            class="bg-(--nc-surface-1) text-(--nc-fg) border border-(--nc-border) rounded
                   px-2 py-1 text-xs font-mono focus:outline-none focus:border-blue-500" />
        </label>
      </div>

      <!-- Actions -->
      <div class="flex items-center justify-end gap-2">
        {#if editingId !== null}
          <button on:click={cancelEdit}
            class="px-3 py-1 rounded text-xs border border-(--nc-border)
                   text-(--nc-fg-2) hover:bg-(--nc-surface-2) transition-colors">
            Cancel
          </button>
        {/if}
        <button on:click={save} disabled={!canSave}
          class="px-3 py-1 rounded text-xs bg-blue-700 hover:bg-blue-600
                 disabled:opacity-40 disabled:cursor-not-allowed
                 text-white font-semibold transition-colors">
          {saveLabel}
        </button>
      </div>
    </div>

  </div>
</div>
