<script lang="ts">
  import { createEventDispatcher, tick } from 'svelte'
  import {
    isCapturing, connectionStatus, selectedInterface,
    interfaces, captureFilter, captureMode, profiles, activeProfile, packets,
    addressBook, addressBookPrefill, timestampMode,
    autoScrollEnabled, maxPackets, capturePacketLimit, ringBuffer, columnVisibility,
    bpfFilter, filterFocusTick, filteredPackets, dnsCache, npcapAvailable,
  } from '../stores'
  import type { CaptureProfile, DecodedValue, AddressBookEntry } from '../types'
  import type { ColumnVisibility } from '../stores'
  import { exportCapture, importCapture, saveAddressBook, exportPcap, importPcap, exportCsv, importCsv } from '../captureService'
  import { parseFilter, tokenize, KNOWN_FIELDS } from '../filter'
  import AddressBookEditor from './AddressBookEditor.svelte'
  import PresetEditor from './PresetEditor.svelte'

  const dispatch = createEventDispatcher()

  // ── Modal / panel state ────────────────────────────────────────────────────
  let showSettings     = false
  let showPresets      = false   // filter-bar presets dropdown
  let showAddressBook  = false
  let showPresetEditor = false
  let addressPrefill   = ''

  // Open address book editor when another component (e.g. PacketTable) requests it
  $: if ($addressBookPrefill !== null) {
    addressPrefill  = $addressBookPrefill
    showAddressBook = true
    addressBookPrefill.set(null)
  }

  // ── File input refs ────────────────────────────────────────────────────────
  let captureFileInput:  HTMLInputElement
  let addrBookFileInput: HTMLInputElement
  let presetFileInput:   HTMLInputElement
  let pcapFileInput:     HTMLInputElement
  let csvFileInput:      HTMLInputElement

  // ── Recording submenu state ────────────────────────────────────────────────
  let exportOpen = false
  let importOpen = false
  let exportMenuPos = { x: 0, y: 0 }
  let importMenuPos = { x: 0, y: 0 }

  function openExportMenu(e: MouseEvent): void {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    exportMenuPos = { x: rect.left, y: rect.top }
    exportOpen = !exportOpen
    importOpen = false
  }

  function openImportMenu(e: MouseEvent): void {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    importMenuPos = { x: rect.left, y: rect.top }
    importOpen = !importOpen
    exportOpen = false
  }

  async function handleCaptureImport(e: Event): Promise<void> {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    try { await importCapture(file) } catch (err) { console.error('[import]', err) }
    finally { captureFileInput.value = '' }
  }

  function handlePcapImport(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (file) { importPcap(file).catch(console.error); (e.target as HTMLInputElement).value = '' }
    showSettings = false
  }

  function handleCsvImport(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (file) { importCsv(file).catch(console.error); (e.target as HTMLInputElement).value = '' }
    showSettings = false
  }

  function handleCsvExport() {
    const cache = new Map(Object.entries($dnsCache))
    exportCsv($filteredPackets, $columnVisibility, $timestampMode, cache)
    showSettings = false
  }

  function exportAddrBook(): void {
    download('netcapture-addresses.json', JSON.stringify($addressBook, null, 2))
  }

  function handleAddrBookImport(e: Event): void {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    file.text().then(text => {
      try {
        const parsed = JSON.parse(text) as AddressBookEntry[]
        if (!Array.isArray(parsed)) throw new Error('Expected a JSON array')
        addressBook.set(parsed)
        saveAddressBook(parsed)
      } catch (err) { console.error('[addr-import]', err) }
    }).finally(() => { addrBookFileInput.value = '' })
  }

  function exportPresets(): void {
    download('netcapture-presets.json', JSON.stringify(userPresets, null, 2))
  }

  function handlePresetImport(e: Event): void {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    file.text().then(text => {
      try {
        const parsed = JSON.parse(text) as { title: string; filter: string }[]
        if (!Array.isArray(parsed)) throw new Error('Expected a JSON array')
        // Merge: skip duplicates by filter string
        const existing = new Set(userPresets.map(p => p.filter))
        const merged = [...userPresets, ...parsed.filter(p => !existing.has(p.filter))]
        saveUserPresets(merged)
      } catch (err) { console.error('[preset-import]', err) }
    }).finally(() => { presetFileInput.value = '' })
  }

  // ── Download helper ────────────────────────────────────────────────────────
  function download(filename: string, content: string): void {
    const blob = new Blob([content], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = filename
    document.body.appendChild(a); a.click()
    document.body.removeChild(a); URL.revokeObjectURL(url)
  }

  // ── Profile / interface selection ──────────────────────────────────────────

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
        if ($npcapAvailable && prof.bpf_filter != null) bpfFilter.set(prof.bpf_filter)
      }
    } else {
      activeProfile.set(null)
      selectedInterface.set(val.slice('iface:'.length))
    }
  }

  // ── BPF presets ────────────────────────────────────────────────────────────
  let showBpfPresets = false
  const BPF_PRESETS = [
    { label: 'TCP only',          value: 'tcp' },
    { label: 'UDP only',          value: 'udp' },
    { label: 'ICMP only',         value: 'icmp' },
    { label: 'DNS  (port 53)',    value: 'port 53' },
    { label: 'HTTP  (port 80)',   value: 'port 80' },
    { label: 'HTTPS  (port 443)', value: 'tcp port 443' },
    { label: 'TCP + HTTPS',       value: 'tcp and port 443' },
    { label: 'Specific host',     value: 'host 192.168.1.1' },
  ]

  // ── Status / mode display ──────────────────────────────────────────────────

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

  // ── Built-in filter presets ────────────────────────────────────────────────

  const BUILTIN_PRESETS: { title: string; filter: string }[] = [
    { title: 'TCP only',                    filter: 'tcp' },
    { title: 'UDP only',                    filter: 'udp' },
    { title: 'ICMP only',                   filter: 'icmp' },
    { title: 'ARP only',                    filter: 'arp' },
    { title: 'Exclude ARP',                 filter: 'not arp' },
    { title: 'HTTP (port 80)',              filter: 'proto == HTTP || port == 80' },
    { title: 'HTTPS / TLS (port 443)',      filter: 'proto == TLS || port == 443' },
    { title: 'DNS (port 53)',               filter: 'proto == DNS || port == 53' },
    { title: 'SSH (port 22)',               filter: 'port == 22' },
    { title: 'Web traffic (80 or 443)',     filter: 'port == 80 || port == 443' },
    { title: 'UDP Device feed (port 9001)', filter: 'port == 9001' },
    { title: 'Inbound to port 80',          filter: 'dst.port == 80' },
    { title: 'Outbound from port 80',       filter: 'src.port == 80' },
    { title: 'Specific host (either dir)',  filter: 'ip.addr == 192.168.1.1' },
    { title: 'From specific host',          filter: 'ip.src == 192.168.1.1' },
    { title: 'To specific host',            filter: 'ip.dst == 192.168.1.1' },
    { title: 'Subnet match (contains)',     filter: 'ip.addr contains 192.168' },
    { title: 'Exclude host',               filter: 'ip.addr != 192.168.1.1' },
    { title: 'Between two hosts',           filter: 'ip.src == 192.168.1.1 || ip.src == 10.0.0.1' },
    { title: 'TCP from specific host',      filter: 'ip.src == 192.168.1.1 && proto == TCP' },
    { title: 'TCP SYN packets',             filter: 'tcp && info contains "SYN"' },
    { title: 'TLS handshake',               filter: 'info contains "handshake"' },
    { title: 'ICMP echo (ping)',            filter: 'icmp && (info contains "request" || info contains "reply")' },
    { title: 'NC-Frame packets only',       filter: 'interpreter == NC-Frame' },
    { title: 'Decoded field equals value',  filter: 'decoded.temperature == 25.0' },
    { title: 'NC-Frame on UDP port 9001',   filter: 'interpreter == NC-Frame && port == 9001' },
  ]

  // ── User presets (localStorage) ───────────────────────────────────────────

  const PRESET_KEY = 'nc:userPresets'
  type UserPreset = { title: string; filter: string }

  // Seed with built-ins on first launch (when key is absent); otherwise use saved list
  let userPresets: UserPreset[] = (() => {
    try {
      const saved = localStorage.getItem(PRESET_KEY)
      if (saved === null) return BUILTIN_PRESETS.map(p => ({ ...p }))
      return JSON.parse(saved) as UserPreset[]
    }
    catch { return BUILTIN_PRESETS.map(p => ({ ...p })) }
  })()

  function saveUserPresets(presets: UserPreset[]): void {
    userPresets = presets
    localStorage.setItem(PRESET_KEY, JSON.stringify(presets))
  }

  // ── Filter history ─────────────────────────────────────────────────────────

  const HIST_KEY = 'nc:filterHistory'
  const MAX_HIST = 15

  let filterHistory: string[] = (() => {
    try { return JSON.parse(localStorage.getItem(HIST_KEY) ?? '[]') as string[] }
    catch { return [] }
  })()

  function pushHistory(filter: string): void {
    filterHistory = [filter, ...filterHistory.filter(h => h !== filter)].slice(0, MAX_HIST)
    localStorage.setItem(HIST_KEY, JSON.stringify(filterHistory))
  }

  // ── Decoded field path discovery ──────────────────────────────────────────

  function collectDecodedPaths(v: DecodedValue, prefix: string, out: Set<string>): void {
    out.add(prefix)
    if (Array.isArray(v)) {
      for (const item of v) collectDecodedPaths(item as DecodedValue, prefix, out)
    } else if (typeof v === 'object' && v !== null) {
      for (const [k, child] of Object.entries(v as Record<string, DecodedValue>)) {
        collectDecodedPaths(child, `${prefix}.${k}`, out)
      }
    }
  }

  $: discoveredDecodedPaths = (() => {
    const out = new Set<string>()
    for (const pkt of $packets) {
      if (!pkt.decoded) continue
      for (const field of pkt.decoded.fields) {
        collectDecodedPaths(field.value, `decoded.${field.key}`, out)
      }
    }
    return [...out].sort()
  })()

  // ── Autocomplete suggestions ───────────────────────────────────────────────

  type SuggestionKind = 'history' | 'field' | 'operator' | 'combiner' | 'protocol'
  interface Suggestion { kind: SuggestionKind; label: string; insertText: string }

  const ALL_FIELDS  = [...KNOWN_FIELDS, 'decoded.'].sort()
  const PROTOCOLS   = ['arp', 'dhcp', 'dns', 'ftp', 'http', 'https', 'icmp', 'ssh', 'tcp', 'tls', 'udp']
  const OPERATORS   = ['==', '!=', 'contains']
  const COMBINERS   = ['&&', '||', 'and', 'or']

  function splitAtCurrentWord(input: string): { prefix: string; currentWord: string } {
    const m = input.match(/^([\s\S]*[\s()])(\S*)$/)
    return m ? { prefix: m[1], currentWord: m[2] } : { prefix: '', currentWord: input }
  }

  function getContext(prefix: string): 'start' | 'after-field' | 'after-op' | 'after-value' | 'after-not' {
    const trimmed = prefix.trimEnd()
    if (!trimmed) return 'start'
    try {
      const tokens = tokenize(trimmed)
      if (!tokens.length) return 'start'
      const last = tokens[tokens.length - 1]
      if (last.kind === 'and' || last.kind === 'or' || last.kind === 'lp') return 'start'
      if (last.kind === 'not')                                              return 'after-not'
      if (last.kind === 'eq' || last.kind === 'neq' || last.kind === 'contains') return 'after-op'
      if (last.kind === 'word') {
        return KNOWN_FIELDS.has(last.value.toLowerCase()) ? 'after-field' : 'after-value'
      }
      if (last.kind === 'rp') return 'after-value'
    } catch { /* incomplete token stream — fall through */ }
    return 'start'
  }

  function computeSuggestions(input: string, history: string[], decodedPaths: string[]): Suggestion[] {
    const { prefix, currentWord } = splitAtCurrentWord(input)
    const wordLower  = currentWord.toLowerCase()
    const inputLower = input.toLowerCase()
    const seen       = new Set<string>()
    const out: Suggestion[] = []

    for (const h of history) {
      if (h !== input && h.toLowerCase().startsWith(inputLower)) {
        out.push({ kind: 'history', label: h, insertText: h })
        seen.add(h)
      }
    }

    const ctx = getContext(prefix)
    if (ctx !== 'after-op') {
      let candidates: string[] = []
      if (ctx === 'start' || ctx === 'after-not') {
        const fieldCandidates = [...new Set([...ALL_FIELDS, ...decodedPaths])]
        candidates = [...fieldCandidates, ...PROTOCOLS, ...(ctx === 'start' ? ['not'] : [])]
      }
      else if (ctx === 'after-field') candidates = OPERATORS
      else if (ctx === 'after-value') candidates = COMBINERS

      for (const c of candidates) {
        if (!c.toLowerCase().startsWith(wordLower) || c.toLowerCase() === wordLower) continue
        const insertText = prefix + c
        if (seen.has(insertText)) continue
        seen.add(insertText)
        const kind: SuggestionKind =
          OPERATORS.includes(c) ? 'operator' :
          COMBINERS.includes(c) || c === 'not' ? 'combiner' :
          PROTOCOLS.includes(c) ? 'protocol' : 'field'
        out.push({ kind, label: c, insertText })
      }
    }

    return out
  }

  // ── Filter bar state ───────────────────────────────────────────────────────

  let filterInputEl: HTMLInputElement
  $: if ($filterFocusTick) { tick().then(() => { filterInputEl?.focus(); filterInputEl?.select() }) }

  let pendingFilter = $captureFilter
  let focused       = false
  let selectedIdx   = -1

  $: if (!focused) pendingFilter = $captureFilter
  $: filterResult      = parseFilter(pendingFilter)
  $: filterEmpty       = !pendingFilter.trim()
  $: filterBorderColor = filterEmpty
    ? 'var(--nc-border)'
    : filterResult.valid ? 'var(--nc-status-ok)' : 'var(--nc-status-err)'

  $: suggestions = computeSuggestions(pendingFilter, filterHistory, discoveredDecodedPaths)
  $: showSuggestions = focused && suggestions.length > 0
  $: if (selectedIdx >= suggestions.length) selectedIdx = -1

  const BADGE: Record<SuggestionKind, string> = {
    history:  'bg-[var(--nc-surface-2)]   text-[var(--nc-fg-3)]',
    field:    'bg-blue-900/40             text-blue-300',
    operator: 'bg-purple-900/40          text-purple-300',
    combiner: 'bg-orange-900/40          text-orange-300',
    protocol: 'bg-green-900/40           text-green-300',
  }

  function closeDropdowns(): void { showPresets = false; showSettings = false; showBpfPresets = false; exportOpen = false; importOpen = false; focused = false }

  function applyFilter(): void {
    if (!filterResult.valid) return
    captureFilter.set(pendingFilter)
    if (pendingFilter.trim()) pushHistory(pendingFilter.trim())
    focused = false
    showPresets = false
  }

  function selectPreset(filter: string): void {
    pendingFilter = filter
    showPresets   = false
  }

  function selectSuggestion(s: Suggestion): void {
    pendingFilter = s.insertText
    selectedIdx   = -1
    if (s.kind === 'history') focused = false
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (showSuggestions) {
      if (e.key === 'ArrowDown') { e.preventDefault(); selectedIdx = Math.min(selectedIdx + 1, suggestions.length - 1); return }
      if (e.key === 'ArrowUp')   { e.preventDefault(); selectedIdx = Math.max(selectedIdx - 1, -1); return }
      if (e.key === 'Tab')       { e.preventDefault(); selectedIdx = selectedIdx < suggestions.length - 1 ? selectedIdx + 1 : 0; return }
      if (e.key === 'Enter' && selectedIdx >= 0) { e.preventDefault(); selectSuggestion(suggestions[selectedIdx]); return }
      if (e.key === 'Escape') { focused = false; selectedIdx = -1; return }
    }
    if (e.key === 'Enter')  { applyFilter(); return }
    if (e.key === 'Escape') {
      if (showPresets) { showPresets = false; return }
      pendingFilter = $captureFilter
      ;(e.target as HTMLInputElement).blur()
    }
    selectedIdx = -1
  }

  // ── Column visibility list (typed so template needs no casts) ─────────────
  const CV_COLS: { key: keyof ColumnVisibility; label: string }[] = [
    { key: 'no',          label: 'No.'   },
    { key: 'time',        label: 'Time'  },
    { key: 'source',      label: 'Source'},
    { key: 'destination', label: 'Dest'  },
    { key: 'proto',       label: 'Proto' },
    { key: 'length',      label: 'Length'},
    { key: 'info',        label: 'Info'  },
  ]

  // ── Capture settings handlers ──────────────────────────────────────────────

  function handleMaxPacketsChange(e: Event): void {
    const v = Number((e.target as HTMLInputElement).value)
    if (v >= 100) maxPackets.set(v)
  }

  function handlePacketLimitChange(e: Event): void {
    capturePacketLimit.set(Math.max(0, Number((e.target as HTMLInputElement).value)))
  }

  function handleColVisChange(key: string, e: Event): void {
    columnVisibility.update(v => ({ ...v, [key]: (e.target as HTMLInputElement).checked }))
  }
</script>

<svelte:window on:click={closeDropdowns} />

<!-- Hidden file inputs -->
<input bind:this={captureFileInput}  type="file" accept=".json" class="hidden" on:change={handleCaptureImport} />
<input bind:this={addrBookFileInput} type="file" accept=".json" class="hidden" on:change={handleAddrBookImport} />
<input bind:this={presetFileInput}   type="file" accept=".json" class="hidden" on:change={handlePresetImport} />
<input bind:this={pcapFileInput}     type="file" accept=".pcap,.pcapng" class="hidden" on:change={handlePcapImport} />
<input bind:this={csvFileInput}      type="file" accept=".csv"           class="hidden" on:change={handleCsvImport} />

<div class="flex flex-col bg-[var(--nc-surface-1)] border-b border-[var(--nc-border)] select-none shrink-0">

  <!-- ── Row 1: brand, controls ──────────────────────────────────────────── -->
  <div class="flex items-center gap-2 px-4 py-2">

    <div class="flex items-center gap-2 mr-1">
      <div class="w-2.5 h-2.5 rounded-full {statusPulse ? 'animate-pulse' : ''}"
        style={statusDotStyle}></div>
      <span class="text-[var(--nc-fg)] font-bold text-base tracking-tight">NetCapture</span>
    </div>

    <select
      value={selectionKey}
      on:change={handleSelectionChange}
      disabled={$isCapturing}
      class="bg-[var(--nc-surface)] text-[var(--nc-fg-1)] border border-[var(--nc-border)] rounded px-2 py-1 text-xs
             w-72 focus:outline-none focus:border-blue-500 disabled:opacity-40 cursor-pointer"
    >
      <optgroup label="Interfaces">
        {#each $interfaces as iface}
          <option value="iface:{iface.name}">{iface.description ?? iface.name}</option>
        {/each}
      </optgroup>
      {#if $profiles.length}
        <optgroup label="Capture Profiles">
          {#each $profiles as prof}
            <option value="profile:{prof.id}" title={prof.description}>{prof.name}</option>
          {/each}
        </optgroup>
      {/if}
    </select>

    {#if $npcapAvailable}
      <div class="relative flex items-center">
        <input
          bind:value={$bpfFilter}
          disabled={$isCapturing}
          placeholder="BPF filter (e.g. tcp port 443)"
          title="Kernel-level BPF capture filter. Filters packets before they reach the app."
          class="bg-[var(--nc-surface)] text-[var(--nc-fg-1)] border border-[var(--nc-border)] rounded-l px-2 py-1 text-xs
                 w-64 focus:outline-none focus:border-blue-500 disabled:opacity-40 font-mono"
        />
        <!-- BPF presets button -->
        <button
          on:click|stopPropagation={() => { showBpfPresets = !showBpfPresets }}
          disabled={$isCapturing}
          title="BPF filter presets"
          class="flex items-center px-1.5 py-1 border border-l-0 border-[var(--nc-border)] rounded-r
                 bg-[var(--nc-surface)] hover:bg-[var(--nc-surface-2)] text-[var(--nc-fg-3)]
                 hover:text-[var(--nc-fg-1)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
          <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd"/>
          </svg>
        </button>
        {#if showBpfPresets}
          <div class="absolute top-full left-0 mt-1 z-50 min-w-[200px]
                      bg-[var(--nc-surface-1)] border border-[var(--nc-border)] rounded shadow-lg py-1"
               on:click|stopPropagation on:keydown|stopPropagation role="none">
            {#each BPF_PRESETS as preset}
              <button
                on:click={() => { bpfFilter.set(preset.value); showBpfPresets = false }}
                class="w-full text-left px-3 py-1.5 text-xs flex items-center justify-between gap-4
                       text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
                <span>{preset.label}</span>
                <span class="font-mono text-[var(--nc-fg-4)] text-[10px]">{preset.value}</span>
              </button>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    {#if !$isCapturing}
      <button on:click={() => dispatch('start')}
        class="flex items-center gap-1.5 bg-green-700 hover:bg-green-600 text-white px-3 py-1 rounded text-xs font-semibold transition-colors">
        <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
          <path d="M6.3 2.841A1.5 1.5 0 004 4.11V15.89a1.5 1.5 0 002.3 1.269l9.344-5.89a1.5 1.5 0 000-2.538L6.3 2.84z"/>
        </svg>
        Start
      </button>
    {:else}
      <button on:click={() => dispatch('stop')}
        class="flex items-center gap-1.5 bg-red-700 hover:bg-red-600 text-white px-3 py-1 rounded text-xs font-semibold transition-colors">
        <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M2 10a8 8 0 1116 0 8 8 0 01-16 0zm5-2.25A.75.75 0 017.75 7h4.5a.75.75 0 01.75.75v4.5a.75.75 0 01-.75.75h-4.5a.75.75 0 01-.75-.75v-4.5z" clip-rule="evenodd"/>
        </svg>
        Stop
      </button>
    {/if}

    <button on:click={() => dispatch('clear')} disabled={$isCapturing}
      class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
             px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40">
      <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 006 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 10.23 1.482l.149-.022.841 10.518A2.75 2.75 0 007.596 19h4.807a2.75 2.75 0 002.742-2.53l.841-10.52.149.023a.75.75 0 00.23-1.482A41.03 41.03 0 0014 4.193V3.75A2.75 2.75 0 0011.25 1h-2.5zM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4zM8.58 7.72a.75.75 0 00-1.5.06l.3 7.5a.75.75 0 101.5-.06l-.3-7.5zm4.34.06a.75.75 0 10-1.5-.06l-.3 7.5a.75.75 0 101.5.06l.3-7.5z" clip-rule="evenodd"/>
      </svg>
      Clear
    </button>

    {#if modeLabel}
      <span class="px-2 py-0.5 rounded border text-[10px] font-semibold tracking-wide" style={modeStyle}>
        {modeLabel}
      </span>
    {/if}

    <!-- ── Settings dropdown ─────────────────────────────────────────────── -->
    <div class="relative ml-auto" role="none" on:click|stopPropagation on:keydown|stopPropagation>
      <button
        on:click|stopPropagation={() => { showSettings = !showSettings; showPresets = false }}
        class="flex items-center px-1 py-1 rounded border transition-colors
               {showSettings
                 ? 'bg-[var(--nc-surface-2)] border-[var(--nc-border)] text-[var(--nc-fg)]'
                 : 'bg-[var(--nc-surface)] border-[var(--nc-border)] text-[var(--nc-fg-3)] hover:text-[var(--nc-fg)] hover:bg-[var(--nc-surface-2)]'}"
        title="Settings"
      >
        <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M7.84 1.804A1 1 0 018.82 1h2.36a1 1 0 01.98.804l.331 1.652a6.993 6.993 0 011.929 1.115l1.598-.54a1 1 0 011.186.447l1.18 2.044a1 1 0 01-.205 1.251l-1.267 1.113a7.047 7.047 0 010 2.228l1.267 1.113a1 1 0 01.205 1.251l-1.18 2.044a1 1 0 01-1.186.447l-1.598-.54a6.993 6.993 0 01-1.929 1.115l-.33 1.652a1 1 0 01-.98.804H8.82a1 1 0 01-.98-.804l-.331-1.652a6.993 6.993 0 01-1.929-1.115l-1.598.54a1 1 0 01-1.186-.447l-1.18-2.044a1 1 0 01.205-1.251l1.267-1.113a7.048 7.048 0 010-2.228L1.821 7.773a1 1 0 01-.206-1.25l1.18-2.045a1 1 0 011.187-.447l1.598.54A6.992 6.992 0 017.51 3.456l.33-1.652zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
        </svg>
      </button>

      {#if showSettings}
        <div
          class="absolute right-0 top-full mt-1 z-50 w-64 max-h-[80vh] overflow-y-auto
                 bg-[var(--nc-surface-1)] border border-[var(--nc-border)] rounded shadow-xl"
          role="none"
          on:click|stopPropagation
          on:keydown|stopPropagation
        >

          <!-- ── Recording ──────────────────────────────────────────────── -->
          <div class="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider
                      text-[var(--nc-fg-4)] border-b border-[var(--nc-border-1)]">
            Recording
          </div>
          <!-- Export group -->
          <button on:click={openExportMenu}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)]
                   {exportOpen ? 'bg-[var(--nc-surface-2)] text-[var(--nc-fg)]' : ''}">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 2.75a.75.75 0 00-1.5 0v8.614L6.295 8.235a.75.75 0 10-1.09 1.03l4.25 4.5a.75.75 0 001.09 0l4.25-4.5a.75.75 0 00-1.09-1.03l-2.955 3.129V2.75z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Export
            <svg class="w-3 h-3 ml-auto" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd"/>
            </svg>
          </button>

          <!-- Import group -->
          <button on:click={openImportMenu} disabled={$isCapturing}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs transition-colors
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)]
                   disabled:opacity-40 disabled:cursor-not-allowed
                   {importOpen ? 'bg-[var(--nc-surface-2)] text-[var(--nc-fg)]' : ''}">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.25 13.25a.75.75 0 001.5 0V4.636l2.955 3.129a.75.75 0 001.09-1.03l-4.25-4.5a.75.75 0 00-1.09 0l-4.25 4.5a.75.75 0 101.09 1.03L9.25 4.636v8.614z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Import
            <svg class="w-3 h-3 ml-auto" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd"/>
            </svg>
          </button>

          <!-- ── Addresses ──────────────────────────────────────────────── -->
          <div class="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider
                      text-[var(--nc-fg-4)] border-t border-b border-[var(--nc-border-1)] mt-1">
            Addresses
          </div>
          <button on:click={() => { showAddressBook = true; showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 2a.75.75 0 01.75.75v.258a33.186 33.186 0 016.668.83.75.75 0 01-.336 1.461 31.28 31.28 0 00-1.103-.232l1.702 7.545a.75.75 0 01-.387.832A4.981 4.981 0 0115 14c-.825 0-1.606-.2-2.294-.556a.75.75 0 01-.387-.832l1.77-7.849a31.743 31.743 0 00-3.339-.254v11.505a20.415 20.415 0 013.78.501.75.75 0 11-.339 1.46 18.927 18.927 0 00-3.441-.456V17.5a.75.75 0 01-1.5 0v-.921a18.927 18.927 0 00-3.441.456.75.75 0 11-.339-1.46 20.415 20.415 0 013.78-.501V4.509a31.743 31.743 0 00-3.339.254l1.77 7.849a.75.75 0 01-.387.832A4.979 4.979 0 015 14a4.981 4.981 0 01-2.294-.556.75.75 0 01-.387-.832l1.702-7.545c-.37.07-.738.146-1.103.232a.75.75 0 01-.336-1.46 33.186 33.186 0 016.668-.83V2.75A.75.75 0 0110 2z"/>
            </svg>
            Manage Addresses
            {#if $addressBook.length}
              <span class="ml-auto text-[10px] text-[var(--nc-fg-4)]">{$addressBook.length}</span>
            {/if}
          </button>
          <button on:click={() => { exportAddrBook(); showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors
                   disabled:opacity-40" disabled={!$addressBook.length}>
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 2.75a.75.75 0 00-1.5 0v8.614L6.295 8.235a.75.75 0 10-1.09 1.03l4.25 4.5a.75.75 0 001.09 0l4.25-4.5a.75.75 0 00-1.09-1.03l-2.955 3.129V2.75z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Export Address Book
          </button>
          <button on:click={() => { addrBookFileInput.click(); showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.25 13.25a.75.75 0 001.5 0V4.636l2.955 3.129a.75.75 0 001.09-1.03l-4.25-4.5a.75.75 0 00-1.09 0l-4.25 4.5a.75.75 0 101.09 1.03L9.25 4.636v8.614z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Import Address Book
          </button>

          <!-- ── Filter Presets ──────────────────────────────────────────── -->
          <div class="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider
                      text-[var(--nc-fg-4)] border-t border-b border-[var(--nc-border-1)] mt-1">
            Filter Presets
          </div>
          <button on:click={() => { showPresetEditor = true; showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M2 4.75A.75.75 0 012.75 4h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 4.75zm0 10.5a.75.75 0 01.75-.75h7.5a.75.75 0 010 1.5h-7.5a.75.75 0 01-.75-.75zM2 10a.75.75 0 01.75-.75h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 10z" clip-rule="evenodd"/>
            </svg>
            Manage Presets
            {#if userPresets.length}
              <span class="ml-auto text-[10px] text-[var(--nc-fg-4)]">{userPresets.length}</span>
            {/if}
          </button>
          <button on:click={() => { exportPresets(); showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors
                   disabled:opacity-40" disabled={!userPresets.length}>
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 2.75a.75.75 0 00-1.5 0v8.614L6.295 8.235a.75.75 0 10-1.09 1.03l4.25 4.5a.75.75 0 001.09 0l4.25-4.5a.75.75 0 00-1.09-1.03l-2.955 3.129V2.75z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Export Presets
          </button>
          <button on:click={() => { presetFileInput.click(); showSettings = false }}
            class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
                   text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
            <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path d="M9.25 13.25a.75.75 0 001.5 0V4.636l2.955 3.129a.75.75 0 001.09-1.03l-4.25-4.5a.75.75 0 00-1.09 0l-4.25 4.5a.75.75 0 101.09 1.03L9.25 4.636v8.614z"/>
              <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
            </svg>
            Import Presets
          </button>

          <!-- ── Capture ────────────────────────────────────────────────── -->
          <div class="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider
                      text-[var(--nc-fg-4)] border-t border-b border-[var(--nc-border-1)] mt-1">
            Capture
          </div>
          <!-- Buffer size -->
          <div class="flex items-center justify-between px-3 py-2 text-xs text-[var(--nc-fg-2)]">
            <span title="Max packets kept in the rolling buffer">Buffer size</span>
            <div class="flex items-center gap-1">
              <input type="number" min="100" max="1000000" step="1000"
                value={$maxPackets}
                on:change={handleMaxPacketsChange}
                class="w-20 bg-[var(--nc-surface)] text-[var(--nc-fg)] border border-[var(--nc-border)]
                       rounded px-1.5 py-0.5 text-xs text-right focus:outline-none focus:border-blue-500" />
              <span class="text-[var(--nc-fg-4)]">pkts</span>
            </div>
          </div>
          <!-- Ring buffer toggle -->
          <div class="flex items-center justify-between px-3 py-2 text-xs text-[var(--nc-fg-2)]">
            <span title="Keep newest N packets (On) or keep all (Off)">Ring buffer</span>
            <div class="flex rounded border border-[var(--nc-border)] overflow-hidden text-[10px]">
              <button on:click={() => ringBuffer.set(true)}
                class="px-2 py-0.5 transition-colors
                       {$ringBuffer ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                On
              </button>
              <button on:click={() => ringBuffer.set(false)}
                class="px-2 py-0.5 transition-colors border-l border-[var(--nc-border)]
                       {!$ringBuffer ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                Off
              </button>
            </div>
          </div>
          <!-- Auto-stop after N packets -->
          <div class="flex items-center justify-between px-3 py-2 text-xs text-[var(--nc-fg-2)]">
            <span title="Automatically stop capture after N packets (0 = unlimited)">Auto-stop after</span>
            <div class="flex items-center gap-1">
              <input type="number" min="0" max="10000000" step="1000"
                value={$capturePacketLimit}
                on:change={handlePacketLimitChange}
                class="w-20 bg-[var(--nc-surface)] text-[var(--nc-fg)] border border-[var(--nc-border)]
                       rounded px-1.5 py-0.5 text-xs text-right focus:outline-none focus:border-blue-500" />
              <span class="text-[var(--nc-fg-4)]">pkts</span>
            </div>
          </div>

          <!-- ── Display ──────────────────────────────────────────────────── -->
          <div class="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider
                      text-[var(--nc-fg-4)] border-t border-b border-[var(--nc-border-1)] mt-1">
            Display
          </div>
          <!-- Timestamp format toggle -->
          <div class="flex items-center justify-between px-3 py-2 text-xs text-[var(--nc-fg-2)]">
            <div class="flex items-center gap-2">
              <svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-13a.75.75 0 00-1.5 0v5c0 .414.336.75.75.75h4a.75.75 0 000-1.5h-3.25V5z" clip-rule="evenodd"/>
              </svg>
              Timestamp
            </div>
            <div class="flex rounded border border-[var(--nc-border)] overflow-hidden text-[10px]">
              <button
                on:click={() => timestampMode.set('relative')}
                class="px-2 py-0.5 transition-colors
                       {$timestampMode === 'relative'
                         ? 'bg-blue-700 text-white'
                         : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                Relative
              </button>
              <button
                on:click={() => timestampMode.set('absolute')}
                class="px-2 py-0.5 transition-colors border-l border-[var(--nc-border)]
                       {$timestampMode === 'absolute'
                         ? 'bg-blue-700 text-white'
                         : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                Absolute
              </button>
            </div>
          </div>
          <!-- Auto-scroll toggle -->
          <div class="flex items-center justify-between px-3 py-2 text-xs text-[var(--nc-fg-2)]">
            <span title="Follow newest packets during live capture">Auto-scroll</span>
            <div class="flex rounded border border-[var(--nc-border)] overflow-hidden text-[10px]">
              <button on:click={() => autoScrollEnabled.set(true)}
                class="px-2 py-0.5 transition-colors
                       {$autoScrollEnabled ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                On
              </button>
              <button on:click={() => autoScrollEnabled.set(false)}
                class="px-2 py-0.5 transition-colors border-l border-[var(--nc-border)]
                       {!$autoScrollEnabled ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
                Off
              </button>
            </div>
          </div>
          <!-- Column visibility -->
          <div class="px-3 py-2 text-xs">
            <div class="text-[10px] text-[var(--nc-fg-4)] mb-1.5 uppercase tracking-wide">Columns</div>
            <div class="grid grid-cols-2 gap-x-4 gap-y-1.5">
              {#each CV_COLS as col}
                <label class="flex items-center gap-1.5 cursor-pointer text-[var(--nc-fg-2)]">
                  <input type="checkbox"
                    checked={$columnVisibility[col.key]}
                    on:change={(e) => handleColVisChange(col.key, e)}
                    class="w-3 h-3 accent-blue-500 cursor-pointer" />
                  {col.label}
                </label>
              {/each}
            </div>
          </div>

          <div class="pb-1"></div>
        </div>
      {/if}
    </div>

  </div>

  <!-- ── Row 2: filter bar ────────────────────────────────────────────────── -->
  <div role="none"
    class="flex items-center gap-2 px-3 py-1.5 border-t border-[var(--nc-border-1)]"
    on:click|stopPropagation on:keydown|stopPropagation>

    <!-- Presets button -->
    <div class="relative shrink-0">
      <button
        on:click|stopPropagation={() => { showPresets = !showPresets; showSettings = false; focused = false }}
        title="Preset filters"
        class="flex items-center gap-1 px-2 py-1 rounded text-xs border transition-colors
               {showPresets
                 ? 'bg-[var(--nc-surface-2)] border-[var(--nc-border)] text-[var(--nc-fg)]'
                 : 'bg-[var(--nc-surface)] border-[var(--nc-border)] text-[var(--nc-fg-3)] hover:text-[var(--nc-fg)] hover:bg-[var(--nc-surface-2)]'}"
      >
        <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
          <path d="M10.75 16.82A7.462 7.462 0 0115 15.5c.71 0 1.396.098 2.046.282A.75.75 0 0018 15.06v-11a.75.75 0 00-.546-.721A9.006 9.006 0 0015 3a8.963 8.963 0 00-4.25 1.065V16.82zM9.25 4.065A8.963 8.963 0 005 3c-.85 0-1.673.118-2.454.339A.75.75 0 002 4.06v11a.75.75 0 00.954.721A7.506 7.506 0 015 15.5c1.579 0 3.042.487 4.25 1.32V4.065z"/>
        </svg>
        Presets
      </button>

      {#if showPresets}
        <div role="none"
          on:click|stopPropagation on:keydown|stopPropagation
          class="absolute left-0 top-full mt-1 z-50 min-w-[380px] max-h-96 overflow-y-auto
                 bg-[var(--nc-surface-1)] border border-[var(--nc-border)] rounded shadow-xl"
        >
          {#if userPresets.length}
            {#each userPresets as preset}
              <button on:click={() => selectPreset(preset.filter)}
                class="w-full text-left px-3 py-2 hover:bg-[var(--nc-surface-2)] transition-colors
                       border-b border-[var(--nc-border-1)] last:border-b-0">
                <div class="flex items-baseline justify-between gap-3">
                  <span class="text-xs font-medium text-[var(--nc-fg)] shrink-0">{preset.title}</span>
                  <span class="text-[10px] font-mono text-[var(--nc-fg-3)] truncate">{preset.filter}</span>
                </div>
              </button>
            {/each}
          {:else}
            <div class="px-4 py-6 text-center text-[var(--nc-fg-5)] text-xs">
              No presets — manage them in Settings.
            </div>
          {/if}
        </div>
      {/if}
    </div>

    <!-- Filter input with autocomplete -->
    <div class="relative flex-1">
      <input
        type="text"
        bind:this={filterInputEl}
        bind:value={pendingFilter}
        on:keydown={handleKeydown}
        on:focus={() => { focused = true; selectedIdx = -1 }}
        on:blur={() => focused = false}
        on:click|stopPropagation
        spellcheck="false"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        data-filter-input="true"
        placeholder="Apply display filter  —  ip.src == 1.2.3.4  ||  port == 9001  &&  not arp"
        class="w-full bg-[var(--nc-surface)] text-[var(--nc-fg)] rounded px-3 py-1 text-xs
               border focus:outline-none placeholder-[var(--nc-fg-4)] transition-colors font-mono"
        style="border-color: {filterBorderColor}"
      />

      {#if showSuggestions}
        <div role="none"
          on:mousedown|preventDefault
          on:click|stopPropagation on:keydown|stopPropagation
          class="absolute left-0 top-full mt-1 z-50 w-full max-h-60 overflow-y-auto
                 bg-[var(--nc-surface-1)] border border-[var(--nc-border)] rounded shadow-xl"
        >
          {#each suggestions as s, i}
            <button
              on:click={() => selectSuggestion(s)}
              class="w-full text-left px-3 py-2 flex items-center gap-2 text-xs transition-colors
                     border-b border-[var(--nc-border-1)] last:border-b-0
                     {i === selectedIdx ? 'bg-[var(--nc-surface-2)]' : 'hover:bg-[var(--nc-surface-2)]'}"
            >
              {#if s.kind === 'history'}
                <svg class="w-3 h-3 shrink-0 text-[var(--nc-fg-4)]" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-13a.75.75 0 00-1.5 0v5c0 .414.336.75.75.75h4a.75.75 0 000-1.5h-3.25V5z" clip-rule="evenodd"/>
                </svg>
                <span class="font-mono text-[var(--nc-fg-1)] truncate">{s.label}</span>
              {:else}
                <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0 {BADGE[s.kind]}">{s.kind}</span>
                <span class="font-mono text-[var(--nc-fg)] font-medium">{s.label}</span>
                {#if s.insertText !== s.label}
                  <span class="font-mono text-[var(--nc-fg-3)] text-[10px] truncate ml-auto">{s.insertText}</span>
                {/if}
              {/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Validation status -->
    <span class="text-[11px] shrink-0 w-36 truncate transition-colors" style="color: {filterBorderColor}">
      {#if !filterEmpty}
        {filterResult.valid ? '✓  Valid expression' : '✗  ' + (filterResult.error ?? 'Invalid')}
      {/if}
    </span>

    <!-- Apply -->
    <button
      on:click={applyFilter}
      disabled={!filterEmpty && !filterResult.valid}
      class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
             px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors shrink-0
             disabled:opacity-40 disabled:cursor-not-allowed"
    >
      Apply
    </button>
  </div>

</div>

<!-- Modals -->
{#if showAddressBook}
  <AddressBookEditor
    prefill={addressPrefill}
    on:close={() => { showAddressBook = false; addressPrefill = '' }}
  />
{/if}

{#if showPresetEditor}
  <PresetEditor
    userPresets={userPresets}
    defaultPresets={BUILTIN_PRESETS}
    on:save={(e) => { saveUserPresets(e.detail); showPresetEditor = false }}
    on:close={() => showPresetEditor = false}
  />
{/if}

<!-- ── Export flyout submenu (fixed, escapes overflow-y-auto of settings panel) -->
{#if exportOpen}
  <div
    class="fixed z-[200] min-w-[9rem] bg-[var(--nc-surface-1)] border border-[var(--nc-border)]
           rounded shadow-xl overflow-hidden"
    style="right:{window.innerWidth - exportMenuPos.x}px; top:{exportMenuPos.y}px"
    role="menu"
    on:click|stopPropagation
    on:keydown|stopPropagation
  >
    <button on:click={() => { exportPcap(); exportOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      PCAP
    </button>
    <button on:click={() => { handleCsvExport(); exportOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      CSV
    </button>
    <button on:click={() => { exportCapture(); exportOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      Capture (JSON)
    </button>
  </div>
{/if}

<!-- ── Import flyout submenu -->
{#if importOpen}
  <div
    class="fixed z-[200] min-w-[9rem] bg-[var(--nc-surface-1)] border border-[var(--nc-border)]
           rounded shadow-xl overflow-hidden"
    style="right:{window.innerWidth - importMenuPos.x}px; top:{importMenuPos.y}px"
    role="menu"
    on:click|stopPropagation
    on:keydown|stopPropagation
  >
    <button on:click={() => { pcapFileInput.click(); importOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      PCAP
    </button>
    <button on:click={() => { csvFileInput.click(); importOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      CSV
    </button>
    <button on:click={() => { captureFileInput.click(); importOpen = false; showSettings = false }}
      class="w-full text-left flex items-center gap-2 px-3 py-2 text-xs
             text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] hover:text-[var(--nc-fg)] transition-colors">
      Capture (JSON)
    </button>
  </div>
{/if}
