<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import {
    isCapturing, connectionStatus, selectedInterface,
    interfaces, captureFilter, captureMode, profiles, activeProfile, packets,
  } from './stores'
  import type { CaptureProfile, DecodedValue } from './types'
  import { exportCapture, importCapture } from './captureService'
  import { parseFilter, tokenize, KNOWN_FIELDS } from './filter'

  let fileInput: HTMLInputElement

  async function handleImport(e: Event): Promise<void> {
    const file = (e.target as HTMLInputElement).files?.[0]
    if (!file) return
    try { await importCapture(file) } catch (err) { console.error('[import]', err) }
    finally { fileInput.value = '' }
  }

  const dispatch = createEventDispatcher()

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
      if (prof) selectedInterface.set(prof.interface)
    } else {
      activeProfile.set(null)
      selectedInterface.set(val.slice('iface:'.length))
    }
  }

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

  // ── Filter presets ─────────────────────────────────────────────────────────

  const PRESETS: { title: string; filter: string }[] = [
    // ── Protocol basics ──────────────────────────────────────────────────────
    { title: 'TCP only',                    filter: 'tcp' },
    { title: 'UDP only',                    filter: 'udp' },
    { title: 'ICMP only',                   filter: 'icmp' },
    { title: 'ARP only',                    filter: 'arp' },
    { title: 'Exclude ARP',                 filter: 'not arp' },
    { title: 'Exclude TCP and UDP',         filter: 'not tcp && not udp' },
    // ── Common application ports ─────────────────────────────────────────────
    { title: 'HTTP (port 80)',              filter: 'proto == HTTP || port == 80' },
    { title: 'HTTPS / TLS (port 443)',      filter: 'proto == TLS || port == 443' },
    { title: 'DNS (port 53)',               filter: 'proto == DNS || port == 53' },
    { title: 'SSH (port 22)',               filter: 'port == 22' },
    { title: 'Web traffic (80 or 443)',     filter: 'port == 80 || port == 443' },
    { title: 'UDP Device feed (port 9001)', filter: 'port == 9001' },
    // ── Port direction ───────────────────────────────────────────────────────
    { title: 'Inbound to port 80',          filter: 'dst.port == 80' },
    { title: 'Outbound from port 80',       filter: 'src.port == 80' },
    { title: 'High ports (> visible via !=)', filter: 'dst.port != 80 && dst.port != 443 && dst.port != 53' },
    // ── IP address filters ───────────────────────────────────────────────────
    { title: 'Specific host (either dir)',  filter: 'ip.addr == 192.168.1.1' },
    { title: 'From specific host',          filter: 'ip.src == 192.168.1.1' },
    { title: 'To specific host',            filter: 'ip.dst == 192.168.1.1' },
    { title: 'Subnet match (contains)',     filter: 'ip.addr contains 192.168' },
    { title: 'Exclude host',               filter: 'ip.addr != 192.168.1.1' },
    { title: 'Between two hosts',           filter: 'ip.src == 192.168.1.1 || ip.src == 10.0.0.1' },
    // ── Combined conditions ──────────────────────────────────────────────────
    { title: 'TCP from specific host',      filter: 'ip.src == 192.168.1.1 && proto == TCP' },
    { title: 'TCP to web ports',            filter: 'tcp && (port == 80 || port == 443)' },
    { title: 'Not local, not ARP',          filter: 'not arp && ip.src != 192.168.1.1' },
    // ── Info / content filters ───────────────────────────────────────────────
    { title: 'TCP SYN packets',             filter: 'tcp && info contains "SYN"' },
    { title: 'TLS handshake',               filter: 'info contains "handshake"' },
    { title: 'ICMP echo (ping)',            filter: 'icmp && (info contains "request" || info contains "reply")' },
    // ── Interpreter / decoded field filters ──────────────────────────────────
    { title: 'NC-Frame packets only',       filter: 'interpreter == NC-Frame' },
    { title: 'Decoded field equals value',  filter: 'decoded.temperature == 25.0' },
    { title: 'Decoded field contains text', filter: 'decoded.status contains "ok"' },
    { title: 'NC-Frame on UDP port 9001',   filter: 'interpreter == NC-Frame && port == 9001' },
  ]

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

  /** Collect every accessible dot-path from a decoded value, including intermediate nodes. */
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

  /** Split input at the start of the last partial token being typed. */
  function splitAtCurrentWord(input: string): { prefix: string; currentWord: string } {
    const m = input.match(/^([\s\S]*[\s()])(\S*)$/)
    return m ? { prefix: m[1], currentWord: m[2] } : { prefix: '', currentWord: input }
  }

  /** Infer what kind of token is expected next, based on the tokens before the cursor. */
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

    // History: entries whose full text starts with the current input
    for (const h of history) {
      if (h !== input && h.toLowerCase().startsWith(inputLower)) {
        out.push({ kind: 'history', label: h, insertText: h })
        seen.add(h)
      }
    }

    // Keyword/field completions based on grammatical context
    const ctx = getContext(prefix)
    if (ctx !== 'after-op') {
      let candidates: string[] = []
      if (ctx === 'start' || ctx === 'after-not') {
        // Merge static fields with live-discovered decoded paths; deduplicate
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

  let pendingFilter = $captureFilter
  let showPresets   = false
  let focused       = false
  let selectedIdx   = -1

  $: if ($captureFilter === '') pendingFilter = ''
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

  function closeDropdowns(): void { showPresets = false; focused = false }

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
    if (s.kind === 'history') focused = false  // close after history pick; stay open for completions
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (showSuggestions) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        selectedIdx = Math.min(selectedIdx + 1, suggestions.length - 1)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        selectedIdx = Math.max(selectedIdx - 1, -1)
        return
      }
      if (e.key === 'Tab') {
        e.preventDefault()
        selectedIdx = selectedIdx < suggestions.length - 1 ? selectedIdx + 1 : 0
        return
      }
      if (e.key === 'Enter' && selectedIdx >= 0) {
        e.preventDefault()
        selectSuggestion(suggestions[selectedIdx])
        return
      }
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
</script>

<svelte:window on:click={closeDropdowns} />

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

    <button on:click={exportCapture} disabled={$isCapturing}
      class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
             px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40">
      <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
        <path d="M10.75 2.75a.75.75 0 00-1.5 0v8.614L6.295 8.235a.75.75 0 10-1.09 1.03l4.25 4.5a.75.75 0 001.09 0l4.25-4.5a.75.75 0 00-1.09-1.03l-2.955 3.129V2.75z"/>
        <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
      </svg>
      Export
    </button>

    <input bind:this={fileInput} type="file" accept=".json" class="hidden" on:change={handleImport} />
    <button on:click={() => fileInput.click()} disabled={$isCapturing}
      class="flex items-center gap-1.5 bg-[var(--nc-surface-2)] hover:bg-[var(--nc-border)] text-[var(--nc-fg-1)]
             px-3 py-1 rounded text-xs border border-[var(--nc-border)] transition-colors disabled:opacity-40">
      <svg class="w-3 h-3" viewBox="0 0 20 20" fill="currentColor">
        <path d="M9.25 13.25a.75.75 0 001.5 0V4.636l2.955 3.129a.75.75 0 001.09-1.03l-4.25-4.5a.75.75 0 00-1.09 0l-4.25 4.5a.75.75 0 101.09 1.03L9.25 4.636v8.614z"/>
        <path d="M3.5 12.75a.75.75 0 00-1.5 0v2.5A2.75 2.75 0 004.75 18h10.5A2.75 2.75 0 0018 15.25v-2.5a.75.75 0 00-1.5 0v2.5c0 .69-.56 1.25-1.25 1.25H4.75c-.69 0-1.25-.56-1.25-1.25v-2.5z"/>
      </svg>
      Import
    </button>

    {#if modeLabel}
      <span class="px-2 py-0.5 rounded border text-[10px] font-semibold tracking-wide" style={modeStyle}>
        {modeLabel}
      </span>
    {/if}
  </div>

  <!-- ── Row 2: filter bar ────────────────────────────────────────────────── -->
  <div role="none"
    class="flex items-center gap-2 px-3 py-1.5 border-t border-[var(--nc-border-1)]"
    on:click|stopPropagation on:keydown|stopPropagation>

    <!-- Presets button -->
    <div class="relative shrink-0">
      <button
        on:click|stopPropagation={() => { showPresets = !showPresets; focused = false }}
        title="Preset filters"
        class="flex items-center gap-1 px-2 py-1 rounded text-xs border transition-colors
               {showPresets
                 ? 'bg-[var(--nc-surface-2)] border-[var(--nc-border)] text-[var(--nc-fg)]'
                 : 'bg-[var(--nc-surface)] border-[var(--nc-border)] text-[var(--nc-fg-3)] hover:text-[var(--nc-fg)] hover:bg-[var(--nc-surface-2)]'}"
      >
        <!-- bookmark icon -->
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
          <div class="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--nc-fg-4)]
                      border-b border-[var(--nc-border)] sticky top-0 bg-[var(--nc-surface-1)]">
            Filter presets — click to load into bar
          </div>

          <!-- Group by category using the comment structure -->
          {#each PRESETS as preset}
            <button
              on:click={() => selectPreset(preset.filter)}
              class="w-full text-left px-3 py-2 hover:bg-[var(--nc-surface-2)] transition-colors
                     border-b border-[var(--nc-border-1)] last:border-b-0"
            >
              <div class="flex items-baseline justify-between gap-3">
                <span class="text-xs font-medium text-[var(--nc-fg)] shrink-0">{preset.title}</span>
                <span class="text-[10px] font-mono text-[var(--nc-fg-3)] truncate">{preset.filter}</span>
              </div>
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <!-- Filter input with history dropdown -->
    <div class="relative flex-1">
      <input
        type="text"
        bind:value={pendingFilter}
        on:keydown={handleKeydown}
        on:focus={() => { focused = true; selectedIdx = -1 }}
        on:blur={() => focused = false}
        on:click|stopPropagation
        spellcheck="false"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
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
                <!-- clock icon -->
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
