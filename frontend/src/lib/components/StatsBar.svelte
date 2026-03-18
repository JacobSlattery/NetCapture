<script lang="ts">
  import { stats, connectionStatus, filteredPackets, captureFilter } from '../stores'

  function fmtBytes(b: number): string {
    if (b < 1024) return `${b} B`
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1073741824) return `${(b / 1048576).toFixed(2)} MB`
    return `${(b / 1073741824).toFixed(2)} GB`
  }

  function fmtNum(n: number): string {
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
    return String(n)
  }

  const PROTO_VAR: Record<string, string> = {
    TCP: '--nc-p-tcp', UDP: '--nc-p-udp', DNS: '--nc-p-dns',
    ICMP: '--nc-p-icmp', HTTP: '--nc-p-http', HTTPS: '--nc-p-https',
    TLS: '--nc-p-https', ARP: '--nc-p-arp',
  }

  function protoStyle(name: string): string {
    return `background-color: var(${PROTO_VAR[name] ?? '--nc-p-default'})`
  }

  $: topProtos = Object.entries($stats.protocol_counts ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)

  $: protoTotal = topProtos.reduce((s, [, v]) => s + v, 0) || 1

  $: statusTextStyle = ({
    connected:    'color: var(--nc-status-ok)',
    connecting:   'color: var(--nc-status-warn)',
    error:        'color: var(--nc-status-err)',
    disconnected: 'color: var(--nc-status-off)',
  } as Record<string, string>)[$connectionStatus] ?? 'color: var(--nc-status-off)'

  $: statusDotStyle = ({
    connected:    'background-color: var(--nc-status-ok)',
    connecting:   'background-color: var(--nc-status-warn)',
    error:        'background-color: var(--nc-status-err)',
    disconnected: 'background-color: var(--nc-status-off)',
  } as Record<string, string>)[$connectionStatus] ?? 'background-color: var(--nc-status-off)'

  $: statusPulse = $connectionStatus === 'connected' || $connectionStatus === 'connecting'
</script>

<div class="flex items-center gap-4 px-4 py-1.5 bg-[var(--nc-surface)] border-b border-[var(--nc-border)] text-xs overflow-x-auto shrink-0 font-mono">
  <!-- Counters -->
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-[var(--nc-fg-4)]">PKT</span>
    <span class="text-[var(--nc-fg)] font-bold">{fmtNum($stats.total_packets)}</span>
  </div>
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-[var(--nc-fg-4)]">SIZE</span>
    <span class="text-[var(--nc-fg)] font-bold">{fmtBytes($stats.total_bytes)}</span>
  </div>
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-[var(--nc-fg-4)]">RATE</span>
    <span class="text-[var(--nc-fg)] font-bold">{$stats.packets_per_sec}/s</span>
  </div>
  {#if $captureFilter ?? '' !== ''}
    <div class="flex items-center gap-1 whitespace-nowrap" style="color: var(--nc-p-tcp)">
      <span>SHOWN</span>
      <span class="font-bold">{fmtNum($filteredPackets.length)}</span>
    </div>
  {/if}

  <!-- Divider -->
  <div class="w-px h-4 bg-[var(--nc-border)] shrink-0"></div>

  <!-- Protocol bars -->
  {#each topProtos as [proto, count]}
    {@const pct = Math.round((count / protoTotal) * 100)}
    <div class="flex items-center gap-1.5 whitespace-nowrap">
      <div class="w-2 h-2 rounded-sm shrink-0" style={protoStyle(proto)}></div>
      <span class="text-[var(--nc-fg-2)]">{proto}</span>
      <div class="w-14 bg-[var(--nc-surface-2)] rounded-full h-1.5 shrink-0">
        <div
          class="h-1.5 rounded-full transition-[width] duration-300"
          style="width: {pct}%; {protoStyle(proto)}"
        ></div>
      </div>
      <span class="text-[var(--nc-fg-4)]">{pct}%</span>
    </div>
  {/each}

  <!-- Connection status — pushed right -->
  <div class="ml-auto flex items-center gap-1.5 whitespace-nowrap shrink-0">
    <div class="w-1.5 h-1.5 rounded-full {statusPulse ? 'animate-pulse' : ''}"
      style={statusDotStyle}></div>
    <span class="uppercase tracking-widest" style={statusTextStyle}>{$connectionStatus}</span>
  </div>
</div>
