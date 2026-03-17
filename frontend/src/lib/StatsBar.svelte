<script>
  import { stats, connectionStatus, filteredPackets, captureFilter } from '../stores.js'

  function fmtBytes(b) {
    if (b < 1024) return `${b} B`
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1073741824) return `${(b / 1048576).toFixed(2)} MB`
    return `${(b / 1073741824).toFixed(2)} GB`
  }

  function fmtNum(n) {
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
    return String(n)
  }

  const PROTO_COLOR = {
    TCP: 'bg-blue-500', UDP: 'bg-green-500', DNS: 'bg-purple-500',
    ICMP: 'bg-amber-500', HTTP: 'bg-orange-500', HTTPS: 'bg-cyan-500',
    TLS: 'bg-cyan-500', ARP: 'bg-pink-500',
  }

  function protoColor(name) {
    return PROTO_COLOR[name] ?? 'bg-gray-500'
  }

  $: topProtos = Object.entries($stats.protocol_counts ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)

  $: protoTotal = topProtos.reduce((s, [, v]) => s + v, 0) || 1

  $: statusColor = {
    connected:    'text-green-400',
    connecting:   'text-yellow-400',
    error:        'text-red-400',
    disconnected: 'text-gray-600',
  }[$connectionStatus] ?? 'text-gray-600'

  $: statusDot = {
    connected:    'bg-green-400 animate-pulse',
    connecting:   'bg-yellow-400 animate-pulse',
    error:        'bg-red-400',
    disconnected: 'bg-gray-600',
  }[$connectionStatus] ?? 'bg-gray-600'
</script>

<div class="flex items-center gap-4 px-4 py-1.5 bg-[#0d1117] border-b border-[#30363d] text-xs overflow-x-auto shrink-0 font-mono">
  <!-- Counters -->
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-gray-600">PKT</span>
    <span class="text-white font-bold">{fmtNum($stats.total_packets)}</span>
  </div>
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-gray-600">SIZE</span>
    <span class="text-white font-bold">{fmtBytes($stats.total_bytes)}</span>
  </div>
  <div class="flex items-center gap-1 whitespace-nowrap">
    <span class="text-gray-600">RATE</span>
    <span class="text-white font-bold">{$stats.packets_per_sec}/s</span>
  </div>
  {#if $captureFilter ?? '' !== ''}
    <div class="flex items-center gap-1 whitespace-nowrap text-blue-400">
      <span>SHOWN</span>
      <span class="font-bold">{fmtNum($filteredPackets.length)}</span>
    </div>
  {/if}

  <!-- Divider -->
  <div class="w-px h-4 bg-[#30363d] shrink-0"></div>

  <!-- Protocol bars -->
  {#each topProtos as [proto, count]}
    {@const pct = Math.round((count / protoTotal) * 100)}
    <div class="flex items-center gap-1.5 whitespace-nowrap">
      <div class="w-2 h-2 rounded-sm shrink-0 {protoColor(proto)}"></div>
      <span class="text-gray-400">{proto}</span>
      <div class="w-14 bg-[#21262d] rounded-full h-1.5 shrink-0">
        <div
          class="h-1.5 rounded-full transition-[width] duration-300 {protoColor(proto)}"
          style="width: {pct}%"
        ></div>
      </div>
      <span class="text-gray-600">{pct}%</span>
    </div>
  {/each}

  <!-- Connection status — pushed right -->
  <div class="ml-auto flex items-center gap-1.5 whitespace-nowrap shrink-0">
    <div class="w-1.5 h-1.5 rounded-full {statusDot}"></div>
    <span class="uppercase tracking-widest {statusColor}">{$connectionStatus}</span>
  </div>
</div>
