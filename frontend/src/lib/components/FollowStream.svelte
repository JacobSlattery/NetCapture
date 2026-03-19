<script lang="ts">
  import { createEventDispatcher } from 'svelte'
  import { packets } from '../stores'
  import type { Packet } from '../types'

  export let anchor: Packet

  const dispatch = createEventDispatcher()

  type DisplayMode = 'ascii' | 'hex'
  let mode: DisplayMode = 'ascii'

  function sameStream(p: Packet, a: Packet): boolean {
    if (a.src_port == null && a.dst_port == null) {
      // ICMP / no ports — match by IP pair
      return (p.src_ip === a.src_ip && p.dst_ip === a.dst_ip) ||
             (p.src_ip === a.dst_ip && p.dst_ip === a.src_ip)
    }
    return (
      (p.src_ip === a.src_ip && p.dst_ip === a.dst_ip &&
       p.src_port === a.src_port && p.dst_port === a.dst_port) ||
      (p.src_ip === a.dst_ip && p.dst_ip === a.src_ip &&
       p.src_port === a.dst_port && p.dst_port === a.src_port)
    )
  }

  $: streamPackets = $packets.filter(p => sameStream(p, anchor)).sort((a, b) => a.id - b.id)

  // Extract application-layer payload from raw_hex
  function extractPayload(pkt: Packet): Uint8Array | null {
    if (!pkt.raw_hex) return null
    try {
      const raw = new Uint8Array(pkt.raw_hex.match(/.{2}/g)!.map(b => parseInt(b, 16)))
      let offset = 0
      const firstNibble = raw[0] >> 4
      const hasEthernet = firstNibble !== 4 && firstNibble !== 6
      if (hasEthernet) offset += 14
      if (raw.length <= offset) return null
      const ipVersion = raw[offset] >> 4
      if (ipVersion !== 4 && ipVersion !== 6) return null
      const ipHdrLen = ipVersion === 4 ? (raw[offset] & 0x0f) * 4 : 40
      offset += ipHdrLen
      const proto = ipVersion === 4 ? raw[offset - ipHdrLen + 9] : raw[offset - ipHdrLen + 6]
      if (proto === 6) { // TCP
        if (raw.length <= offset + 12) return null
        const tcpHdrLen = (raw[offset + 12] >> 4) * 4
        offset += tcpHdrLen
      } else if (proto === 17) { // UDP
        offset += 8
      }
      return raw.slice(offset)
    } catch {
      return null
    }
  }

  function toAscii(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('')
  }

  function toHexDump(bytes: Uint8Array): string {
    const lines: string[] = []
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16)
      const hex   = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ')
      const ascii = Array.from(chunk).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('')
      lines.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(47)}  ${ascii}`)
    }
    return lines.join('\n')
  }

  function isForward(pkt: Packet): boolean {
    return pkt.src_ip === anchor.src_ip && pkt.src_port === anchor.src_port
  }

  const protoLabel = anchor.protocol.split('/')[0]
</script>

<div class="fixed inset-0 z-[100] flex items-center justify-center bg-black/60">
  <div
    class="flex flex-col rounded-lg shadow-2xl bg-[var(--nc-surface-1)] border border-[var(--nc-border)]"
    style="width: 760px; height: 560px; min-width: 480px; min-height: 320px; resize: both; overflow: hidden;"
  >
    <!-- Header -->
    <div class="flex items-center justify-between px-5 py-3 border-b border-[var(--nc-border)] shrink-0">
      <div>
        <div class="font-semibold text-sm text-[var(--nc-fg)]">Follow {protoLabel} Stream</div>
        <div class="text-[10px] text-[var(--nc-fg-4)] mt-0.5 font-mono">
          {anchor.src_ip}{anchor.src_port != null ? `:${anchor.src_port}` : ''} ↔
          {anchor.dst_ip}{anchor.dst_port != null ? `:${anchor.dst_port}` : ''}
          · {streamPackets.length} packets
        </div>
      </div>
      <div class="flex items-center gap-3">
        <!-- Mode toggle -->
        <div class="flex rounded border border-[var(--nc-border)] overflow-hidden text-[10px]">
          <button on:click={() => mode = 'ascii'}
            class="px-2 py-0.5 transition-colors
                   {mode === 'ascii' ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
            ASCII
          </button>
          <button on:click={() => mode = 'hex'}
            class="px-2 py-0.5 transition-colors border-l border-[var(--nc-border)]
                   {mode === 'hex' ? 'bg-blue-700 text-white' : 'text-[var(--nc-fg-3)] hover:bg-[var(--nc-surface-2)]'}">
            Hex dump
          </button>
        </div>
        <button on:click={() => dispatch('close')}
          class="text-[var(--nc-fg-4)] hover:text-[var(--nc-fg)] transition-colors p-1">
          <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/>
          </svg>
        </button>
      </div>
    </div>

    <!-- Stream content -->
    <div class="flex-1 overflow-y-auto min-h-0 p-3 font-mono text-xs space-y-1">
      {#each streamPackets as pkt}
        {@const payload = extractPayload(pkt)}
        {#if payload && payload.length > 0}
          <div class="rounded px-2 py-1.5 {isForward(pkt) ? 'bg-blue-900/30 border-l-2 border-blue-500' : 'bg-rose-900/20 border-l-2 border-rose-500'}">
            <div class="text-[10px] text-[var(--nc-fg-4)] mb-1">
              #{pkt.id} · {pkt.timestamp} · {pkt.src_ip}{pkt.src_port != null ? `:${pkt.src_port}` : ''} → {pkt.dst_ip}{pkt.dst_port != null ? `:${pkt.dst_port}` : ''} · {payload.length} bytes
            </div>
            {#if mode === 'ascii'}
              <pre class="whitespace-pre-wrap break-all text-[var(--nc-fg-2)] leading-relaxed">{toAscii(payload)}</pre>
            {:else}
              <pre class="whitespace-pre text-[var(--nc-fg-2)] leading-relaxed text-[10px]">{toHexDump(payload)}</pre>
            {/if}
          </div>
        {/if}
      {:else}
        <div class="text-center text-[var(--nc-fg-5)] py-8">No stream packets found.</div>
      {/each}
    </div>

    <!-- Footer -->
    <div class="shrink-0 flex items-center justify-between px-5 py-3 border-t border-[var(--nc-border)] text-xs text-[var(--nc-fg-4)]">
      <span>
        <span class="inline-block w-2 h-2 rounded-sm bg-blue-500 mr-1"></span>
        {anchor.src_ip}{anchor.src_port != null ? `:${anchor.src_port}` : ''} (initiator)
        &nbsp;
        <span class="inline-block w-2 h-2 rounded-sm bg-rose-500 mr-1"></span>
        {anchor.dst_ip}{anchor.dst_port != null ? `:${anchor.dst_port}` : ''} (responder)
      </span>
      <button on:click={() => dispatch('close')}
        class="px-3 py-1 rounded border border-[var(--nc-border)] text-[var(--nc-fg-2)] hover:bg-[var(--nc-surface-2)] transition-colors">
        Close
      </button>
    </div>
  </div>
</div>
