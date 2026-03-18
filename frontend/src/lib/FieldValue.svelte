<script lang="ts">
  import type { DecodedValue } from '../types'
  export let value: DecodedValue
  export let depth: number = 0

  $: isArray  = Array.isArray(value)
  $: isObject = value !== null && typeof value === 'object' && !Array.isArray(value)
</script>

{#if isArray}
  <div class="ml-2 border-l border-[var(--nc-border-2)] pl-1.5 w-full">
    {#each value as item, i}
      <div class="flex items-baseline gap-1 py-px">
        <span class="text-[var(--nc-fg-3)] text-[10px] shrink-0">[{i}]</span>
        <svelte:self value={item} depth={depth + 1} />
      </div>
    {/each}
  </div>
{:else if isObject}
  <div class="ml-2 border-l border-[var(--nc-border-2)] pl-1.5 w-full">
    {#each Object.entries(value) as [k, v]}
      <div class="flex items-baseline gap-1 py-px">
        <span class="text-[var(--nc-fg-3)] text-[10px] shrink-0 truncate max-w-[4rem]">{k}</span>
        <svelte:self value={v} depth={depth + 1} />
      </div>
    {/each}
  </div>
{:else}
  <span class="text-[var(--nc-fg-1)] text-[11px] break-all font-semibold">{String(value)}</span>
{/if}
