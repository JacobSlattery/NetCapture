<script lang="ts">
  import { onMount } from 'svelte'

  export let x = 0
  export let y = 0
  export let items: Array<
    | { label: string; sub?: string; action: () => void }
    | { separator: true }
  > = []
  export let onclose: (() => void) | undefined = undefined

  let menuEl: HTMLDivElement

  function close() { onclose?.() }

  // Clamp position to viewport so the menu never overflows
  function clampedStyle(x: number, y: number): string {
    if (!menuEl) return `left:${x}px;top:${y}px`
    const { offsetWidth: w, offsetHeight: h } = menuEl
    const cx = Math.min(x, window.innerWidth  - w - 8)
    const cy = Math.min(y, window.innerHeight - h - 8)
    return `left:${Math.max(4, cx)}px;top:${Math.max(4, cy)}px`
  }

  let style = `left:${x}px;top:${y}px`
  onMount(() => { style = clampedStyle(x, y) })

  function handleWindow(e: MouseEvent | KeyboardEvent) {
    if (e instanceof KeyboardEvent && e.key !== 'Escape') return
    close()
  }
</script>

<svelte:window on:mousedown={handleWindow} on:keydown={handleWindow} on:scroll={close} />

<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-no-static-element-interactions -->
<div
  bind:this={menuEl}
  class="fixed z-200 min-w-50 py-1
         bg-(--nc-surface-1) border border-(--nc-border) rounded shadow-2xl text-xs"
  {style}
  on:mousedown|stopPropagation
  on:click|stopPropagation
>
  {#each items as item}
    {#if 'separator' in item}
      <div class="my-1 border-t border-(--nc-border-1)"></div>
    {:else}
      <button
        class="w-full text-left px-3 py-1.5 flex items-baseline gap-3
               text-(--nc-fg-2) hover:bg-(--nc-surface-2) hover:text-(--nc-fg)
               transition-colors duration-75"
        on:click={() => { item.action(); close() }}
      >
        <span class="shrink-0">{item.label}</span>
        {#if item.sub}
          <span class="font-mono text-[10px] text-(--nc-fg-4) truncate">{item.sub}</span>
        {/if}
      </button>
    {/if}
  {/each}
</div>
