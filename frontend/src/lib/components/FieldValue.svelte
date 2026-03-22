<script lang="ts">
  import type { DecodedValue } from '../types'
  export let value: DecodedValue
  export let depth: number = 0
  /** Dot-path prefix for context menu — e.g. "status" for a top-level field named "status" */
  export let fieldPath: string = ''
  /** Optional handler for right-click on a sub-item: (event, dotPath, value) */
  export let oncontext:   ((e: MouseEvent, path: string, val: DecodedValue) => void) | null = null
  /** Notify parent when a sub-row is entered; path is the full dot-path */
  export let onhover:     ((path: string) => void) | null = null
  /** Notify parent when a sub-row is left; path is the full dot-path */
  export let onleave:     ((path: string) => void) | null = null
  /** Currently highlighted path (full dot-path, strict match per row) */
  export let hoveredPath: string | null = null
  /** When true, the parent container is highlighted but individual values should be visually cut out */
  export let structMode:  boolean = false
  /** Granular changed dot-paths from track diff (e.g. "meta.fw") */
  export let changedPaths: Set<string> = new Set()
  /** New top-level keys from track diff */
  export let newPaths:     Set<string> = new Set()

  const HL      = 'background:var(--nc-row-selected);color:#fff'
  const CUTOUT  = 'background:var(--nc-surface-1);color:var(--nc-fg-1)'
  const CHANGED = 'background:color-mix(in srgb,var(--nc-status-err) 18%,transparent)'
  const ISNEW   = 'background:color-mix(in srgb,var(--nc-status-ok) 14%,transparent)'

  /** Returns true if path itself or any descendant is in the set */
  function hasPath(set: Set<string>, path: string): boolean {
    if (set.has(path)) return true
    for (const p of set) if (p.startsWith(path + '.')) return true
    return false
  }

  $: isArray  = Array.isArray(value)
  $: isObject = value !== null && typeof value === 'object' && !Array.isArray(value)
</script>

{#if isArray}
  <div class="w-full">
    {#each value as DecodedValue[] as item, i}
      {@const subPath    = fieldPath ? `${fieldPath}.${i}` : String(i)}
      {@const isStruct   = hoveredPath === subPath + '.__struct'}
      {@const hl         = hoveredPath === subPath || isStruct}
      {@const rowChanged = !hl && changedPaths.has(subPath)}
      {@const rowNew     = !hl && !rowChanged && newPaths.has(subPath)}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="flex items-baseline gap-1 py-px"
        style={hl ? HL : structMode ? CUTOUT : rowChanged ? CHANGED : rowNew ? ISNEW : ''}
        on:mouseenter={() => { if (onhover) onhover(subPath) }}
        on:mouseleave={() => { if (onleave) onleave(subPath) }}
        on:contextmenu|stopPropagation={(e) => { if (oncontext) oncontext(e, subPath, item) }}>
        <span class="text-[10px] shrink-0" style={hl ? 'color:#fff' : 'color:var(--nc-fg-3)'}>[{i}]</span>
        <svelte:self value={item} depth={depth + 1} fieldPath={subPath}
          {oncontext} {onhover} {onleave} {hoveredPath} structMode={isStruct || structMode} {changedPaths} {newPaths} />
      </div>
    {/each}
  </div>
{:else if isObject}
  <div class="w-full">
    {#each Object.entries(value) as [k, v]}
      {@const subPath    = fieldPath ? `${fieldPath}.${k}` : k}
      {@const isStruct   = hoveredPath === subPath + '.__struct'}
      {@const hl         = hoveredPath === subPath || isStruct}
      {@const rowChanged = !hl && changedPaths.has(subPath)}
      {@const rowNew     = !hl && !rowChanged && newPaths.has(subPath)}
      <!-- svelte-ignore a11y-no-static-element-interactions -->
      <div class="flex items-baseline gap-1 py-px"
        style={hl ? HL : structMode ? CUTOUT : rowChanged ? CHANGED : rowNew ? ISNEW : ''}
        on:mouseenter={() => { if (onhover) onhover(subPath) }}
        on:mouseleave={() => { if (onleave) onleave(subPath) }}
        on:contextmenu|stopPropagation={(e) => { if (oncontext) oncontext(e, subPath, v) }}>
        <span class="text-[10px] shrink-0 truncate max-w-16" style={hl ? 'color:#fff' : 'color:var(--nc-fg-3)'} title={k}>{k}</span>
        <svelte:self value={v} depth={depth + 1} fieldPath={subPath}
          {oncontext} {onhover} {onleave} {hoveredPath} structMode={isStruct || structMode} {changedPaths} {newPaths} />
      </div>
    {/each}
  </div>
{:else}
  <span class="text-[11px] break-all font-semibold">{String(value)}</span>
{/if}
