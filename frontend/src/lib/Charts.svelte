<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import * as echarts from 'echarts'
  import { stats, chartHistory } from '../stores'

  let pieEl:   HTMLDivElement
  let lineEl:  HTMLDivElement
  let pieChart:  echarts.ECharts | undefined
  let lineChart: echarts.ECharts | undefined
  let mo:  MutationObserver | undefined

  const PROTO_COLORS = {
    TCP:   '#3b82f6',
    UDP:   '#10b981',
    DNS:   '#8b5cf6',
    ICMP:  '#f59e0b',
    HTTP:  '#f97316',
    HTTPS: '#06b6d4',
    TLS:   '#06b6d4',
    ARP:   '#ec4899',
  }

  function protoColor(name: string): string {
    return (PROTO_COLORS as Record<string, string>)[name] ?? '#6b7280'
  }

  function getThemeColors() {
    const s = getComputedStyle(document.documentElement)
    const get = (v: string): string => s.getPropertyValue(v).trim()
    return {
      surface1:  get('--nc-surface-1'),
      border:    get('--nc-border'),
      border1:   get('--nc-border-1'),
      fg:        get('--nc-fg'),
      fg2:       get('--nc-fg-2'),
      fg3:       get('--nc-fg-3'),
    }
  }

  function initCharts() {
    pieChart?.dispose()
    lineChart?.dispose()

    pieChart  = echarts.init(pieEl,  null, { renderer: 'canvas' })
    lineChart = echarts.init(lineEl, null, { renderer: 'svg'    })

    const t = getThemeColors()

    // Set full static config once — subsequent updates only push data
    pieChart.setOption({
      backgroundColor: 'transparent',
      animation: false,
      tooltip: {
        trigger: 'item',
        formatter: '{b}: {c} ({d}%)',
        backgroundColor: t.surface1,
        borderColor: t.border,
        textStyle: { color: t.fg },
      },
      legend: {
        orient: 'vertical',
        right: '4%',
        top: 'center',
        textStyle: { color: t.fg2, fontSize: 11 },
      },
      series: [{
        name: 'Protocol',
        type: 'pie',
        radius: ['42%', '70%'],
        center: ['38%', '50%'],
        avoidLabelOverlap: true,
        label: { show: false },
        emphasis: {
          label: { show: true, fontSize: 12, fontWeight: 'bold', color: t.fg },
          itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0,0,0,0.5)' },
        },
        data: [],
      }],
    })

    lineChart.setOption({
      backgroundColor: 'transparent',
      animation: false,
      grid: { top: 28, right: 54, bottom: 28, left: 52 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: t.surface1,
        borderColor: t.border,
        textStyle: { color: t.fg, fontSize: 11 },
        formatter: (params: Array<{ marker: string; seriesName: string; value: number; seriesIndex: number }>) =>
          params.map(p => `${p.marker}${p.seriesName}: <b>${p.value}${p.seriesIndex === 1 ? ' KB/s' : ' pkt/s'}</b>`).join('<br>'),
      },
      legend: {
        top: 4, right: 8,
        textStyle: { color: t.fg2, fontSize: 10 },
        data: ['Pkts/s', 'KB/s'],
      },
      xAxis: {
        type: 'category',
        data: [],
        axisLine: { lineStyle: { color: t.border } },
        axisLabel: {
          color: t.fg3, fontSize: 10,
          interval: (idx: number) => idx % 10 === 0,
          formatter: (val: string) => val.slice(0, 8),
        },
        splitLine: { show: false },
      },
      yAxis: [
        {
          type: 'value',
          name: 'Pkts/s',
          nameTextStyle: { color: t.fg3, fontSize: 10 },
          axisLine: { lineStyle: { color: t.border } },
          axisLabel: { color: t.fg3, fontSize: 10 },
          splitLine: { lineStyle: { color: t.border1 } },
        },
        {
          type: 'value',
          name: 'KB/s',
          nameTextStyle: { color: t.fg3, fontSize: 10 },
          axisLine: { lineStyle: { color: t.border } },
          axisLabel: { color: t.fg3, fontSize: 10 },
          splitLine: { show: false },
        },
      ],
      series: [
        {
          name: 'Pkts/s',
          type: 'bar',
          data: [],
          itemStyle: { color: '#3b82f6' },
          barMaxWidth: 12,
        },
        {
          name: 'KB/s',
          type: 'line',
          yAxisIndex: 1,
          data: [],
          smooth: true,
          symbol: 'none',
          lineStyle: { color: '#10b981', width: 2 },
          areaStyle: { color: 'rgba(16,185,129,0.12)' },
        },
      ],
    })
  }

  function updatePie(counts: Record<string, number> | undefined): void {
    if (!pieChart) return
    const raw = Object.entries(counts ?? {}).sort((a, b) => b[1] - a[1])
    if (!raw.length) return
    pieChart.setOption({
      series: [{ data: raw.map(([name, value]) => ({ name, value, itemStyle: { color: protoColor(name) } })) }],
    })
  }

  function updateLine(history: import('../types').ChartPoint[] | undefined): void {
    if (!lineChart || !history?.length) return

    // Always fill a fixed 50-slot window so the chart width stays constant
    // and data accumulates from the right edge rather than expanding outward.
    const SLOTS = 50
    const pad   = SLOTS - history.length
    const times  = new Array(SLOTS).fill('')
    const pkts   = new Array(SLOTS).fill(null)
    const kbytes = new Array(SLOTS).fill(null)

    for (let i = 0; i < history.length; i++) {
      const h = history[i]
      times[pad + i]  = h.time
      pkts[pad + i]   = h.packets
      kbytes[pad + i] = +(h.bytes / 1024).toFixed(1)
    }

    lineChart.setOption({
      xAxis: { data: times },
      series: [{ data: pkts }, { data: kbytes }],
    })
  }

  let ro: ResizeObserver | undefined
  let resizeTimer: ReturnType<typeof setTimeout> | null = null

  onMount(() => {
    initCharts()
    // Seed with current store values — the reactive statements already fired
    // before onMount (when the charts were still null), so we repopulate here.
    updatePie($stats.protocol_counts)
    updateLine($chartHistory)

    ro = new ResizeObserver(() => {
      clearTimeout(resizeTimer ?? undefined)
      resizeTimer = setTimeout(() => {
        pieChart?.resize()
        lineChart?.resize()
      }, 100)
    })
    if (pieEl) ro.observe(pieEl)
    if (lineEl) ro.observe(lineEl)

    // Re-init charts when parent app toggles the theme class on <html>
    mo = new MutationObserver(() => {
      initCharts()
      updatePie($stats.protocol_counts)
      updateLine($chartHistory)
    })
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
  })

  onDestroy(() => {
    clearTimeout(resizeTimer ?? undefined)
    ro?.disconnect()
    mo?.disconnect()
    pieChart?.dispose()
    lineChart?.dispose()
  })

  // Reactive updates driven by stores
  $: updatePie($stats.protocol_counts)
  $: updateLine($chartHistory)
</script>

<div class="flex border-b border-[var(--nc-border)] bg-[var(--nc-surface)] shrink-0" style="height:190px">
  <div bind:this={pieEl} class="w-[32%] min-w-[180px]"></div>
  <div class="w-px bg-[var(--nc-surface-2)]"></div>
  <div bind:this={lineEl} class="flex-1"></div>
</div>
