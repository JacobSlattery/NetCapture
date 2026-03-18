<script lang="ts">
  import { onMount, onDestroy } from 'svelte'
  import * as echarts from 'echarts/core'
  import { PieChart, BarChart, LineChart } from 'echarts/charts'
  import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
  import { CanvasRenderer, SVGRenderer } from 'echarts/renderers'
  import type { ECharts } from 'echarts/core'
  import { stats, chartHistory } from '../stores'

  echarts.use([PieChart, BarChart, LineChart, TooltipComponent, LegendComponent, GridComponent, CanvasRenderer, SVGRenderer])

  let pieEl:   HTMLDivElement
  let lineEl:  HTMLDivElement
  let pieChart:  ECharts | undefined
  let lineChart: ECharts | undefined
  let mo:  MutationObserver | undefined

  // Protocol and chart colours are read from CSS vars at init time so they
  // stay in sync with app.css. Re-read on theme change via MutationObserver.
  let protoColors: Record<string, string> = {}

  function protoColor(name: string): string {
    return protoColors[name] ?? protoColors['default'] ?? '#6b7280'
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
      pTcp:      get('--nc-p-tcp'),
      pUdp:      get('--nc-p-udp'),
      pDns:      get('--nc-p-dns'),
      pIcmp:     get('--nc-p-icmp'),
      pHttp:     get('--nc-p-http'),
      pHttps:    get('--nc-p-https'),
      pArp:      get('--nc-p-arp'),
      pDefault:  get('--nc-p-default'),
    }
  }

  function initCharts() {
    pieChart?.dispose()
    lineChart?.dispose()

    pieChart  = echarts.init(pieEl,  null, { renderer: 'canvas' })
    lineChart = echarts.init(lineEl, null, { renderer: 'svg'    })

    const t = getThemeColors()
    protoColors = {
      TCP: t.pTcp, UDP: t.pUdp, DNS: t.pDns, ICMP: t.pIcmp,
      HTTP: t.pHttp, HTTPS: t.pHttps, TLS: t.pHttps, ARP: t.pArp,
      default: t.pDefault,
    }

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

    const savedLegend = loadLegend()

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
        top: 4, left: 'center',
        textStyle: { color: t.fg2, fontSize: 10 },
        data: ['Pkts/s', 'KB/s'],
        ...(savedLegend ? { selected: savedLegend } : {}),
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
          itemStyle: { color: t.pTcp },
          barMaxWidth: 12,
        },
        {
          name: 'KB/s',
          type: 'line',
          yAxisIndex: 1,
          color: t.pUdp,
          data: [],
          smooth: true,
          symbol: 'none',
          lineStyle: { color: t.pUdp, width: 2 },
          areaStyle: { color: `color-mix(in srgb, ${t.pUdp} 12%, transparent)` },
        },
      ],
    })

    lineChart.on('legendselectchanged', (e: { selected: Record<string, boolean> }) => {
      saveLegend(e.selected)
    })
  }

  const _LEGEND_KEY = 'nc:chartLegend'

  function saveLegend(selected: Record<string, boolean>): void {
    localStorage.setItem(_LEGEND_KEY, JSON.stringify(selected))
  }

  function loadLegend(): Record<string, boolean> | null {
    try {
      const raw = localStorage.getItem(_LEGEND_KEY)
      return raw ? JSON.parse(raw) as Record<string, boolean> : null
    } catch { return null }
  }

  function updatePie(counts: Record<string, number> | undefined): void {
    if (!pieChart) return
    const raw = Object.entries(counts ?? {}).sort((a, b) => b[1] - a[1])
    if (!raw.length) {
      pieChart.setOption({ series: [{ data: [] }] })
      return
    }
    pieChart.setOption({
      series: [{ data: raw.map(([name, value]) => ({ name, value, itemStyle: { color: protoColor(name) } })) }],
    })
  }

  function updateLine(history: import('../types').ChartPoint[] | undefined): void {
    if (!lineChart) return
    if (!history?.length) {
      lineChart.setOption({
        xAxis: { data: [] },
        series: [{ data: [] }, { data: [] }],
      })
      return
    }

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
