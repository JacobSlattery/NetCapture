<script>
  import { onMount, onDestroy } from 'svelte'
  import * as echarts from 'echarts'
  import { stats, chartHistory } from '../stores.js'

  let pieEl
  let lineEl
  let pieChart
  let lineChart

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

  function protoColor(name) {
    return PROTO_COLORS[name] ?? '#6b7280'
  }

  function initCharts() {
    pieChart  = echarts.init(pieEl,  'dark', { renderer: 'canvas' })
    lineChart = echarts.init(lineEl, 'dark', { renderer: 'svg'    })

    // Set full static config once — subsequent updates only push data
    pieChart.setOption({
      backgroundColor: 'transparent',
      animation: false,
      tooltip: {
        trigger: 'item',
        formatter: '{b}: {c} ({d}%)',
        backgroundColor: '#161b22',
        borderColor: '#30363d',
        textStyle: { color: '#e6edf3' },
      },
      legend: {
        orient: 'vertical',
        right: '4%',
        top: 'center',
        textStyle: { color: '#8b949e', fontSize: 11 },
      },
      series: [{
        name: 'Protocol',
        type: 'pie',
        radius: ['42%', '70%'],
        center: ['38%', '50%'],
        avoidLabelOverlap: true,
        label: { show: false },
        emphasis: {
          label: { show: true, fontSize: 12, fontWeight: 'bold', color: '#e6edf3' },
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
        backgroundColor: '#161b22',
        borderColor: '#30363d',
        textStyle: { color: '#e6edf3', fontSize: 11 },
        formatter: params =>
          params.map(p => `${p.marker}${p.seriesName}: <b>${p.value}${p.seriesIndex === 1 ? ' KB/s' : ' pkt/s'}</b>`).join('<br>'),
      },
      legend: {
        top: 4, right: 8,
        textStyle: { color: '#8b949e', fontSize: 10 },
        data: ['Pkts/s', 'KB/s'],
      },
      xAxis: {
        type: 'category',
        data: [],
        axisLine: { lineStyle: { color: '#30363d' } },
        axisLabel: {
          color: '#6e7681', fontSize: 10,
          interval: (idx) => idx % 10 === 0,
          formatter: val => val.slice(0, 8),
        },
        splitLine: { show: false },
      },
      yAxis: [
        {
          type: 'value',
          name: 'Pkts/s',
          nameTextStyle: { color: '#6e7681', fontSize: 10 },
          axisLine: { lineStyle: { color: '#30363d' } },
          axisLabel: { color: '#6e7681', fontSize: 10 },
          splitLine: { lineStyle: { color: '#1c2128' } },
        },
        {
          type: 'value',
          name: 'KB/s',
          nameTextStyle: { color: '#6e7681', fontSize: 10 },
          axisLine: { lineStyle: { color: '#30363d' } },
          axisLabel: { color: '#6e7681', fontSize: 10 },
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

  function updatePie(counts) {
    if (!pieChart) return
    const raw = Object.entries(counts ?? {}).sort((a, b) => b[1] - a[1])
    if (!raw.length) return
    pieChart.setOption({
      series: [{ data: raw.map(([name, value]) => ({ name, value, itemStyle: { color: protoColor(name) } })) }],
    })
  }

  function updateLine(history) {
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

  let ro
  let resizeTimer = null

  onMount(() => {
    initCharts()
    // Seed with current store values — the reactive statements already fired
    // before onMount (when the charts were still null), so we repopulate here.
    updatePie($stats.protocol_counts)
    updateLine($chartHistory)
    ro = new ResizeObserver(() => {
      clearTimeout(resizeTimer)
      resizeTimer = setTimeout(() => {
        pieChart?.resize()
        lineChart?.resize()
      }, 100)
    })
    if (pieEl) ro.observe(pieEl)
    if (lineEl) ro.observe(lineEl)
  })

  onDestroy(() => {
    clearTimeout(resizeTimer)
    ro?.disconnect()
    pieChart?.dispose()
    lineChart?.dispose()
  })

  // Reactive updates driven by stores
  $: updatePie($stats.protocol_counts)
  $: updateLine($chartHistory)
</script>

<div class="flex border-b border-[#30363d] bg-[#0d1117] shrink-0" style="height:190px">
  <div bind:this={pieEl} class="w-[32%] min-w-[180px]"></div>
  <div class="w-px bg-[#21262d]"></div>
  <div bind:this={lineEl} class="flex-1"></div>
</div>
