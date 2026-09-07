<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowRight } from '@element-plus/icons-vue'
import type { EChartsOption } from 'echarts'
import EChart from '@/components/EChart.vue'
import { api, subscribeFeed } from '@/api'
import type { Alert, Dashboard, Severity } from '@/api/types'
import { fmtHM, nowClock } from '@/utils/format'

const router = useRouter()

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}

/* ---------- 自适应缩放（1920x1080 定稿等比缩放） ---------- */
const scale = ref(1)
function fit() {
  scale.value = Math.min(window.innerWidth / 1920, window.innerHeight / 1080)
}
const frameStyle = computed(() => {
  const s = scale.value
  return {
    width: `${1920 * s}px`,
    height: `${1080 * s}px`,
    transform: `scale(${s})`,
  }
})

/* ---------- 数据 ---------- */
const dash = ref<Dashboard | null>(null)
const clock = ref(nowClock())
const dateStr = ref('')

const live: Alert[] = []
const seen = new Set<string>()
function ingestAlerts(list: Alert[]) {
  for (const a of list) {
    if (!seen.has(a.id)) {
      seen.add(a.id)
      live.unshift(a)
    }
  }
  if (live.length > 60) live.length = 60
}
const liveAlerts = ref<Alert[]>([])
const lastAlertId = ref('')

function nowDate() {
  const d = new Date()
  const w = ['日', '一', '二', '三', '四', '五', '六'][d.getDay()]
  const p = (n: number) => String(n).padStart(2, '0')
  dateStr.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} 星期${w}`
}

async function refresh() {
  const d = await api.dashboard()
  dash.value = d
  ingestAlerts(d.recentAlerts)
  liveAlerts.value = live.slice(0, 8)
}

function tick() {
  clock.value = nowClock()
}

let timer: number | undefined
let poll: number | undefined
let unsub: (() => void) | undefined

onMounted(async () => {
  fit()
  window.addEventListener('resize', fit)
  timer = window.setInterval(tick, 1000)
  nowDate()
  await refresh()
  poll = window.setInterval(() => void refresh(), 6000)
  unsub = subscribeFeed((e) => {
    if (e.kind === 'alert' && e.alert) {
      lastAlertId.value = e.alert.id
      ingestAlerts([e.alert])
      liveAlerts.value = live.slice(0, 8)
    }
  })
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', fit)
  if (timer) window.clearInterval(timer)
  if (poll) window.clearInterval(poll)
  unsub?.()
})

/* ---------- ECharts 配置 ---------- */
const AXIS = {
  axisLine: { lineStyle: { color: 'rgba(125,179,255,0.25)' } },
  axisLabel: { color: '#7d97bf', fontSize: 11 },
  splitLine: { lineStyle: { color: 'rgba(125,179,255,0.08)' } },
}

const trendOption = computed<EChartsOption>(() => {
  const d = dash.value
  if (!d) return {}
  return {
    tooltip: { trigger: 'axis', backgroundColor: 'rgba(10,20,40,0.95)', borderColor: 'rgba(34,211,238,0.4)', textStyle: { color: '#e6f2ff', fontSize: 12 } },
    legend: { data: ['本时段', '上一时段'], textStyle: { color: '#9fb6d8' }, right: 8, top: 0 },
    grid: { left: 42, right: 16, top: 34, bottom: 26 },
    xAxis: { type: 'category', data: d.hourly.map((h) => h.label), ...AXIS },
    yAxis: { type: 'value', ...AXIS },
    series: [
      {
        name: '本时段',
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: d.hourly.map((h) => h.cur),
        lineStyle: { width: 2, color: '#22d3ee' },
        itemStyle: { color: '#22d3ee' },
        areaStyle: {
          color: {
            type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(34,211,238,0.35)' },
              { offset: 1, color: 'rgba(34,211,238,0.02)' },
            ],
          },
        },
      },
      {
        name: '上一时段',
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: d.hourly.map((h) => h.prev),
        lineStyle: { width: 1.5, color: '#64748b', type: 'dashed' },
        itemStyle: { color: '#64748b' },
      },
    ],
  }
})

const rulesOption = computed<EChartsOption>(() => {
  const d = dash.value
  if (!d) return {}
  const top = [...d.topRules].slice(0, 8).reverse()
  return {
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(10,20,40,0.95)',
      borderColor: 'rgba(34,211,238,0.4)',
      textStyle: { color: '#e6f2ff' },
      axisPointer: { type: 'shadow' },
      formatter(params) {
        const arr = Array.isArray(params) ? params : [params]
        const r = top[Number((arr[0] as { dataIndex?: number }).dataIndex ?? 0)]
        return r ? `${r.name}<br/>累计生效次数：<b>${r.firedTimes}</b><br/>近24h命中：${r.hits24}<br/>级别：${r.severity}（${r.ruleType === 'manual' ? '人工规则' : '衍生规则'}）` : ''
      },
    },
    grid: { left: 96, right: 42, top: 6, bottom: 6 },
    xAxis: {
      type: 'value',
      ...AXIS,
      axisLabel: { color: '#7d97bf', fontSize: 10 },
      splitLine: { lineStyle: { color: 'rgba(125,179,255,0.07)' } },
    },
    yAxis: { type: 'category', data: top.map((r) => (r.name.length > 8 ? `${r.name.slice(0, 8)}…` : r.name)), axisLabel: { color: '#b7cbe9', fontSize: 11 } },
    series: [
      {
        type: 'bar',
        barWidth: 10,
        data: top.map((r, i) => ({
          value: r.firedTimes,
          itemStyle: {
            color: {
              type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
              colorStops: [
                { offset: 0, color: '#0ea5e9' },
                { offset: 1, color: i === 0 ? '#22d3ee' : '#3b82f6' },
              ],
            },
            borderRadius: [0, 5, 5, 0],
          },
        })),
        label: { show: true, position: 'right', color: '#22d3ee', fontSize: 11, formatter: '{c}' },
      },
    ],
  }
})

const sevOption = computed<EChartsOption>(() => {
  const d = dash.value
  if (!d) return {}
  const data = d.sevDist.map((s) => ({ name: s.severity, value: s.count, itemStyle: { color: SEV_COLOR[s.severity] } }))
  return {
    tooltip: { trigger: 'item', backgroundColor: 'rgba(10,20,40,0.95)', borderColor: 'rgba(34,211,238,0.4)', textStyle: { color: '#e6f2ff' } },
    series: [
      {
        type: 'pie',
        radius: ['52%', '68%'],
        center: ['36%', '50%'],
        avoidLabelOverlap: true,
        itemStyle: { borderColor: '#0a1426', borderWidth: 2 },
        label: { show: false },
        emphasis: { label: { show: false } },
        data,
      },
    ],
  }
})

const decoderOption = computed<EChartsOption>(() => {
  const d = dash.value
  if (!d) return {}
  const top = d.decoderDist.slice(0, 5)
  const max = top[0]?.count ?? 1
  return {
    tooltip: { trigger: 'item', backgroundColor: 'rgba(10,20,40,0.95)', borderColor: 'rgba(34,211,238,0.4)', textStyle: { color: '#e6f2ff' } },
    grid: { left: 8, right: 64, top: 8, bottom: 8 },
    xAxis: { type: 'value', show: false, max },
    yAxis: { type: 'category', inverse: true, data: top.map((t) => t.name), axisLabel: { color: '#b7cbe9', fontSize: 11 }, axisTick: { show: false }, axisLine: { show: false } },
    series: [
      {
        type: 'bar',
        barWidth: 8,
        label: { show: true, position: 'right', color: '#9fb6d8', fontSize: 10, formatter: '{c}' },
        itemStyle: { color: '#38bdf8', borderRadius: 4 },
        data: top.map((t) => t.count),
      },
    ],
  }
})

/* ---------- 衍生展示数据 ---------- */
const hostRows = computed(() => dash.value?.hosts ?? [])
const sevLegend = computed(() => {
  const d = dash.value
  if (!d) return []
  return d.sevDist.map((s) => ({ sev: s.severity, color: SEV_COLOR[s.severity], count: s.count }))
})
</script>

<template>
  <div class="bigscreen-root">
    <div class="bigscreen-frame" :style="frameStyle">
      <!-- ===== 顶部标题栏 ===== -->
      <header class="bs-header">
        <div class="head-left">
          <div class="sys-badge">SCSSA · 自进化安全智能体</div>
          <div class="mode-tag">离线演示数据源</div>
        </div>
        <div class="head-center">
          <div class="main-title">实时安全监控态势大屏</div>
          <div class="main-sub">规则底座 · 模式认知 · 数据溯源 &nbsp;|&nbsp; L1 规则命中 → L2 模式认知 → L3 LLM 决策中枢</div>
        </div>
        <div class="head-right">
          <span class="live-dot" /><span class="live-txt">数据流在线</span>
          <div class="head-time">
            <div class="clock mono">{{ clock }}</div>
            <div class="date">{{ dateStr }}</div>
          </div>
          <el-button class="admin-btn" text @click="router.push('/admin/alerts')">进入后台 <el-icon><ArrowRight /></el-icon></el-button>
        </div>
      </header>

      <!-- ===== 指标卡 ===== -->
      <section class="metric-row">
        <div v-for="(m, i) in dash ? [
          { label: '今日告警', value: dash.overview.todayTotal, color: '#22d3ee', sub: '人工 + 衍生双规则池实时匹配' },
          { label: '高危及以上', value: dash.overview.critical + dash.overview.high, color: '#f87171', sub: `Critical ${dash.overview.critical} / High ${dash.overview.high}` },
          { label: 'AI 研判 TP / FP', value: dash.overview.tpToday, color: '#f59e0b', sub: `误报 ${dash.overview.fpToday} · 待复核 ${dash.overview.openReview}` },
          { label: '待人工审批 A3', value: dash.overview.pendingApprovals, color: '#fb923c', sub: '高风险动作必须人工确认（HITL）' },
          { label: '在线主机', value: `${dash.overview.hostsOnline}/${dash.overview.hostsTotal}`, color: '#34d399', sub: '含 Web / App / DB 等业务分组' },
          { label: '生效规则数', value: dash.overview.rulesActive, color: '#38bdf8', sub: `今日累计命中 ${dash.overview.firedToday} 次` },
        ] : []"
          :key="i"
          class="metric-card"
        >
          <div class="metric-label">{{ m.label }}</div>
          <div class="metric-value num" :style="{ color: m.color, textShadow: `0 0 18px ${m.color}55` }">{{ m.value }}</div>
          <div class="metric-sub">{{ m.sub }}</div>
        </div>
      </section>

      <!-- ===== 主面板区 ===== -->
      <section class="bs-main">
        <!-- 左列 -->
        <div class="col col-left">
          <div class="panel panel-fill">
            <div class="panel-title"><span class="bar" />命中规则 TOP（按累计生效次数）</div>
            <div class="panel-body chart"><EChart :option="rulesOption" /></div>
          </div>
          <div class="panel panel-40">
            <div class="panel-title"><span class="bar" />告警级别分布（近 24h）</div>
            <div class="panel-body sev-wrap">
              <div class="sev-chart">
                <EChart :option="sevOption" />
                <div v-if="dash" class="sev-center">
                  <div class="c-num num">{{ dash.overview.todayTotal }}</div>
                  <div class="c-sub">今日告警</div>
                </div>
              </div>
              <ul class="sev-legend">
                <li v-for="s in sevLegend" :key="s.sev">
                  <span class="dot" :style="{ background: s.color }" />
                  <span>{{ s.sev }}</span>
                  <span class="num">{{ s.count }}</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <!-- 中列 -->
        <div class="col col-center">
          <div class="panel panel-trend">
            <div class="panel-title"><span class="bar" />告警时间趋势（本时段 vs 上一时段）</div>
            <div class="panel-body chart"><EChart :option="trendOption" /></div>
          </div>
          <div class="panel panel-ticker">
            <div class="panel-title">
              <span class="bar" />
              实时告警流
              <span v-if="lastAlertId" class="live-badge">LIVE</span>
            </div>
            <div class="ticker-body">
              <table class="ticker-table">
                <thead>
                  <tr>
                    <th>时间</th><th>级别</th><th>主机</th><th>告警 / 命中规则</th><th>技术</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(a, idx) in liveAlerts" :key="a.id" :class="{ flash: a.id === lastAlertId }">
                    <td class="mono dim">{{ fmtHM(a.ts) }}</td>
                    <td>
                      <span class="sev-chip" :style="{ color: SEV_COLOR[a.severity], borderColor: SEV_COLOR[a.severity] + '66', background: SEV_COLOR[a.severity] + '14' }">{{ a.severity }}</span>
                    </td>
                    <td class="mono">{{ a.agent.name }}<div class="sub">{{ a.agent.ip }}</div></td>
                    <td>
                      <div class="ellipsis" style="max-width: 330px">{{ a.rule.description }}</div>
                      <div class="sub mono">#{{ a.rule.id }} · {{ a.hitRules[0]?.name ?? '-' }}</div>
                    </td>
                    <td class="mono dim" v-if="idx === 0">{{ (a.rule.mitreTechniques ?? []).join(', ') || '-' }}</td>
                    <td class="mono dim" v-else>{{ (a.rule.mitreTechniques ?? []).join(', ') || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- 右列 -->
        <div class="col col-right">
          <div class="panel panel-fill">
            <div class="panel-title"><span class="bar" />数据源 / 解码器 TOP（近 24h）</div>
            <div class="panel-body chart"><EChart :option="decoderOption" /></div>
          </div>
          <div class="panel panel-hosts">
            <div class="panel-title">
              <span class="bar" />主机在线状态
              <span class="host-count num">{{ dash?.overview.hostsOnline }}<i>/{{ dash?.overview.hostsTotal }}</i></span>
            </div>
            <div class="host-list">
              <div v-for="h in hostRows" :key="h.name" class="host-item">
                <span class="host-dot" :class="`st-${h.status}`" />
                <span class="host-name mono">{{ h.name }}</span>
                <span class="host-role">{{ h.role }}</span>
                <span class="host-ip mono dim">{{ h.ip }}</span>
                <span class="host-st dim" :class="`st-txt-${h.status}`">{{ h.status === 'online' ? '在线' : h.status === 'degraded' ? '降级' : '离线' }}</span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.bigscreen-root {
  position: fixed;
  inset: 0;
  overflow: hidden;
  background:
    radial-gradient(1600px 800px at 50% -10%, rgba(37, 99, 235, 0.16), transparent 55%),
    radial-gradient(900px 500px at 10% 110%, rgba(34, 211, 238, 0.07), transparent 60%),
    var(--bg-deep);
  display: flex;
  align-items: center;
  justify-content: center;
}
.bigscreen-frame {
  flex: none;
  transform-origin: center center;
  display: flex;
  flex-direction: column;
  padding: 14px 18px 16px;
  gap: 12px;
  box-sizing: border-box;
}

/* 顶栏 */
.bs-header {
  display: flex;
  align-items: center;
  height: 74px;
  padding: 0 6px;
}
.head-left {
  width: 420px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.sys-badge {
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 1px;
  padding: 6px 12px;
  border: 1px solid rgba(34, 211, 238, 0.4);
  background: linear-gradient(90deg, rgba(34, 211, 238, 0.12), rgba(59, 130, 246, 0.06));
  color: #a5f3fc;
  border-radius: 6px;
}
.mode-tag {
  font-size: 12px;
  color: var(--txt-dim);
  padding: 4px 10px;
  border: 1px dashed rgba(125, 179, 255, 0.3);
  border-radius: 12px;
  letter-spacing: 1px;
}
.head-center {
  flex: 1;
  text-align: center;
}
.main-title {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: 6px;
  background: linear-gradient(90deg, #67e8f9, #93c5fd, #67e8f9);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  text-shadow: 0 0 30px rgba(34, 211, 238, 0.25);
}
.main-sub {
  margin-top: 6px;
  font-size: 12px;
  color: var(--txt-dim);
  letter-spacing: 2px;
}
.head-right {
  width: 420px;
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 10px;
}
.live-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--ok);
  box-shadow: 0 0 10px var(--ok);
  animation: pulse 1.6s infinite;
}
.live-txt {
  color: var(--ok);
  font-size: 12px;
  letter-spacing: 1px;
}
.head-time {
  text-align: right;
  margin-right: 8px;
}
.clock {
  font-size: 24px;
  color: #e6f2ff;
  line-height: 1;
}
.date {
  font-size: 11px;
  color: var(--txt-dim);
  margin-top: 4px;
  letter-spacing: 1px;
}
.admin-btn {
  color: var(--txt);
  border: 1px solid var(--line-soft);
  height: 30px;
  border-radius: 6px;
  padding: 0 10px;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
}
.admin-btn:hover {
  color: var(--accent);
  border-color: var(--accent);
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}

/* 指标卡 */
.metric-row {
  display: flex;
  gap: 14px;
  height: 96px;
}
.metric-card {
  flex: 1;
  position: relative;
  background: linear-gradient(160deg, rgba(16, 33, 61, 0.75), rgba(9, 20, 38, 0.75));
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  overflow: hidden;
  padding: 12px 16px 8px;
  box-sizing: border-box;
}
.metric-card::after {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  height: 3px;
  width: 100%;
  background: linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.6), transparent);
}
.metric-label {
  font-size: 12px;
  color: var(--txt);
  letter-spacing: 1px;
}
.metric-value {
  margin-top: 2px;
  font-size: 34px;
  font-weight: 700;
  line-height: 1.1;
}
.metric-sub {
  margin-top: 4px;
  font-size: 11px;
  color: var(--txt-dim);
}

/* 主区三列 */
.bs-main {
  flex: 1;
  min-height: 0;
  display: flex;
  gap: 14px;
}
.col {
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-width: 0;
}
.col-left,
.col-right {
  width: 462px;
  flex: none;
}
.col-center {
  flex: 1;
}
.panel {
  background: linear-gradient(165deg, rgba(14, 28, 52, 0.86), rgba(8, 18, 36, 0.86));
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  min-height: 0;
  box-shadow: inset 0 0 30px rgba(34, 211, 238, 0.03);
}
.panel-fill {
  flex: 1.35;
}
.panel-40 {
  flex: 1;
}
.panel-trend {
  flex: 1.25;
}
.panel-ticker {
  flex: 1.15;
}
.panel-hosts {
  flex: 1;
}
.panel-title {
  flex: none;
  display: flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 14px;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: 0.5px;
  color: var(--txt-strong);
  border-bottom: 1px solid var(--line-soft);
  background: linear-gradient(90deg, rgba(34, 211, 238, 0.06), transparent);
}
.bar {
  width: 9px;
  height: 9px;
  border: 2px solid var(--accent);
  transform: rotate(45deg);
  box-shadow: 0 0 8px rgba(34, 211, 238, 0.7);
}
.panel-body {
  flex: 1;
  min-height: 0;
  padding: 8px;
  box-sizing: border-box;
}
.chart {
  height: calc(100% - 16px);
}
.host-count {
  margin-left: auto;
  font-size: 16px;
  color: var(--ok);
}
.host-count i {
  font-style: normal;
  color: var(--txt-dim);
  font-size: 12px;
}

/* 级别分布 */
.sev-wrap {
  display: flex;
  align-items: stretch;
  gap: 6px;
  height: 100%;
  box-sizing: border-box;
}
.sev-chart {
  position: relative;
  flex: none;
  width: 56%;
  min-width: 0;
  height: 100%;
}
.sev-chart > div:first-child {
  width: 100%;
  height: 100%;
}
.sev-center {
  position: absolute;
  left: 36%;
  top: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
  line-height: 1.1;
  pointer-events: none;
}
.sev-center .c-num {
  font-size: 30px;
  font-weight: 700;
  color: #e6f2ff;
  text-shadow: 0 0 14px rgba(34, 211, 238, 0.25);
}
.sev-center .c-sub {
  margin-top: 5px;
  font-size: 12px;
  color: #5f7ba6;
  letter-spacing: 2px;
}
.sev-legend {
  flex: 1;
  min-width: 0;
  list-style: none;
  margin: auto 0;
  padding: 0;
  align-self: center;
}
.sev-legend li {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--txt);
  padding: 5px 0;
}
.sev-legend .dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
}
.sev-legend .num {
  margin-left: auto;
  color: var(--txt-strong);
}

/* 实时告警流 */
.live-badge {
  margin-left: auto;
  font-size: 10px;
  color: var(--crit);
  border: 1px solid rgba(248, 113, 113, 0.5);
  border-radius: 4px;
  padding: 0 6px;
  letter-spacing: 1px;
  animation: pulse 1.4s infinite;
}
.ticker-body {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.ticker-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.ticker-table th {
  text-align: left;
  color: var(--txt-dim);
  font-weight: 500;
  font-size: 11px;
  padding: 6px 8px;
  border-bottom: 1px solid var(--line-soft);
  letter-spacing: 1px;
}
.ticker-table td {
  padding: 5px 8px;
  border-bottom: 1px solid rgba(125, 179, 255, 0.06);
  vertical-align: top;
}
.ticker-table tbody tr {
  animation: slideIn 0.35s ease;
}
@keyframes slideIn {
  from { opacity: 0; transform: translateY(-6px); }
  to { opacity: 1; transform: translateY(0); }
}
.ticker-table tr.flash {
  background: linear-gradient(90deg, rgba(34, 211, 238, 0.1), transparent);
}
.sev-chip {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  border: 1px solid;
  font-size: 11px;
}
.sub {
  font-size: 10px;
  color: var(--txt-dim);
  margin-top: 1px;
}

/* 主机列表 */
.host-list {
  flex: 1;
  overflow: auto;
  padding: 4px 12px 10px;
}
.host-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4.5px 0;
  border-bottom: 1px dashed rgba(125, 179, 255, 0.07);
  font-size: 12px;
}
.host-item:last-child {
  border-bottom: none;
}
.host-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: none;
}
.st-online {
  background: var(--ok);
  box-shadow: 0 0 6px var(--ok);
}
.st-offline {
  background: var(--crit);
}
.st-degraded {
  background: var(--warn);
  box-shadow: 0 0 6px var(--warn);
}
.host-name {
  color: var(--txt-strong);
}
.host-role {
  font-size: 10px;
  color: var(--accent);
  border: 1px solid rgba(34, 211, 238, 0.3);
  border-radius: 3px;
  padding: 0 4px;
}
.host-ip {
  font-size: 11px;
}
.host-st {
  margin-left: auto;
  font-size: 11px;
}
.st-txt-online {
  color: var(--ok);
}
.st-txt-degraded {
  color: var(--warn);
}
.st-txt-offline {
  color: var(--crit);
}
</style>
