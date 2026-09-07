<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { api, subscribeFeed } from '@/api'
import type { Alert, AlertSource, AlertStatus, Severity, VerdictClass } from '@/api/types'
import { fmtTime } from '@/utils/format'
import AlertDrawer from './AlertDrawer.vue'

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}

const filters = reactive<{
  keyword: string
  severity: Severity | ''
  verdict: VerdictClass | 'unknown' | ''
  source: AlertSource | ''
  status: AlertStatus | ''
}>({
  keyword: '',
  severity: '',
  verdict: '',
  source: '',
  status: '',
})

const rows = ref<Alert[]>([])
const total = ref(0)
const loading = ref(false)
const page = ref(1)
const size = ref(20)
const detailId = ref<string | null>(null)
const liveBadge = ref(false)
let unsub: (() => void) | undefined

async function load() {
  loading.value = true
  const res = await api.alerts({ ...filters, page: page.value, size: size.value })
  rows.value = res.items
  total.value = res.total
  loading.value = false
}

function search() {
  page.value = 1
  void load()
}

function reset() {
  filters.keyword = ''
  filters.severity = ''
  filters.verdict = ''
  filters.source = ''
  filters.status = ''
  search()
}

function openRow(a: Alert) {
  detailId.value = a.id
}

onMounted(async () => {
  await load()
  unsub = subscribeFeed((e) => {
    if (e.kind === 'alert') {
      liveBadge.value = true
      window.setTimeout(() => (liveBadge.value = false), 2600)
    }
  })
})

onBeforeUnmount(() => unsub?.())
</script>

<template>
  <div class="alerts-page">
    <!-- 筛选栏 -->
    <div class="toolbar panel">
      <el-input v-model="filters.keyword" placeholder="搜索：ID / 主机 / IP / 描述 / MITRE 技术…" clearable class="kw" @keyup.enter="search">
        <template #prefix><el-icon><Search /></el-icon></template>
      </el-input>
      <el-select v-model="filters.severity" placeholder="级别" clearable style="width: 120px">
        <el-option v-for="s in ['Low', 'Medium', 'High', 'Critical']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.verdict" placeholder="研判" clearable style="width: 130px">
        <el-option label="TP 威胁" value="TP" />
        <el-option label="FP 误报" value="FP" />
        <el-option label="未研判" value="unknown" />
      </el-select>
      <el-select v-model="filters.source" placeholder="来源" clearable style="width: 110px">
        <el-option v-for="s in ['wazuh', 'replay', 'eval']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.status" placeholder="状态" clearable style="width: 110px">
        <el-option label="处理中" value="open" />
        <el-option label="已复核" value="reviewed" />
        <el-option label="已忽略" value="dismissed" />
      </el-select>
      <el-button type="primary" @click="search">查询</el-button>
      <el-button @click="reset">重置</el-button>
      <el-button text @click="load"><el-icon :class="loading ? 'spin' : ''"><Refresh /></el-icon> 刷新</el-button>
    </div>

    <!-- 列表 -->
    <div class="panel table-panel">
      <div class="table-head">
        <span>告警记录</span>
        <span class="text-dim">共 {{ total }} 条</span>
        <span v-if="liveBadge" class="live-badge">有新告警推送</span>
      </div>
      <el-table v-loading="loading" :data="rows" @row-click="openRow" class="alert-table">
        <el-table-column label="时间" width="140">
          <template #default="{ row }"><span class="mono">{{ fmtTime(row.ts) }}</span></template>
        </el-table-column>
        <el-table-column label="级别" width="100">
          <template #default="{ row }">
            <span class="sev" :style="{ color: SEV_COLOR[row.severity as Severity], borderColor: SEV_COLOR[row.severity as Severity] + '88' }">{{ row.severity }}</span>
          </template>
        </el-table-column>
        <el-table-column label="主机" width="150">
          <template #default="{ row }">
            <div class="mono">{{ row.agent.name }}</div>
            <div class="sub mono">{{ row.agent.ip }}</div>
          </template>
        </el-table-column>
        <el-table-column label="告警描述" min-width="260">
          <template #default="{ row }">
            <div class="main ellipsis">{{ row.rule.description }}</div>
            <div class="sub mono">#{{ row.rule.id }} · {{ row.family }} · {{ row.decoder }}</div>
          </template>
        </el-table-column>
        <el-table-column label="MITRE" width="130">
          <template #default="{ row }">
            <el-tag v-for="t in row.rule.mitreTechniques.slice(0, 2)" :key="t" size="small" type="primary" class="tech">{{ t }}</el-tag>
            <span v-if="!row.rule.mitreTechniques.length" class="text-dim">-</span>
          </template>
        </el-table-column>
        <el-table-column label="AI 研判" width="150">
          <template #default="{ row }">
            <span v-if="row.verdict" :class="row.verdict.classification === 'TP' ? 'verd tp' : 'verd fp'">
              {{ row.verdict.classification }} · {{ row.verdict.priority }}
            </span>
            <span v-else class="verd pending">待研判</span>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="80">
          <template #default="{ row }"><span class="text-dim">{{ row.source }}</span></template>
        </el-table-column>
      </el-table>
      <div class="pager">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="size"
          :total="total"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next, jumper"
          background
          @current-change="load"
          @size-change="search"
        />
      </div>
    </div>

    <AlertDrawer v-model:alert-id="detailId" @reviewed="load" />
  </div>
</template>

<style scoped>
.alerts-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  flex-wrap: wrap;
}
.kw {
  width: 320px;
}
.table-panel {
  display: flex;
  flex-direction: column;
  padding-bottom: 8px;
  overflow: hidden;
}
.table-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px 6px;
  font-weight: 600;
  letter-spacing: 1px;
}
.live-badge {
  color: var(--crit);
  font-size: 11px;
  animation: pulse 1.2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.alert-table {
  cursor: pointer;
}
.alert-table .sub {
  font-size: 11px;
  color: var(--txt-dim);
  margin-top: 2px;
}
.sev {
  border: 1px solid;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}
.tech {
  margin-right: 4px;
}
.verd {
  font-size: 12px;
  padding: 1px 8px;
  border-radius: 4px;
}
.verd.tp {
  color: var(--crit);
  background: rgba(248, 113, 113, 0.14);
}
.verd.fp {
  color: var(--ok);
  background: rgba(52, 211, 153, 0.14);
}
.verd.pending {
  color: var(--warn);
  background: rgba(251, 191, 36, 0.12);
}
.pager {
  display: flex;
  justify-content: flex-end;
  padding: 10px 14px 0;
}
.spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
