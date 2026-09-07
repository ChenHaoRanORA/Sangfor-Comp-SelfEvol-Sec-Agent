<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { User } from '@element-plus/icons-vue'
import { api, subscribeFeed } from '@/api'
import type { ActionRecord, Alert, Severity } from '@/api/types'
import { fmtTime } from '@/utils/format'

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}

interface Row {
  ac: ActionRecord
  al: Alert | null
}
const pending = ref<Row[]>([])
const history = ref<Row[]>([])
const loading = ref(false)
const approver = ref('安全员-陈工')

const pendingCount = computed(() => pending.value.length)

async function load() {
  loading.value = true
  const all = await api.actions()
  const pend = all.filter((a) => a.status === 'pending')
  const hist = all.filter((a) => a.status !== 'pending').slice(0, 30)
  pending.value = await resolveRows(pend)
  history.value = await resolveRows(hist)
  loading.value = false
}

async function resolveRows(list: ActionRecord[]): Promise<Row[]> {
  return Promise.all(
    list.map(async (ac) => {
      const al = await api.alert(ac.alertId)
      return { ac, al }
    }),
  )
}

async function decide(r: Row, approved: boolean) {
  await api.decide(r.ac.actionId, approved, approver.value)
  ElMessage.success(approved ? `已批准：${r.ac.name}` : `已拒绝：${r.ac.name}`)
  await load()
}

let unsub: (() => void) | undefined
onMounted(async () => {
  await load()
  unsub = subscribeFeed((e) => {
    if (e.kind === 'approval') void load()
  })
})
onBeforeUnmount(() => unsub?.())
</script>

<template>
  <div class="appr-page">
    <!-- 头部概览 -->
    <div class="head-bar panel">
      <div class="intro">
        <div class="title">A3 处置动作人工确认（HITL）</div>
        <div class="sub text-dim">规则触发 A3 级处置动作时流程在此挂起，必须人工批准后才会下发执行；全程写审计。</div>
      </div>
      <div class="stat">
        <span class="big num" :style="{ color: pendingCount ? 'var(--crit)' : 'var(--ok)' }">{{ pendingCount }}</span>
        <span class="label">待审批</span>
      </div>
      <el-input v-model="approver" style="width: 170px" placeholder="审批人">
        <template #prefix><el-icon><User /></el-icon></template>
      </el-input>
    </div>

    <el-tabs class="panel tabs-panel" v-loading="loading">
      <!-- 待审批队列 -->
      <el-tab-pane :label="`待审批队列 (${pendingCount})`" name="queue">
        <el-empty v-if="!pendingCount" description="暂无待审批的 A3 动作，当前策略运行平稳" :image-size="90" />
        <div v-for="r in pending" :key="r.ac.actionId" class="queue-item">
          <div class="q-left">
            <div class="q-top">
              <el-tag size="small" type="danger" effect="dark">A3 需人工确认</el-tag>
              <span class="q-name">{{ r.ac.name }}</span>
              <span class="q-time mono text-dim">{{ fmtTime(r.ac.ts) }}</span>
            </div>
            <div class="q-desc">
              <template v-if="r.al">
                <span class="sev" :style="{ color: SEV_COLOR[r.al.severity], borderColor: SEV_COLOR[r.al.severity] }">{{ r.al.severity }}</span>
                <span class="ellipsis" style="max-width: 460px">{{ r.al.rule.description }}</span>
                <span class="mono text-dim">#{{ r.al.rule.id }}</span>
              </template>
              <span v-else class="mono text-dim">{{ r.ac.alertId }}</span>
            </div>
            <div v-if="r.al" class="q-meta mono text-dim">
              {{ r.al.id }} · {{ r.al.agent.name }} ({{ r.al.agent.ip }}) · 命中规则 {{ r.ac.ruleId }}
              <template v-if="r.al.hitRules.length"> · 级别 {{ r.al.severity }}</template>
            </div>
          </div>
          <div class="q-actions">
            <el-button type="danger" plain @click="decide(r, true)">批准执行</el-button>
            <el-button @click="decide(r, false)">拒绝</el-button>
          </div>
        </div>
      </el-tab-pane>

      <!-- 执行记录 -->
      <el-tab-pane label="执行记录（审计）" name="history">
        <el-table :data="history" class="hist-table">
          <el-table-column label="时间" width="150">
            <template #default="{ row }"><span class="mono">{{ fmtTime(row.ac.ts) }}</span></template>
          </el-table-column>
          <el-table-column label="动作" min-width="180">
            <template #default="{ row }">
              <span class="num">{{ row.ac.actionId }}</span>
              <div class="h-sub">{{ row.ac.name }}</div>
            </template>
          </el-table-column>
          <el-table-column label="级别" width="80">
            <template #default="{ row }">
              <el-tag size="small" :type="row.ac.tier === 'A3' ? 'danger' : row.ac.tier === 'A1' ? 'success' : 'warning'">{{ row.ac.tier }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="关联告警" min-width="200">
            <template #default="{ row }">
              <span v-if="row.al" class="ellipsis" style="display: inline-block; max-width: 260px">{{ row.al.rule.description }}</span>
              <span v-else class="mono text-dim">{{ row.ac.alertId }}</span>
            </template>
          </el-table-column>
          <el-table-column label="审批人" width="110">
            <template #default="{ row }"><span class="text-dim">{{ row.ac.approvedBy || '-' }}</span></template>
          </el-table-column>
          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <span :class="['st', `st-${row.ac.status}`]">{{ row.ac.status }}</span>
            </template>
          </el-table-column>
          <el-table-column label="结果" min-width="220">
            <template #default="{ row }"><span class="text-dim">{{ row.ac.result || '-' }}</span></template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.appr-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.head-bar {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 14px 18px;
}
.intro {
  flex: 1;
}
.intro .title {
  font-size: 16px;
  font-weight: 700;
}
.intro .sub {
  font-size: 12px;
  margin-top: 4px;
}
.stat {
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.stat .big {
  font-size: 30px;
  font-weight: 700;
}
.stat .label {
  color: var(--txt-dim);
}
.tabs-panel {
  padding: 4px 12px 12px;
}
.queue-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 8px;
  border-bottom: 1px dashed rgba(125, 179, 255, 0.12);
  background: linear-gradient(90deg, rgba(248, 113, 113, 0.04), transparent);
}
.queue-item:hover {
  background: linear-gradient(90deg, rgba(248, 113, 113, 0.09), transparent);
}
.q-left {
  flex: 1;
  min-width: 0;
}
.q-top {
  display: flex;
  align-items: center;
  gap: 10px;
}
.q-name {
  font-size: 15px;
  font-weight: 600;
}
.q-time {
  margin-left: auto;
  font-size: 12px;
}
.q-desc {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 6px 0 4px;
  font-size: 13px;
}
.sev {
  padding: 1px 8px;
  border: 1px solid;
  border-radius: 4px;
  font-size: 11px;
}
.q-meta {
  font-size: 11px;
}
.q-actions {
  flex: none;
  display: flex;
  gap: 8px;
}
.h-sub {
  font-size: 11px;
  color: var(--txt-dim);
}
.st {
  font-size: 12px;
}
.st-done {
  color: var(--ok);
}
.st-denied {
  color: var(--txt-dim);
}
.st-failed {
  color: var(--crit);
}
.st-pending {
  color: var(--warn);
}
</style>
