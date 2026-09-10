<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import type { ActionRecord, Alert, AlertEvidence, Severity } from '@/api/types'
import { fmtTime } from '@/utils/format'

const props = defineProps<{ alertId: string | null }>()
const emit = defineEmits<{ (e: 'update:alertId', v: string | null): void; (e: 'reviewed'): void }>()

const router = useRouter()
const alert = ref<Alert | null>(null)
const actions = ref<ActionRecord[]>([])
const loading = ref(false)

/* 证据面板 & 复核写回 */
const evidence = ref<AlertEvidence | null>(null)
const evLoading = ref(false)
const revReason = ref('')
const revPrio = ref('Medium')
const revBy = ref('analyst')
const revBusy = ref(false)

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}

const open = computed({
  get: () => props.alertId !== null,
  set: (v: boolean) => emit('update:alertId', v ? props.alertId : null),
})

async function loadEvidence(id: string) {
  evLoading.value = true
  evidence.value = null
  try {
    evidence.value = await api.alertEvidence(id)
  } catch {
    evidence.value = null
  } finally {
    evLoading.value = false
  }
}

watch(
  () => props.alertId,
  async (id) => {
    if (!id) return
    loading.value = true
    alert.value = await api.alert(id)
    const all = await api.actions()
    actions.value = all.filter((a) => alert.value?.actionIds.includes(a.actionId))
    loading.value = false
    void loadEvidence(id)
  },
  { immediate: true },
)

async function review(cls: 'TP' | 'FP') {
  if (!alert.value || revBusy.value) return
  revBusy.value = true
  try {
    alert.value = await api.reviewAlert(alert.value.id, cls, {
      reason: revReason.value,
      priority: revPrio.value,
      by: revBy.value,
    })
    const fb = (alert.value as Alert & { feedback?: { fragmentId?: string } }).feedback
    if (fb?.fragmentId) ElMessage.success(`已复核 ${cls} · 经验已写回多层记忆（feedback 片段 ${fb.fragmentId}）`)
    else ElMessage.success(`已复核：${cls}`)
    emit('reviewed')
  } finally {
    revBusy.value = false
  }
}

function gotoApproval() {
  emit('update:alertId', null)
  router.push('/admin/approvals')
}
</script>

<template>
  <el-drawer v-model="open" :title="`告警详情 · ${alert?.id ?? ''}`" size="680px" destroy-on-close class="alert-drawer">
    <div v-if="loading" class="loading">加载中…</div>
    <div v-else-if="alert" class="drawer-body">
      <!-- 概要 -->
      <div class="summ">
        <span class="sev" :style="{ color: SEV_COLOR[alert.severity], borderColor: SEV_COLOR[alert.severity] }">{{ alert.severity }}</span>
        <span v-if="alert.verdict" :class="['verd', alert.verdict.classification === 'TP' ? 'verd-tp' : 'verd-fp']">
          {{ alert.verdict.classification }} · {{ alert.verdict.priority }}
        </span>
        <span v-else class="verd verd-pending">待研判</span>
        <span class="tag">{{ alert.status === 'reviewed' ? '已复核' : alert.status === 'dismissed' ? '已忽略' : '处理中' }}</span>
        <span class="text-dim">{{ alert.source.toUpperCase() }}</span>
      </div>
      <div class="grid2">
        <div><span class="k">时间</span><span class="v mono">{{ fmtTime(alert.ts) }}</span></div>
        <div><span class="k">主机</span><span class="v mono">{{ alert.agent.name }} ({{ alert.agent.ip }}) · {{ alert.agent.os }}</span></div>
        <div><span class="k">解码器</span><span class="v">{{ alert.decoder }}</span></div>
        <div><span class="k">行为族</span><span class="v">{{ alert.family }}</span></div>
      </div>

      <!-- 原始告警 -->
      <el-collapse>
        <el-collapse-item name="raw" title="原始告警（raw / full_log）">
          <pre class="raw mono">{{ alert.raw }}</pre>
        </el-collapse-item>
      </el-collapse>

      <!-- 头部规则信息 -->
      <h4 class="sec">源头规则（Wazuh / 采集端）</h4>
      <div class="card">
        <div class="grid2">
          <div><span class="k">Rule ID</span><span class="v mono">#{{ alert.rule.id }} · level {{ alert.rule.level }}</span></div>
          <div><span class="k">Groups</span><span class="v">{{ alert.rule.groups.join(', ') || '-' }}</span></div>
        </div>
        <div style="margin-top: 8px"><span class="k">描述</span><span class="v">{{ alert.rule.description }}</span></div>
        <div style="margin-top: 6px">
          <span class="k">MITRE</span>
          <template v-if="alert.rule.mitreTechniques.length">
            <el-tag v-for="t in alert.rule.mitreTechniques" :key="t" size="small" class="mitre-tag" type="primary">{{ t }}</el-tag>
            <span class="text-dim" style="margin-left: 6px">{{ alert.rule.mitreTactics.join(' / ') }}</span>
          </template>
          <span v-else class="v">-</span>
        </div>
      </div>

      <!-- 命中规则（双规则池） -->
      <h4 class="sec">命中规则（人工/衍生双池，含生效次数）</h4>
      <el-table :data="alert.hitRules" size="small" class="mini-table">
        <el-table-column label="规则" prop="name" min-width="160" show-overflow-tooltip />
        <el-table-column label="类型" width="86">
          <template #default="{ row }">
            <el-tag :type="row.ruleType === 'manual' ? 'success' : 'warning'" size="small">{{ row.ruleType === 'manual' ? '人工' : '衍生' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="级别" width="80">
          <template #default="{ row }"><span :style="{ color: SEV_COLOR[row.severity as Severity] }">{{ row.severity }}</span></template>
        </el-table-column>
        <el-table-column label="生效次数" width="100">
          <template #default="{ row }"><span class="num mono">{{ row.firedTimes }}</span></template>
        </el-table-column>
      </el-table>

      <!-- LLM 研判 -->
      <h4 class="sec">LLM 研判（三级联动决策中枢）</h4>
      <div v-if="alert.verdict" class="verdict-box" :class="alert.verdict.classification === 'TP' ? 'box-tp' : 'box-fp'">
        <div class="verdict-head">
          <b>{{ alert.verdict.classification === 'TP' ? '确认为威胁' : '判定误报' }}</b>
          <span class="text-dim">优先级 {{ alert.verdict.priority }} · 模型 {{ alert.verdict.model }}</span>
        </div>
        <p>{{ alert.verdict.justification }}</p>
      </div>
      <div v-else class="verdict-box box-pending">
        <p>该告警暂未进入 LLM 研判（低风险 / 规则直判归档），如需可人工复核。</p>
      </div>

      <!-- 研判证据依据（实时检索 · 防泄漏） -->
      <h4 class="sec">研判证据依据（记忆 + 模式 + ATT&CK，仅引用历史）</h4>
      <div v-if="evLoading" class="text-dim" style="font-size: 12px">检索历史相似经验…</div>
      <div v-else-if="evidence" class="ev-card">
        <div class="ev-head">
          <el-tag size="small" type="primary" effect="plain">相似片段 {{ evidence.counts.frags }}</el-tag>
          <el-tag size="small" type="warning" effect="plain">可疑模式 {{ evidence.counts.patterns }}</el-tag>
          <el-tag size="small" type="danger" effect="plain">图谱行 {{ evidence.counts.kb }}</el-tag>
          <span class="text-dim ev-guard">{{ evidence.leakageGuard }}</span>
        </div>
        <pre v-if="evidence.evidenceText" class="ev-pre mono">{{ evidence.evidenceText }}</pre>
        <div v-else class="text-dim">该告警之前的相似经验/模式为空（seq 太靠前或为全新行为）。</div>
      </div>
      <div v-else class="text-dim">证据检索不可用。</div>

      <!-- 动作记录 -->
      <h4 class="sec">动作记录（分级自主行动 A0–A3）</h4>
      <el-table v-if="actions.length" :data="actions" size="small" class="mini-table">
        <el-table-column label="动作" prop="name" min-width="150" />
        <el-table-column label="级别" width="60">
          <template #default="{ row }"><el-tag size="small" type="danger">{{ row.tier }}</el-tag></template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <span :class="row.status === 'done' ? 'st-ok' : row.status === 'pending' ? 'st-pend' : row.status === 'denied' ? 'st-no' : 'st-fail'">{{ row.status }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结果" prop="result" min-width="200" show-overflow-tooltip />
      </el-table>
      <el-empty v-else description="无动作记录（仅通知）" :image-size="60" />

      <!-- 关联记忆 -->
      <h4 class="sec">关联可疑模式 / 历史片段（分层记忆溯源）</h4>
      <div v-if="alert.relatedPatterns.length || alert.relatedFragments.length" class="rel-box">
        <div v-for="p in alert.relatedPatterns" :key="p.patternId" class="rel-item">
          <span class="rel-tag pat">模式</span>
          <span>{{ p.title }}</span>
          <span class="rel-meta mono text-dim">{{ p.patternId }} · 命中 {{ p.hits }} · 置信 {{ (p.confidence * 100).toFixed(0) }}%</span>
        </div>
        <div v-for="f in alert.relatedFragments.slice(0, 4)" :key="f.fragmentId" class="rel-item">
          <span class="rel-tag frag">片段</span>
          <span class="ellipsis" style="max-width: 340px">{{ f.summary }}</span>
          <span class="rel-meta mono text-dim">{{ f.fragmentId }}</span>
        </div>
      </div>
      <div v-else class="text-dim">无关联模式/片段</div>

      <!-- 底部操作 -->
      <div class="rev-box">
        <el-input v-model="revReason" size="small" placeholder="复核理由（将随 feedback 片段写回多层记忆）" clearable />
        <div class="rev-meta">
          <el-select v-model="revPrio" size="small" style="width: 120px">
            <el-option v-for="s in ['Low', 'Medium', 'High', 'Critical']" :key="s" :label="s" :value="s" />
          </el-select>
          <el-input v-model="revBy" size="small" style="width: 130px" placeholder="复核人" />
        </div>
      </div>
      <div class="foot-actions">
        <el-button :disabled="revBusy || alert.verdict?.classification === 'FP'" @click="review('FP')">复核：误报（回传降噪）</el-button>
        <el-button type="danger" plain :disabled="revBusy || alert.verdict?.classification === 'TP'" @click="review('TP')">复核：确认威胁</el-button>
        <el-button v-if="actions.some((a) => a.tier === 'A3' && a.status === 'pending')" type="primary" @click="gotoApproval">
          去审批 A3 动作
        </el-button>
      </div>
    </div>
  </el-drawer>
</template>

<style scoped>
.loading {
  padding: 60px;
  text-align: center;
  color: var(--txt-dim);
}
.summ {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.sev {
  padding: 2px 10px;
  border: 1px solid;
  border-radius: 4px;
  font-weight: 600;
}
.verd {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
}
.verd-tp {
  background: rgba(248, 113, 113, 0.15);
  color: var(--crit);
}
.verd-fp {
  background: rgba(52, 211, 153, 0.15);
  color: var(--ok);
}
.verd-pending {
  background: rgba(251, 191, 36, 0.12);
  color: var(--warn);
}
.tag {
  font-size: 11px;
  color: var(--txt-dim);
  border: 1px dashed var(--line);
  border-radius: 3px;
  padding: 1px 6px;
}
.grid2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px 16px;
  margin: 6px 0 10px;
}
.grid2 .k,
.k {
  color: var(--txt-dim);
  font-size: 12px;
  margin-right: 8px;
}
.grid2 .v {
  color: var(--txt-strong);
}
.raw {
  background: rgba(4, 10, 22, 0.85);
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  padding: 10px;
  font-size: 11.5px;
  color: #b7cbe9;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}
.sec {
  margin: 16px 0 8px;
  font-size: 13px;
  color: var(--accent);
  font-weight: 600;
  letter-spacing: 1px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.sec::before {
  content: '';
  width: 3px;
  height: 14px;
  background: var(--accent);
  border-radius: 2px;
}
.card {
  background: rgba(13, 26, 51, 0.6);
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  padding: 10px 12px;
}
.mitre-tag {
  margin-right: 6px;
}
.mini-table :deep(.el-table__header th) {
  background: rgba(18, 34, 68, 0.7);
  color: var(--txt);
  font-size: 12px;
}
.verdict-box {
  border-radius: 6px;
  padding: 10px 12px;
  font-size: 13px;
}
.box-tp {
  background: rgba(248, 113, 113, 0.08);
  border: 1px solid rgba(248, 113, 113, 0.3);
}
.box-fp {
  background: rgba(52, 211, 153, 0.08);
  border: 1px solid rgba(52, 211, 153, 0.3);
}
.box-pending {
  background: rgba(56, 189, 248, 0.06);
  border: 1px dashed rgba(56, 189, 248, 0.3);
}
.verdict-head {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
}
.verdict-box p {
  margin: 0;
  color: var(--txt);
  line-height: 1.7;
}
.rel-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  padding: 6px 0;
  border-bottom: 1px dashed rgba(125, 179, 255, 0.08);
}
.rel-tag {
  flex: none;
  font-size: 11px;
  border-radius: 3px;
  padding: 0 5px;
}
.rel-tag.pat {
  color: var(--accent);
  border: 1px solid rgba(34, 211, 238, 0.4);
}
.rel-tag.frag {
  color: #a78bfa;
  border: 1px solid rgba(167, 139, 250, 0.4);
}
.rel-meta {
  margin-left: auto;
  font-size: 11px;
}
.foot-actions {
  margin-top: 10px;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
.st-ok { color: var(--ok); }
.st-pend { color: var(--warn); }
.st-no { color: var(--txt-dim); }
.st-fail { color: var(--crit); }
.ev-card {
  border: 1px solid var(--line-soft);
  border-left: 2px solid rgba(34, 211, 238, 0.45);
  border-radius: 6px;
  padding: 8px 10px;
  background: rgba(4, 10, 22, 0.35);
}
.ev-head {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.ev-guard {
  margin-left: auto;
  font-size: 11px;
}
.ev-pre {
  margin: 0;
  font-size: 11.5px;
  line-height: 1.7;
  color: #b7cbe9;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 34vh;
  overflow: auto;
}
.rev-box {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 18px;
  border-top: 1px dashed var(--line);
  padding-top: 12px;
}
.rev-meta {
  display: flex;
  justify-content: flex-end;
  gap: 6px;
}
</style>
