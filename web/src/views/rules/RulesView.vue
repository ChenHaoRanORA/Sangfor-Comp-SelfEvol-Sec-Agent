<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ChatLineRound, Plus } from '@element-plus/icons-vue'
import { api, subscribeFeed } from '@/api'
import type { NlRuleDraft, RuleItem, Severity, Tier } from '@/api/types'
import { fmtAgo, fmtTime } from '@/utils/format'

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}
const router = useRouter()

/* ---------- 列表 ---------- */
const tab = ref<'manual' | 'derived'>('manual')
const manualRules = ref<RuleItem[]>([])
const derivedRules = ref<RuleItem[]>([])
const loading = ref(false)
const autoEvolve = ref(true)
const highlightId = ref('')
const knownDerived = new Set<string>()

async function load(t?: string) {
  if (t === 'manual' || tab.value === 'manual') manualRules.value = await api.rules('manual')
  if (t === 'derived' || tab.value === 'derived') {
    const before = new Set(knownDerived)
    const list = await api.rules('derived')
    derivedRules.value = list
    for (const r of list) {
      if (!knownDerived.has(r.ruleId)) {
        knownDerived.add(r.ruleId)
        if (before.size > 0 && autoEvolve.value) {
          highlightId.value = r.ruleId
          ElMessage.success({ message: `系统自动生成衍生规则：${r.name}（来自 ${r.sourcePatternId}）`, duration: 4500 })
        }
      }
    }
  }
}

async function toggleEnable(r: RuleItem, on: boolean) {
  await api.toggleRule(r.ruleId, on)
  ElMessage.success(on ? `已启用 ${r.name}` : `已停用 ${r.name}`)
  await load()
}

async function toggleFrozen(r: RuleItem, frozen: boolean) {
  await api.toggleDerivedFrozen(r.ruleId, frozen)
  ElMessage.success(frozen ? `${r.name} 已冻结，系统不再自动演化` : `${r.name} 已解冻`)
  await load()
}

async function toggleAuto() {
  const res = await api.toggleEvolution(autoEvolve.value)
  autoEvolve.value = res.on
  ElMessage.success(res.on ? '自动演化总开关：开启（衍生规则可自动增删改，全部有审计）' : '自动演化总开关：已关闭（衍生规则库冻结）')
}

/* ---------- 编辑 ---------- */
interface EditForm {
  name: string
  description: string
  severity: Severity
  expr: string
  tier: Tier
  allow: string[]
}
const editVisible = ref(false)
const editForm = reactive<EditForm>({ name: '', description: '', severity: 'Medium', expr: '', tier: 'A1', allow: [] })
const editing = ref<RuleItem | null>(null)
const ALLOW_OPTIONS = [
  { label: '取证快照 snapshot', value: 'snapshot' },
  { label: '图谱查询 query', value: 'query' },
  { label: '告警抑制 suppress', value: 'suppress' },
  { label: '封禁IP block_ip', value: 'block_ip' },
  { label: '主机隔离 isolate', value: 'isolate' },
]

function openEdit(r: RuleItem) {
  editing.value = r
  editForm.name = r.name
  editForm.description = r.description
  editForm.severity = r.severity
  editForm.expr = r.expression
  editForm.tier = r.actionPolicy.maxTier
  editForm.allow = [...r.actionPolicy.allow]
  editVisible.value = true
}

async function saveEdit() {
  if (!editing.value) return
  await api.updateRule(editing.value.ruleId, { ...editForm })
  ElMessage.success('规则已更新（人工权威，已记审计）')
  editVisible.value = false
  await load()
}

async function removeRule(r: RuleItem) {
  await ElMessageBox.confirm(`确认删除人工规则「${r.name}」？该操作仅人工可执行并留存审计。`, '删除确认', { type: 'warning' })
  await api.deleteRule(r.ruleId)
  ElMessage.success('已删除')
  await load()
}

/* ---------- 标准表单创建 ---------- */
const createVisible = ref(false)
const createForm = reactive<EditForm>({ name: '', description: '', severity: 'Medium', expr: '', tier: 'A1', allow: [] })
async function submitCreate() {
  if (!createForm.name.trim()) return ElMessage.warning('请填写规则名称')
  await api.createRuleFromNlRaw({
    name: createForm.name,
    description: createForm.description || createForm.name,
    severity: createForm.severity,
    expr: createForm.expr || '{"field":"rule.level","op":"gte","value":8}',
    tier: createForm.tier,
    allow: createForm.allow,
  })
  ElMessage.success('人工规则创建成功')
  createVisible.value = false
  Object.assign(createForm, { name: '', description: '', severity: 'Medium', expr: '', tier: 'A1', allow: [] })
  await load()
}

/* ---------- NL 向导 ---------- */
const nlVisible = ref(false)
const nlText = ref('')
const nlCompiling = ref(false)
const draft = ref<NlRuleDraft | null>(null)
const SUGGESTS = [
  '监控 sshd 连续登录失败超过 5 次，判为爆破，自动取证并通知',
  '当 suricata/ids 报告 webshell 访问时，直接封禁来源 IP 并隔离主机',
  'sysmon 出现 mshta/powershell 编码执行，采集快照并抑制同类 30 分钟',
  'auditd 新增用户或修改 sudoers 属于高权限变更，需要人工确认处置',
]

async function compileNl() {
  if (!nlText.value.trim()) return
  nlCompiling.value = true
  draft.value = await api.nlCompile(nlText.value)
  nlCompiling.value = false
}

async function confirmCreate() {
  if (!draft.value) return
  await api.createRuleFromNl(draft.value)
  ElMessage.success('自然语言规则已生成并通过样例校验，人工规则库已更新')
  nlVisible.value = false
  nlText.value = ''
  draft.value = null
  await load()
}

/* ---------- 审计抽屉 ---------- */
const auditVisible = ref(false)
const auditRule = ref<RuleItem | null>(null)
function openAudit(r: RuleItem) {
  auditRule.value = r
  auditVisible.value = true
}

/* ---------- 溯源抽屉（衍生规则 → 来源模式 → 证据片段） ---------- */
interface FragLite { fragmentId: string; summary: string; host?: string; ts?: number; classification?: string }
interface RuleTrace {
  rule?: RuleItem
  note?: string
  pattern: {
    patternId: string
    dataset?: string
    title?: string
    description?: string
    kind?: string
    confidence?: number
    hits?: number
    ruleIds?: string[]
    mitreTechniques?: string[]
    mitreTactics?: string[]
    supportingFragments?: FragLite[]
  } | null
}
const traceVisible = ref(false)
const traceLoading = ref(false)
const trace = ref<RuleTrace | null>(null)
async function openTrace(r: RuleItem) {
  trace.value = null
  traceVisible.value = true
  traceLoading.value = true
  try {
    trace.value = await api.ruleTrace(r.ruleId)
  } finally {
    traceLoading.value = false
  }
}

/* ---------- 轮询：演示自动演化可见性 ---------- */
let poll: number | undefined
let unsub: (() => void) | undefined

onMounted(async () => {
  autoEvolve.value = (await api.evolveEnabled()).on
  await load('manual')
  await load('derived')
  poll = window.setInterval(() => void load(), 12_000)
  unsub = subscribeFeed((e) => {
    if (e.kind === 'rule-update' && tab.value === 'derived') void load()
  })
})
onBeforeUnmount(() => {
  if (poll) window.clearInterval(poll)
  unsub?.()
})
</script>

<template>
  <div class="rules-page">
    <!-- 概览条 -->
    <div class="bar panel">
      <div class="bar-item">
        <span class="k">人工规则</span>
        <span class="v num">{{ manualRules.length }}</span>
        <span class="text-dim">仅人工可增删改</span>
      </div>
      <div class="bar-item">
        <span class="k">衍生规则</span>
        <span class="v num">{{ derivedRules.length }}</span>
        <span class="text-dim">系统自动 CRUD</span>
      </div>
      <div class="bar-item">
        <span class="k">自动演化</span>
        <el-switch v-model="autoEvolve" @change="toggleAuto" />
        <span class="text-dim" style="margin-left: 6px">{{ autoEvolve ? '开（每次变更留审计）' : '关（库冻结）' }}</span>
      </div>
      <div class="bar-spacer" />
      <el-button type="warning" plain @click="router.push('/admin/suggestions')">
        规则建议（人工拍板升格 / 拒绝）
      </el-button>
      <el-button type="primary" plain @click="nlVisible = true">
        <el-icon style="margin-right: 4px"><ChatLineRound /></el-icon>NL 自然语言创建
      </el-button>
      <el-button type="primary" @click="createVisible = true">
        <el-icon style="margin-right: 4px"><Plus /></el-icon>手动新建
      </el-button>
    </div>

    <!-- Tab 列表 -->
    <div class="panel list-panel">
      <el-tabs v-model="tab" @tab-change="load">
        <el-tab-pane label="人工规则" name="manual">
          <el-table v-loading="loading && tab === 'manual'" :data="manualRules" class="rule-table">
            <el-table-column label="规则" min-width="220">
              <template #default="{ row }">
                <div class="rname">{{ row.name }}</div>
                <div class="sub ellipsis" style="max-width: 380px">{{ row.description }}</div>
              </template>
            </el-table-column>
            <el-table-column label="级别" width="90">
              <template #default="{ row }"><span :style="{ color: SEV_COLOR[row.severity as Severity] }">{{ row.severity }}</span></template>
            </el-table-column>
            <el-table-column label="动作策略" width="130">
              <template #default="{ row }">
                <el-tag size="small" :type="row.actionPolicy.maxTier === 'A3' ? 'danger' : row.actionPolicy.maxTier === 'A2' ? 'warning' : 'success'">
                  {{ row.actionPolicy.maxTier }} {{ row.actionPolicy.allow.join('/') || '通知' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="生效次数" width="100">
              <template #default="{ row }"><b class="num" style="color: var(--accent)">{{ row.firedTimes }}</b></template>
            </el-table-column>
            <el-table-column label="最近触发" width="110">
              <template #default="{ row }">
                <span v-if="row.lastTriggeredAt" class="mono text-dim">{{ fmtAgo(row.lastTriggeredAt) }}</span>
                <span v-else class="text-dim">-</span>
              </template>
            </el-table-column>
            <el-table-column label="启用" width="80">
              <template #default="{ row }">
                <el-switch :model-value="row.enabled" @change="(v: string | number | boolean) => toggleEnable(row, Boolean(v))" />
              </template>
            </el-table-column>
            <el-table-column label="所有者 / 版本" width="130">
              <template #default="{ row }"><span class="text-dim">{{ row.owner }}</span><span class="mono sub">v{{ row.revision }}</span></template>
            </el-table-column>
            <el-table-column label="操作" width="190" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" size="small" @click="openEdit(row)">编辑</el-button>
                <el-button link size="small" @click="openAudit(row)">审计</el-button>
                <el-button link type="danger" size="small" @click="removeRule(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="衍生规则（自动演化）" name="derived">
          <el-table v-loading="loading && tab === 'derived'" :data="derivedRules" class="rule-table">
            <el-table-column label="规则" min-width="230">
              <template #default="{ row }">
                <div class="rname">{{ row.name }}</div>
                <div class="sub ellipsis" style="max-width: 400px">{{ row.description }}</div>
              </template>
            </el-table-column>
            <el-table-column label="来源模式" width="140">
              <template #default="{ row }">
                <el-tag size="small" type="warning" effect="plain">{{ row.sourcePatternId || '-' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="置信度" width="120">
              <template #default="{ row }">
                <el-progress
                  :percentage="Math.round(((row.confidence ?? 0.7) * 100))"
                  :stroke-width="8"
                  :color="(row.confidence ?? 0.7) >= 0.85 ? '#f87171' : '#fbbf24'"
                />
              </template>
            </el-table-column>
            <el-table-column label="级别" width="80">
              <template #default="{ row }"><span :style="{ color: SEV_COLOR[row.severity as Severity] }">{{ row.severity }}</span></template>
            </el-table-column>
            <el-table-column label="生效次数" width="90">
              <template #default="{ row }"><b class="num" style="color: var(--accent)">{{ row.firedTimes }}</b></template>
            </el-table-column>
            <el-table-column label="状态" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="row.state === 'paused' ? 'info' : 'success'">{{ row.state }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="人工冻结" width="90">
              <template #default="{ row }">
                <el-switch :model-value="row.state === 'paused'" @change="(v: string | number | boolean) => toggleFrozen(row, Boolean(v))" />
              </template>
            </el-table-column>
            <el-table-column label="最近变更" width="110">
              <template #default="{ row }"><span class="mono text-dim">{{ fmtAgo(row.updatedAt) }}</span></template>
            </el-table-column>
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button link type="primary" size="small" @click="openTrace(row)">溯源</el-button>
                <el-button link size="small" @click="openAudit(row)">审计</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </div>

    <!-- 编辑弹窗 -->
    <el-dialog v-model="editVisible" title="编辑人工规则" width="620px">
      <el-form label-width="90px">
        <el-form-item label="名称"><el-input v-model="editForm.name" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="editForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="级别">
          <el-select v-model="editForm.severity" style="width: 160px">
            <el-option v-for="s in ['Low', 'Medium', 'High', 'Critical']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="表达式"><el-input v-model="editForm.expr" type="textarea" :rows="3" class="mono" /></el-form-item>
        <el-form-item label="最大动作级">
          <el-select v-model="editForm.tier" style="width: 160px">
            <el-option v-for="t in ['A0', 'A1', 'A2', 'A3']" :key="t" :label="`${t} ${t === 'A0' ? '仅通知' : t === 'A1' ? '只读' : t === 'A2' ? '受限' : '处置(须确认)'}`" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="允许动作">
          <el-checkbox-group v-model="editForm.allow">
            <el-checkbox v-for="o in ALLOW_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" @click="saveEdit">保存（记审计）</el-button>
      </template>
    </el-dialog>

    <!-- 手动新建弹窗 -->
    <el-dialog v-model="createVisible" title="手动新建人工规则" width="620px">
      <el-form label-width="90px">
        <el-form-item label="名称"><el-input v-model="createForm.name" placeholder="如：Nginx 异常 UA 封禁" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="createForm.description" type="textarea" :rows="2" /></el-form-item>
        <el-form-item label="级别">
          <el-select v-model="createForm.severity" style="width: 160px">
            <el-option v-for="s in ['Low', 'Medium', 'High', 'Critical']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item label="表达式"><el-input v-model="createForm.expr" type="textarea" :rows="3" placeholder='{"field":"rule.id","op":"in","value":[5501,5710]}' class="mono" /></el-form-item>
        <el-form-item label="最大动作级">
          <el-select v-model="createForm.tier" style="width: 160px">
            <el-option v-for="t in ['A0', 'A1', 'A2', 'A3']" :key="t" :label="t" :value="t" />
          </el-select>
        </el-form-item>
        <el-form-item label="允许动作">
          <el-checkbox-group v-model="createForm.allow">
            <el-checkbox v-for="o in ALLOW_OPTIONS" :key="o.value" :value="o.value">{{ o.label }}</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- NL 向导 -->
    <el-dialog v-model="nlVisible" title="自然语言创建人工规则（LLM 编译 → 人工确认）" width="760px" top="6vh">
      <div class="nl-step">
        <div class="nl-hint">1. 用一句话描述你想防护的行为（支持口语，越具体越好）：</div>
        <el-input v-model="nlText" type="textarea" :rows="3" placeholder="例：当 auditd 出现新增用户或 sudoers 变更时，判为高权限后门风险，需要封禁来源并人工审批" />
        <div class="suggests">
          <el-tag v-for="s in SUGGESTS" :key="s" class="suggest" effect="plain" @click="nlText = s">{{ s }}</el-tag>
        </div>
        <div style="margin-top: 10px">
          <el-button type="primary" :loading="nlCompiling" @click="compileNl">2. 编译为规则候选（LLM）</el-button>
        </div>
      </div>
      <template v-if="draft">
        <el-divider />
        <div class="nl-draft">
          <div class="draft-row"><span class="k">名称</span><b>{{ draft.name }}</b></div>
          <div class="draft-row"><span class="k">级别</span><b :style="{ color: SEV_COLOR[draft.severity] }">{{ draft.severity }}</b></div>
          <div class="draft-row"><span class="k">动作策略</span>{{ draft.actionPolicy.maxTier }} · {{ draft.actionPolicy.allow.join(' / ') || '仅通知' }}</div>
          <div class="draft-row"><span class="k">规则表达式</span></div>
          <pre class="draft-expr mono">{{ draft.expression }}</pre>
          <div class="draft-row"><span class="k">编译摘要</span><span class="text-dim">{{ draft.summary }}</span></div>
          <div class="draft-row"><span class="k">样例校验</span>
            <el-tag v-for="f in draft.fieldHits" :key="f" size="small" class="suggest" type="success" effect="plain">{{ f }}</el-tag>
          </div>
          <div class="draft-row"><span class="k">样例命中</span><b class="num" style="color: var(--accent)">{{ draft.sampleHits }}</b><span class="text-dim"> / 近 24h 样本</span></div>
          <div class="draft-row warn-tip">3. 确认无误后写入人工规则库（人工权威，此后仅人工可改）</div>
        </div>
      </template>
      <template #footer>
        <el-button @click="nlVisible = false">取消</el-button>
        <el-button type="primary" :disabled="!draft" @click="confirmCreate">确认创建人工规则</el-button>
      </template>
    </el-dialog>

    <!-- 审计抽屉 -->
    <el-drawer v-model="auditVisible" :title="`规则审计 · ${auditRule?.ruleId ?? ''}`" size="520px">
      <template v-if="auditRule">
        <div class="audit-meta">
          <div class="a-title">{{ auditRule.name }}</div>
          <div class="text-dim" style="font-size: 12px">{{ auditRule.description }}</div>
          <el-tag :type="auditRule.ruleType === 'manual' ? 'success' : 'warning'" size="small" style="margin-top: 8px">
            {{ auditRule.ruleType === 'manual' ? '人工规则 · 人工权威' : '衍生规则 · 系统自动演化' }} · v{{ auditRule.revision }}
          </el-tag>
        </div>
        <el-timeline class="audit-tl">
          <el-timeline-item v-for="e in [...auditRule.audit].reverse()" :key="e.ts + e.op" :timestamp="fmtTime(e.ts)" placement="top">
            <el-tag size="small" :type="e.op.startsWith('system') ? 'warning' : 'success'" effect="plain">{{ e.op }}</el-tag>
            <span class="by">{{ e.by }}</span>
            <div class="note">{{ e.note }}</div>
          </el-timeline-item>
        </el-timeline>
      </template>
    </el-drawer>

    <!-- 溯源抽屉：衍生规则 → 来源模式 → 证据片段 -->
    <el-drawer v-model="traceVisible" :title="`溯源链 · ${trace?.rule?.ruleId ?? ''}`" size="640px">
      <div v-if="traceLoading" class="text-dim">溯源加载中…</div>
      <template v-else-if="trace">
        <div v-if="trace.note" class="text-dim" style="margin-bottom: 12px">{{ trace.note }}</div>
        <div class="trace-title">衍生规则（顶层）</div>
        <div v-if="trace.rule" class="trace-card">
          <div class="tc-line"><span class="k">名称</span><b>{{ trace.rule.name }}</b></div>
          <div class="tc-line"><span class="k">描述</span>{{ trace.rule.description }}</div>
          <div class="tc-line"><span class="k">级别 / 状态</span>
            <span :style="{ color: SEV_COLOR[trace.rule.severity as Severity] }">{{ trace.rule.severity }}</span>
            <el-tag size="small" :type="trace.rule.state === 'paused' ? 'info' : 'success'" effect="plain" style="margin-left: 6px">{{ trace.rule.state }}</el-tag>
            <span class="text-dim" style="margin-left: 6px">生效 {{ trace.rule.firedTimes }} 次</span>
          </div>
          <div class="tc-line"><span class="k">动作策略</span>{{ trace.rule.actionPolicy.maxTier }} · {{ trace.rule.actionPolicy.allow.join('/') || '仅通知' }}</div>
        </div>
        <template v-if="trace.pattern">
          <el-divider style="margin: 14px 0" />
          <div class="trace-title">来源模式（中间层 · Pattern）</div>
          <div class="trace-card">
            <div class="tc-line"><span class="k">模式</span><span class="mono">{{ trace.pattern.patternId }}</span></div>
            <div class="tc-line"><span class="k">数据域 / 类型</span>{{ trace.pattern.dataset }}
              <el-tag size="small" effect="plain" style="margin-left: 6px">{{ trace.pattern.kind }}</el-tag></div>
            <div class="tc-line" v-if="trace.pattern.hits != null"><span class="k">支撑样本</span>{{ trace.pattern.hits }} 条命中 · 置信度 {{ Math.round((trace.pattern.confidence ?? 0.7) * 100) }}%</div>
            <div class="tc-line" v-if="trace.pattern.description"><span class="k">说明</span>{{ trace.pattern.description }}</div>
            <div class="tc-line" v-if="trace.pattern.ruleIds?.length"><span class="k">覆盖规则</span>
              <el-tag v-for="rid in trace.pattern.ruleIds" :key="rid" size="small" type="info" effect="plain" style="margin-right: 4px">{{ rid }}</el-tag></div>
            <div class="tc-line" v-if="trace.pattern.mitreTechniques?.length || trace.pattern.mitreTactics?.length"><span class="k">MITRE</span>
              <el-tag v-for="t in trace.pattern.mitreTechniques?.slice(0, 8)" :key="t" size="small" type="danger" effect="plain" style="margin-right: 4px">{{ t }}</el-tag>
              <el-tag v-for="t in trace.pattern.mitreTactics ?? []" :key="t" size="small" type="warning" effect="plain" style="margin-right: 4px">{{ t }}</el-tag></div>
          </div>
          <el-divider style="margin: 14px 0" />
          <div class="trace-title">证据片段（底层 · Episodic Memory）
            <span class="text-dim" style="font-weight: 400">共 {{ trace.pattern.supportingFragments?.length ?? 0 }} 条</span></div>
          <div class="frag-list">
            <div v-for="f in trace.pattern.supportingFragments" :key="f.fragmentId" class="frag-item">
              <div class="fi-head">
                <span class="mono">{{ f.fragmentId }}</span>
                <span class="text-dim">{{ f.host }}</span>
                <span class="text-dim" v-if="f.ts">{{ fmtAgo(f.ts) }}</span>
              </div>
              <div class="fi-sum">{{ f.summary }}</div>
            </div>
            <div v-if="!trace.pattern.supportingFragments?.length" class="text-dim">无证据片段</div>
          </div>
        </template>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.rules-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.bar {
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 12px 16px;
}
.bar-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.bar-item .k {
  color: var(--txt-dim);
  font-size: 13px;
}
.bar-item .v {
  font-size: 18px;
  font-weight: 700;
  color: var(--txt-strong);
}
.bar-spacer {
  flex: 1;
}
.list-panel {
  padding: 6px 8px 10px;
}
.list-panel :deep(.el-tabs__nav-wrap::after) {
  background: var(--line-soft);
}
.rname {
  color: var(--txt-strong);
  font-weight: 600;
}
.sub {
  font-size: 11px;
  color: var(--txt-dim);
  margin-top: 2px;
}
.rule-table :deep(.el-table__row) {
  height: 40px;
}
.row-flash {
  animation: flashbg 1.6s ease;
}
@keyframes flashbg {
  0%, 60% { background: rgba(34, 211, 238, 0.14); }
  100% { background: transparent; }
}
.suggests {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}
.suggest {
  cursor: pointer;
  max-width: 100%;
}
.nl-hint {
  color: var(--txt-dim);
  font-size: 12px;
  margin-bottom: 8px;
}
.draft-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 6px 0;
  font-size: 13px;
}
.draft-row .k {
  flex: none;
  width: 80px;
  color: var(--txt-dim);
  font-size: 12px;
}
.draft-expr {
  background: rgba(4, 10, 22, 0.85);
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  padding: 8px;
  font-size: 11px;
  color: #7dd3fc;
  margin: 4px 0;
}
.warn-tip {
  color: var(--warn);
  font-size: 12px;
}
.audit-meta {
  margin-bottom: 18px;
}
.a-title {
  font-size: 16px;
  font-weight: 700;
  margin-bottom: 6px;
}
.audit-tl :deep(.el-timeline-item__timestamp) {
  color: var(--txt-dim);
}
.by {
  color: var(--txt);
  font-size: 12px;
  margin-left: 8px;
}
.note {
  color: var(--txt);
  margin-top: 4px;
  line-height: 1.6;
}
/* 溯源抽屉 */
.trace-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--txt-dim);
  margin-bottom: 8px;
}
.trace-card {
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  padding: 10px 12px;
  font-size: 13px;
  background: rgba(255, 255, 255, 0.015);
}
.tc-line {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin: 6px 0;
  line-height: 1.5;
  flex-wrap: wrap;
}
.tc-line .k {
  flex: none;
  width: 88px;
  color: var(--txt-dim);
  font-size: 12px;
}
.frag-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 46vh;
  overflow: auto;
}
.frag-item {
  border: 1px solid var(--line-soft);
  border-left: 2px solid rgba(34, 211, 238, 0.5);
  border-radius: 6px;
  padding: 8px 10px;
  background: rgba(4, 10, 22, 0.4);
}
.fi-head {
  display: flex;
  gap: 10px;
  align-items: center;
  font-size: 11px;
  margin-bottom: 4px;
}
.fi-sum {
  font-size: 12px;
  color: var(--txt);
  line-height: 1.6;
}
</style>
