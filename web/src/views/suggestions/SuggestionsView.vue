<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '@/api'
import type { RulePromoteCandidate, Severity } from '@/api/types'

const SEV_COLOR: Record<Severity, string> = {
  Low: '#34d399',
  Medium: '#fbbf24',
  High: '#fb923c',
  Critical: '#f87171',
}

const list = ref<RulePromoteCandidate[]>([])
const loading = ref(false)
const error = ref('')
/** 正在生成解释的候选 ruleId → true（并发逐条在服务端串行完成，天然有序） */
const generating = reactive<Record<string, boolean>>({})
const generatingAll = ref(false)
/** 正在执行 同意/拒绝 的候选 ruleId */
const busy = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    list.value = await api.promoteCandidates()
  } catch (e) {
    error.value = '加载建议失败，请确认后端已启动并接入多层记忆库'
    console.error(e)
  } finally {
    loading.value = false
  }
}

function missingCount() {
  return list.value.filter((c) => !c.explain).length
}

/** 生成单条解释：有缓存直接返回；无 LLM 时服务端自动降级为证据拼装摘要并缓存 */
async function explainFor(c: RulePromoteCandidate, force = false) {
  generating[c.ruleId] = true
  try {
    const res = await api.ruleSuggestExplain(c.ruleId, force)
    c.explain = res.text
    c.explainSource = res.source
  } catch (e) {
    ElMessage.error('解释生成失败，请稍后重试')
    console.error(e)
  } finally {
    delete generating[c.ruleId]
  }
}

/** 一键补齐所有缺失解释（逐条串行，避免一次性 N 路 LLM 请求） */
async function generateMissingAll() {
  const missing = list.value.filter((c) => !c.explain)
  if (!missing.length) return
  generatingAll.value = true
  try {
    for (const c of missing) await explainFor(c)
    ElMessage.success(`已补齐 ${missing.length} 条候选解释`)
  } finally {
    generatingAll.value = false
  }
}

/** 同意：升格为人工权威规则（此后命中直发、不再被自动演化改动，全程审计） */
async function accept(c: RulePromoteCandidate) {
  try {
    await ElMessageBox.confirm(
      `确认将「${c.name}」升格为人工权威规则？\n\n` +
        `升格后规则脱离衍生自动演化（系统不再自动增删改），此后命中即按规则定级直发、不消耗大模型推理；` +
        `仅人工可治理，全程留审计并关联来源模式 ${c.promoteFromPatternId ?? '-'}。`,
      '同意升格（自进化 → 人工权威）',
      { type: 'warning', confirmButtonText: '拍板升格', cancelButtonText: '再想想' },
    )
  } catch {
    return
  }
  busy.value = c.ruleId
  try {
    await api.promoteRule(c.ruleId, {
      note: `建议页拍板：${c.name}（${c.ruleId}）经验证有含金量，升格为人工权威规则`,
    })
    ElMessage.success(`「${c.name}」已升格为人工规则，可在"规则管理 → 人工规则"治理`)
    await load()
  } finally {
    busy.value = ''
  }
}

/** 拒绝：仅退出『建议新增』推荐；衍生规则保持 active 继续演化（含审计，可复核） */
async function reject(c: RulePromoteCandidate) {
  try {
    await ElMessageBox.confirm(
      `确认拒绝「${c.name}」的升格建议？\n\n` +
        `该规则仅不再出现在"建议新增"列表中；其作为衍生规则仍保持生效（命中继续参与处置分流与经验验证）。` +
        `您之后不会再见此推荐，除非由开发/审计侧显式重置。`,
      '拒绝升格建议',
      { type: 'info', confirmButtonText: '拒绝推荐', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  busy.value = c.ruleId
  try {
    await api.rejectRule(c.ruleId, {
      note: `建议页拒绝：${c.name}（${c.ruleId}）不升格，仅退出推荐，保留衍生规则继续演化`,
    })
    ElMessage.success(`已拒绝「${c.name}」，不再推荐（衍生规则保持生效）`)
    await load()
  } finally {
    busy.value = ''
  }
}

function exprText(c: RulePromoteCandidate): string {
  const e = c.expression as unknown
  return typeof e === 'string' ? e : JSON.stringify(e ?? null, null, 2)
}

onMounted(() => void load())
</script>

<template>
  <div class="sugg-page">
    <!-- 说明 + 操作条 -->
    <div class="bar panel">
      <div class="bar-item">
        <span class="k">建议新增规则</span>
        <span class="v num">{{ list.length }}</span>
        <span class="text-dim">经验证有含金量的可疑模式 → 人工拍板</span>
      </div>
      <div class="bar-item" v-if="missingCount() > 0">
        <span class="k">缺解释</span>
        <span class="v num" style="color: var(--warn)">{{ missingCount() }}</span>
      </div>
      <div class="bar-spacer" />
      <el-button :disabled="!missingCount() || generatingAll" :loading="generatingAll" @click="generateMissingAll">
        一键生成缺失解释（LLM）
      </el-button>
      <el-button plain @click="load">
        <el-icon style="margin-right: 4px"><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <!-- 权威边界说明 -->
    <div class="hint">
      <b>权威边界：</b>以下候选由系统从历史处置经验归纳（经验 → 可疑模式 → 衍生规则，且反复命中验证）。
      升格为人工规则只由<b class="warn">您拍板</b>；<b class="ok">同意</b> = 固化为人工程序化规则（命中直发、不再消耗大模型）；
      <b>拒绝</b> = 仅不再推荐，底层衍生规则保持生效继续演化。每条候选附<em>大模型自然语言解释</em>供决策参考。
    </div>

    <!-- 错误态 -->
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" style="margin-bottom: 12px" />

    <!-- 列表 -->
    <div v-loading="loading" class="cand-list">
      <template v-if="!loading && list.length">
        <div v-for="c in list" :key="c.ruleId" class="cand-card panel">
          <!-- 头：名称 + 级别 + 操作 -->
          <div class="cc-head">
            <div class="cc-title">
              <div class="cc-name">{{ c.name }}</div>
              <div class="cc-sub ellipsis">{{ c.description || '（无描述）' }}</div>
            </div>
            <div class="cc-actions">
              <el-button
                type="success"
                :loading="busy === c.ruleId"
                :disabled="!!busy && busy !== c.ruleId"
                @click="accept(c)"
              >同意 · 升格为人工规则</el-button>
              <el-button
                type="danger"
                plain
                :loading="busy === c.ruleId"
                :disabled="!!busy && busy !== c.ruleId"
                @click="reject(c)"
              >拒绝 · 不再推荐</el-button>
            </div>
          </div>

          <!-- 元信息 -->
          <div class="cc-meta">
            <span class="chip">
              <span class="k">级别</span>
              <b :style="{ color: SEV_COLOR[c.severity] }">{{ c.severity }}</b>
            </span>
            <span class="chip">
              <span class="k">重复命中</span>
              <b class="num" style="color: var(--accent)">{{ c.firedTimes }}</b><span class="text-dim"> 次</span>
            </span>
            <span class="chip">
              <span class="k">支撑片段</span>
              <b class="num">{{ c.validation?.supportFragments ?? c.hits ?? 0 }}</b>
              <el-tag v-if="(c.validation?.feedbackFragments ?? 0) > 0" size="small" type="success" effect="plain" style="margin-left: 6px">
                {{ c.validation?.feedbackFragments }} 人工复核
              </el-tag>
            </span>
            <span class="chip">
              <span class="k">模式置信度</span>
              <b class="num">{{ Math.round(((c.confidence ?? c.validation?.confidence ?? 0.7)) * 100) }}%</b>
            </span>
            <span class="chip mono src">
              <span class="k">来源模式</span>{{ c.promoteFromPatternId ?? '-' }}
            </span>
          </div>

          <!-- 大模型解释 -->
          <div class="cc-explain" :class="{ none: !c.explain }">
            <div class="ex-head">
              <span class="ex-label">为什么建议新增</span>
              <el-tag v-if="c.explain && c.explainSource === 'llm'" size="small" type="success" effect="dark">大模型总结</el-tag>
              <el-tag v-else-if="c.explain && c.explainSource === 'template'" size="small" type="info" effect="plain">证据自动摘要（LLM 暂不可用）</el-tag>
              <el-button
                v-if="c.explain"
                link
                type="primary"
                size="small"
                :loading="!!generating[c.ruleId]"
                :disabled="generatingAll"
                @click="explainFor(c, true)"
              >重新生成</el-button>
              <el-button
                v-else
                link
                type="primary"
                size="small"
                :loading="!!generating[c.ruleId]"
                :disabled="generatingAll"
                @click="explainFor(c)"
              >用大模型生成解释</el-button>
            </div>
            <div v-if="c.explain" class="ex-text">{{ c.explain }}</div>
            <div v-else class="ex-placeholder">尚未生成解释，点击右侧"用大模型生成解释"查看候选理由。</div>
          </div>

          <!-- 表达式（可折叠） -->
          <details class="cc-expr">
            <summary>规则表达式 · 覆盖原始告警规则（可展开）</summary>
            <pre class="mono">{{ exprText(c) }}</pre>
          </details>
        </div>
      </template>

      <el-empty v-else-if="!loading && !error" description="当前没有待拍板的建议新增规则：经验证的候选均已升格 / 被拒绝，或处于冻结草稿态" :image-size="80" />
    </div>
  </div>
</template>

<style scoped>
.sugg-page {
  display: flex;
  flex-direction: column;
  gap: 12px;
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
.hint {
  font-size: 12px;
  line-height: 1.9;
  color: var(--txt);
  border: 1px dashed var(--line-soft);
  border-radius: 8px;
  padding: 10px 14px;
  background: rgba(34, 211, 238, 0.04);
}
.hint b {
  color: var(--txt-strong);
}
.hint b.warn {
  color: var(--warn);
}
.hint b.ok {
  color: var(--ok);
}
.hint em {
  color: var(--accent);
  font-style: normal;
}
.cand-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 120px;
}
.cand-card {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.cc-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}
.cc-title {
  min-width: 0;
}
.cc-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--txt-strong);
}
.cc-sub {
  font-size: 12px;
  color: var(--txt-dim);
  margin-top: 3px;
  max-width: 560px;
}
.cc-actions {
  flex: none;
  display: flex;
  gap: 8px;
}
.cc-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 20px;
  padding: 8px 12px;
  background: rgba(4, 10, 22, 0.5);
  border-radius: 6px;
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
}
.chip .k {
  color: var(--txt-dim);
  font-size: 12px;
}
.chip.src {
  color: var(--accent);
}
.cc-explain {
  border: 1px solid var(--line-soft);
  border-left: 3px solid var(--accent);
  border-radius: 8px;
  padding: 10px 12px;
  background: rgba(34, 211, 238, 0.05);
}
.cc-explain.none {
  border-left-color: var(--warn);
  background: rgba(251, 191, 36, 0.03);
}
.ex-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.ex-label {
  font-size: 12px;
  font-weight: 700;
  color: var(--txt);
  letter-spacing: 1px;
}
.ex-head :deep(.el-button) {
  margin-left: auto;
}
.ex-text {
  font-size: 13px;
  color: var(--txt-strong);
  line-height: 1.9;
}
.ex-placeholder {
  font-size: 12px;
  color: var(--txt-dim);
}
.cc-expr {
  border: 1px solid var(--line-soft);
  border-radius: 6px;
  background: rgba(4, 10, 22, 0.4);
}
.cc-expr summary {
  cursor: pointer;
  font-size: 12px;
  color: var(--txt-dim);
  padding: 7px 12px;
  user-select: none;
}
.cc-expr summary:hover {
  color: var(--accent);
}
.cc-expr pre {
  margin: 0;
  padding: 4px 12px 12px;
  font-size: 11px;
  line-height: 1.7;
  color: #7dd3fc;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
