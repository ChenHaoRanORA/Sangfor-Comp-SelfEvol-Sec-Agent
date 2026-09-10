import type { ActionStatus, AlertEvidence, AlertSource, AlertStatus, RuleItem, RulePromoteCandidate, RuleSuggestExplain, Severity, Tier, VerdictClass } from './types'
import * as db from './mockDb'
import { http } from './http'

/**
 * 页面数据门面。
 * - dashboard / alerts / alert / review / rules(含编辑) / 自动演化开关 / 衍生规则 已接真实 Agent 演示后端（FastAPI REST，衍生规则直读多层记忆库 MemoryStore）；
 * - 审批 A3、NL 编译向导等尚未实现的系统能力仍走本地 Mock（保持页面可操作）。
 * - 实时流 subscribeFeed 来自后端 WebSocket /ws/feed。
 */

/* ================= 已接真实后端 ================= */

export const api = {
  async dashboard() {
    return (await http.get('/api/dashboard')).data
  },
  async alerts(params: {
    keyword?: string
    severity?: Severity | ''
    verdict?: VerdictClass | 'unknown' | ''
    source?: AlertSource | ''
    status?: AlertStatus | ''
    page: number
    size: number
  }) {
    return (await http.get('/api/alerts', { params })).data
  },
  async alert(id: string) {
    return (await http.get(`/api/alerts/${encodeURIComponent(id)}`)).data
  },
  /** 复核告警（后端同时写回多层记忆 feedback 片段 + 审计） */
  async reviewAlert(id: string, cls: 'TP' | 'FP', opts?: { reason?: string; priority?: string; by?: string }) {
    return (await http.post(`/api/alerts/${encodeURIComponent(id)}/review`, {
      cls,
      reason: opts?.reason ?? '',
      priority: opts?.priority ?? '',
      by: opts?.by ?? 'analyst',
    })).data
  },
  /** 实时证据面板：相似记忆片段 + 命中模式 + ATT&CK 图谱多跳（seq 防泄漏） */
  async alertEvidence(id: string): Promise<AlertEvidence> {
    return (await http.get(`/api/alerts/${encodeURIComponent(id)}/evidence`)).data
  },
  async rules(ruleType?: 'manual' | 'derived'): Promise<RuleItem[]> {
    return (await http.get('/api/rules', { params: { type: ruleType ?? 'manual' } })).data
  },
  async toggleRule(ruleId: string, enabled: boolean) {
    return (await http.patch(`/api/rules/${encodeURIComponent(ruleId)}`, { enabled })).data
  },
  async toggleDerivedFrozen(ruleId: string, frozen: boolean) {
    return (await http.patch(`/api/rules/${encodeURIComponent(ruleId)}`, { state: frozen ? 'paused' : 'active' })).data
  },
  async updateRule(ruleId: string, patch: { name?: string; description?: string; severity?: Severity; expr?: string; tier?: Tier; allow?: string[] }) {
    return (await http.patch(`/api/rules/${encodeURIComponent(ruleId)}`, { ...patch })).data
  },
  async deleteRule(ruleId: string) {
    return (await http.delete(`/api/rules/${encodeURIComponent(ruleId)}`)).data
  },
  async createRuleFromNlRaw(p: { name: string; description: string; severity: Severity; expr: string; tier: Tier; allow: string[] }) {
    return (await http.post('/api/rules', { ...p })).data
  },
  async createRuleFromNl(draft: ReturnType<typeof db.nlCompile>) {
    return (await http.post('/api/rules', {
      name: draft.name,
      description: draft.description,
      severity: draft.severity,
      expr: draft.expression,
      tier: draft.actionPolicy.maxTier,
      allow: draft.actionPolicy.allow,
    })).data
  },

  /* ================= 仍为本地 Mock（能力未接入后端） ================= */
  async actions(status?: ActionStatus | '') {
    return db.getActions(status)
  },
  async decide(actionId: string, approved: boolean, by: string) {
    return db.decideApproval(actionId, approved, by)
  },
  async hosts() {
    return db.getHosts()
  },
  async nlCompile(text: string) {
    return db.nlCompile(text)
  },
  async toggleEvolution(on: boolean) {
    return (await http.post('/api/evolution', { on })).data
  },
  async evolveEnabled() {
    return (await http.get('/api/evolution')).data
  },
  /** 待升格人工规则候选（经验证有含金量的衍生规则 + 来源模式统计，可能含已缓存 LLM 解释） */
  async promoteCandidates(): Promise<RulePromoteCandidate[]> {
    return (await http.get('/api/evolution/promote-candidates')).data
  },
  /** 人工拍板（同意）：衍生规则 → 人工权威规则（记忆落库 + 审计 + 人工池登记） */
  async promoteRule(ruleId: string, opts?: { note?: string; by?: string }) {
    return (await http.post('/api/evolution/promote', {
      ruleId,
      note: opts?.note ?? '',
      by: opts?.by ?? 'analyst',
    })).data
  },
  /** 人工拒绝：仅退出『建议新增规则』推荐，衍生规则保持 active 继续演化（含审计） */
  async rejectRule(ruleId: string, opts?: { note?: string; by?: string }) {
    return (await http.post('/api/evolution/reject', {
      ruleId,
      note: opts?.note ?? '',
      by: opts?.by ?? 'analyst',
    })).data
  },
  /** 生成/获取候选规则的大模型自然语言解释（服务端缓存；LLM 不可用自动降级模板） */
  async ruleSuggestExplain(ruleId: string, force = false): Promise<RuleSuggestExplain> {
    return (await http.post(`/api/evolution/promote-candidates/${encodeURIComponent(ruleId)}/explain`, { force })).data
  },
  async ruleTrace(ruleId: string) {
    return (await http.get(`/api/rules/${encodeURIComponent(ruleId)}/trace`)).data
  },
}

export { subscribeFeed } from './feed'
export type { FeedEvent, FeedKind } from './feed'
export type * from './types'
