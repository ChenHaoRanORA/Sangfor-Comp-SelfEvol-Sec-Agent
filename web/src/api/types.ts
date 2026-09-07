/** 前端数据模型 —— 与后端统一 Alert/Rule/Pattern/Fragment/ActionRecord 契约对齐 */

export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'
export type VerdictClass = 'TP' | 'FP'
export type AlertSource = 'wazuh' | 'replay' | 'eval'
export type AlertStatus = 'open' | 'reviewed' | 'dismissed'
export type Tier = 'A0' | 'A1' | 'A2' | 'A3'

export interface AgentInfo {
  name: string
  ip: string
  os: 'linux' | 'windows'
}

/** 告警头部携带的 Wazuh/MITRE 规则信息（对应原始 rule.*） */
export interface RawRuleRef {
  id: number
  level: number
  groups: string[]
  description: string
  mitreTechniques: string[]
  mitreTactics: string[]
}

/** 详情抽屉展示的「命中规则」（来自人工/衍生双规则池，含生效次数） */
export interface HitRule {
  ruleId: string
  ruleType: 'manual' | 'derived'
  name: string
  firedTimes: number
  severity: Severity
  maxTier: Tier
}

export interface Verdict {
  classification: VerdictClass
  priority: Severity
  justification: string
  model: string
  reviewedBy?: string
}

export interface RelatedPattern {
  patternId: string
  title: string
  hits: number
  confidence: number
}

export interface RelatedFragment {
  fragmentId: string
  summary: string
  ts: number
}

/** 统一告警 */
export interface Alert {
  id: string
  ts: number
  source: AlertSource
  agent: AgentInfo
  decoder: string
  family: string
  severity: Severity
  raw: string
  rule: RawRuleRef
  verdict: Verdict | null
  status: AlertStatus
  hitRules: HitRule[]
  relatedPatterns: RelatedPattern[]
  relatedFragments: RelatedFragment[]
  actionIds: string[]
}

export type RuleState = 'active' | 'draft' | 'paused' | 'superseded'

export interface AuditEntry {
  ts: number
  op: string
  by: string
  note: string
}

export interface ActionPolicy {
  maxTier: Tier
  allow: string[]
}

/** 规则（人工 + 衍生） */
export interface RuleItem {
  ruleId: string
  ruleType: 'manual' | 'derived'
  name: string
  description: string
  enabled: boolean
  state: RuleState
  severity: Severity
  expression: string
  actionPolicy: ActionPolicy
  firedTimes: number
  series: number[] // 近 24h 每小时命中数
  lastTriggeredAt: number | null
  owner: string
  createdAt: number
  updatedAt: number
  revision: number
  audit: AuditEntry[]
  // 衍生规则特有
  sourcePatternId?: string
  confidence?: number
  hits?: number
  auto: boolean
}

export type ActionStatus = 'pending' | 'done' | 'denied' | 'failed'

export interface ActionRecord {
  actionId: string
  alertId: string
  ruleId: string
  tier: Tier
  name: string
  status: ActionStatus
  approvedBy?: string
  result?: string
  ts: number
  updatedAt?: number
}

export interface HostStatus {
  name: string
  ip: string
  role: string
  os: 'linux' | 'windows'
  status: 'online' | 'offline' | 'degraded'
  lastSeen: number
  alertToday: number
}

export interface HourPoint {
  label: string
  ts: number
  cur: number
  prev: number
}

export interface DashboardOverview {
  todayTotal: number
  critical: number
  high: number
  medium: number
  low: number
  openReview: number
  pendingApprovals: number
  hostsTotal: number
  hostsOnline: number
  rulesActive: number
  firedToday: number
  tpToday: number
  fpToday: number
}

export interface Dashboard {
  overview: DashboardOverview
  hourly: HourPoint[]
  sevDist: { severity: Severity; count: number }[]
  decoderDist: { name: string; count: number }[]
  topRules: TopRule[]
  hosts: HostStatus[]
  recentAlerts: Alert[]
}

/** 大屏规则 TOP 行（额外携带近24h命中） */
export type TopRule = RuleItem & { hits24: number }

export interface QueryParams {
  keyword?: string
  severity?: Severity | ''
  verdict?: VerdictClass | 'unknown'
  source?: AlertSource | ''
  status?: AlertStatus | ''
  page: number
  size: number
}

export interface PageResult<T> {
  total: number
  items: T[]
}

export interface NlRuleDraft {
  name: string
  description: string
  severity: Severity
  expression: string
  actionPolicy: ActionPolicy
  summary: string
  fieldHits: string[]
  sampleHits: number
}
