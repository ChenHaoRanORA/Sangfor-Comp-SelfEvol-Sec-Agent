import type { ActionStatus, AlertSource, AlertStatus, RuleItem, Severity, Tier, VerdictClass } from './types'
import * as db from './mockDb'

/** 异步门面：页面只依赖本模块，切真实后端时把实现换成 axios/WebSocket 即可 */

const wait = (ms = 120) => new Promise<void>((r) => setTimeout(r, ms))

export const api = {
  async dashboard() {
    await wait(80)
    return db.buildDashboard()
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
    await wait()
    return db.getAlertsPage(params)
  },
  async alert(id: string) {
    await wait()
    return db.getAlert(id)
  },
  async reviewAlert(id: string, cls: 'TP' | 'FP') {
    await wait(150)
    return db.reviewAlert(id, cls)
  },
  async rules(ruleType?: 'manual' | 'derived'): Promise<RuleItem[]> {
    await wait()
    return db.getRules(ruleType)
  },
  async toggleRule(ruleId: string, enabled: boolean) {
    await wait(60)
    return db.setRuleEnabled(ruleId, enabled)
  },
  async toggleDerivedFrozen(ruleId: string, frozen: boolean) {
    await wait(60)
    return db.setDerivedFrozen(ruleId, frozen)
  },
  async updateRule(ruleId: string, patch: Parameters<typeof db.updateManualRule>[1]) {
    await wait(150)
    return db.updateManualRule(ruleId, patch)
  },
  async deleteRule(ruleId: string) {
    await wait(150)
    return db.deleteRule(ruleId)
  },
  async actions(status?: ActionStatus | '') {
    await wait()
    return db.getActions(status)
  },
  async decide(actionId: string, approved: boolean, by: string) {
    await wait(150)
    return db.decideApproval(actionId, approved, by)
  },
  async hosts() {
    await wait(60)
    return db.getHosts()
  },
  async nlCompile(text: string) {
    await wait(600)
    return db.nlCompile(text)
  },
  async createRuleFromNl(draft: ReturnType<typeof db.nlCompile>) {
    await wait(150)
    return db.createManualRule(draft)
  },
  async createRuleFromNlRaw(p: { name: string; description: string; severity: Severity; expr: string; tier: Tier; allow: string[] }) {
    await wait(150)
    return db.createManualRuleFull(p)
  },
  async toggleEvolution(on: boolean) {
    await wait(60)
    db.toggleEvolution(on)
    return { on }
  },
  async evolveEnabled() {
    return db.evolveSwitch()
  },
}

export { subscribeFeed } from './mockDb'
export type { FeedEvent, FeedKind } from './mockDb'
export type * from './types'
