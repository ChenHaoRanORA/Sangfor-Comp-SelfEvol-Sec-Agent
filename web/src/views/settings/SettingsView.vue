<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api'
import type { Severity, Tier } from '@/api/types'

const evolve = ref(true)
const testing = ref(false)

const llm = reactive({
  baseUrl: 'https://api.deepseek.com/v1',
  apiKey: 'sk-demo-****（演示脱敏）',
  model: 'deepseek-chat',
  timeout: 60,
})

const gates = reactive({
  patternGate: true,
  ruleReplay: true,
  auditAll: true,
  costGuard: true,
})

const tiers: { tier: Tier; name: string; desc: string; confirm: string }[] = [
  { tier: 'A0', name: '仅通知', desc: '记录并推送通知，不产生任何系统变更', confirm: '无' },
  { tier: 'A1', name: '只读自主', desc: '取证快照、图谱溯源查询、生成研判报告', confirm: '无' },
  { tier: 'A2', name: '受限自主', desc: '告警聚合/抑制、隔离可疑进程（沙箱侧）、下发展示指令', confirm: '规则显式允许' },
  { tier: 'A3', name: '处置动作', desc: '封禁 IP、杀进程、隔离主机、下发阻断', confirm: '必须人工确认' },
]

async function testLlm() {
  testing.value = true
  await new Promise((r) => setTimeout(r, 900))
  testing.value = false
  ElMessage.success('连接成功：OpenAI 兼容端点可用，模型 ' + llm.model)
}

function save() {
  ElMessage.success('配置已保存（前端演示态，切换真实后端后由 FastAPI 持久化）')
}

async function toggling(on: boolean) {
  const res = await api.toggleEvolution(on)
  evolve.value = res.on
  ElMessage.success(res.on ? '自动演化总开关：开启' : '自动演化总开关：已关闭')
}

onMounted(async () => {
  evolve.value = (await api.evolveEnabled()).on
})
</script>

<template>
  <div class="settings-page">
    <div class="grid">
      <!-- LLM 配置 -->
      <div class="panel s-card">
        <div class="panel-title"><span class="bar" />大模型接入（OpenAI 兼容端点）</div>
        <div class="s-body">
          <el-form label-width="110px" label-position="left">
            <el-form-item label="Base URL">
              <el-input v-model="llm.baseUrl" placeholder="https://api.deepseek.com/v1" />
            </el-form-item>
            <el-form-item label="API Key">
              <el-input v-model="llm.apiKey" type="password" show-password placeholder="sk-..." />
            </el-form-item>
            <el-form-item label="模型">
              <el-select v-model="llm.model" style="width: 100%">
                <el-option label="deepseek-chat" value="deepseek-chat" />
                <el-option label="deepseek-reasoner" value="deepseek-reasoner" />
                <el-option label="gpt-4o" value="gpt-4o" />
                <el-option label="qwen-max" value="qwen-max" />
              </el-select>
            </el-form-item>
            <el-form-item label="超时(秒)">
              <el-input-number v-model="llm.timeout" :min="10" :max="300" />
            </el-form-item>
          </el-form>
          <div class="btn-row">
            <el-button :loading="testing" @click="testLlm">测试连接</el-button>
            <el-button type="primary" @click="save">保存</el-button>
          </div>
          <div class="tip text-dim">研判 / 模式归纳 / 规则编译 / NL 规则助手 共用该端点；输出走 JSON Schema 强约束。</div>
        </div>
      </div>

      <!-- 运行模式 -->
      <div class="panel s-card">
        <div class="panel-title"><span class="bar" />运行与数据源</div>
        <div class="s-body">
          <el-form label-width="110px" label-position="left">
            <el-form-item label="运行模式">
              <el-radio-group :model-value="'offline'" disabled>
                <el-radio value="offline">离线回放（现期）</el-radio>
                <el-radio value="online">在线靶场（后期）</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="数据入口">
              <span class="mono text-dim">POST /api/v1/ingest（Webhook，预留 Syslog/WS）</span>
            </el-form-item>
            <el-form-item label="离线数据集">
              <div class="ds-list">
                <span class="chip">linux-APT-2024（Wazuh/Linux 审计流）</span>
                <span class="chip">llm-soc 178（带标签研判基准）</span>
              </div>
            </el-form-item>
            <el-form-item label="静态知识库">
              <span class="mono text-dim">Kùzu · MITRE ATT&CK 企业版（Tactic 15 / Technique 697 / 关系 19931）</span>
            </el-form-item>
          </el-form>
          <div class="btn-row">
            <el-button type="primary" @click="save">保存</el-button>
          </div>
        </div>
      </div>
    </div>

    <div class="grid">
      <!-- 门控 -->
      <div class="panel s-card">
        <div class="panel-title"><span class="bar" />自进化门控</div>
        <div class="s-body">
          <el-form label-width="130px" label-position="left">
            <el-form-item label="自动演化总开关">
              <el-switch v-model="evolve" @change="toggling" />
              <span class="text-dim" style="margin-left: 8px">{{ evolve ? '衍生规则可自动增删改' : '已冻结' }}</span>
            </el-form-item>
            <el-form-item label="模式入库需门控">
              <el-switch v-model="gates.patternGate" />
            </el-form-item>
            <el-form-item label="规则需回放验证">
              <el-switch v-model="gates.ruleReplay" />
            </el-form-item>
            <el-form-item label="全部变更写审计">
              <el-switch v-model="gates.auditAll" />
            </el-form-item>
            <el-form-item label="LLM 成本护栏">
              <el-switch v-model="gates.costGuard" />
            </el-form-item>
          </el-form>
          <div class="btn-row"><el-button type="primary" @click="save">保存</el-button></div>
        </div>
      </div>

      <!-- A0-A3 -->
      <div class="panel s-card">
        <div class="panel-title"><span class="bar" />分级自主行动策略（A0–A3）</div>
        <div class="s-body">
          <div v-for="t in tiers" :key="t.tier" class="tier-row">
            <span class="tier-tag" :class="`tier-${t.tier}`">{{ t.tier }}</span>
            <div class="tier-info">
              <b>{{ t.name }}</b>
              <div class="text-dim" style="font-size: 12px">{{ t.desc }}</div>
            </div>
            <span class="tier-confirm" :class="{ danger: t.tier === 'A3' }">{{ t.confirm }}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="panel s-card">
      <div class="panel-title"><span class="bar" />告警级别色阶</div>
      <div class="s-body sev-row">
        <span v-for="(s, i) in (['Critical', 'High', 'Medium', 'Low'] as Severity[])" :key="s" class="sev-chip">
          <span class="swatch" :style="{ background: ['#f87171', '#fb923c', '#fbbf24', '#34d399'][i] }" />
          {{ s }}
        </span>
        <span class="text-dim" style="margin-left: auto">映射至 Element / ECharts 统一色板</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
@media (max-width: 1100px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
.s-card {
  min-width: 0;
}
.s-body {
  padding: 14px 16px;
}
.btn-row {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 4px;
}
.tip {
  font-size: 12px;
  margin-top: 10px;
}
.ds-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  font-size: 11px;
  color: #7dd3fc;
  border: 1px solid rgba(56, 189, 248, 0.3);
  background: rgba(56, 189, 248, 0.06);
  padding: 2px 8px;
  border-radius: 12px;
}
.tier-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 9px 4px;
  border-bottom: 1px dashed rgba(125, 179, 255, 0.1);
}
.tier-row:last-child {
  border-bottom: none;
}
.tier-tag {
  width: 42px;
  height: 26px;
  border-radius: 6px;
  display: grid;
  place-items: center;
  font-weight: 800;
  font-size: 13px;
  color: #0b1220;
  background: #94a3b8;
}
.tier-A0 { background: #94a3b8; }
.tier-A1 { background: #38bdf8; }
.tier-A2 { background: #fbbf24; }
.tier-A3 { background: #f87171; }
.tier-info {
  flex: 1;
}
.tier-confirm {
  color: var(--ok);
  font-size: 12px;
}
.tier-confirm.danger {
  color: var(--crit);
  font-weight: 600;
}
.sev-row {
  display: flex;
  align-items: center;
  gap: 18px;
}
.sev-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--txt);
}
.swatch {
  width: 14px;
  height: 14px;
  border-radius: 3px;
  display: inline-block;
}
</style>
