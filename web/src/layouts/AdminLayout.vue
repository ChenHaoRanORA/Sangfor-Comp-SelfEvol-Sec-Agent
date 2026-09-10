<script setup lang="ts">
import { markRaw, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { BellFilled, Checked, MagicStick, Monitor, Setting, SetUp } from '@element-plus/icons-vue'
import { api } from '@/api'
import { nowClock } from '@/utils/format'

const route = useRoute()
const clock = ref(nowClock())
const pendingApprovals = ref(0)
let timer: number | undefined
let pollTimer: number | undefined

const menus = [
  { path: '/admin/alerts', label: '告警历史', icon: markRaw(BellFilled) },
  { path: '/admin/rules', label: '规则管理', icon: markRaw(SetUp) },
  { path: '/admin/suggestions', label: '规则建议', icon: markRaw(MagicStick) },
  { path: '/admin/approvals', label: 'A3 审批', icon: markRaw(Checked) },
  { path: '/admin/settings', label: '设置', icon: markRaw(Setting) },
]

function tick() {
  clock.value = nowClock()
}

onMounted(() => {
  timer = window.setInterval(tick, 1000)
  const load = async () => {
    const d = await api.dashboard()
    pendingApprovals.value = d.overview.pendingApprovals
  }
  void load()
  pollTimer = window.setInterval(load, 10_000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
  if (pollTimer) window.clearInterval(pollTimer)
})
</script>

<template>
  <div class="admin-root">
    <aside class="admin-aside">
      <div class="brand">
        <div class="brand-logo">S</div>
        <div>
          <div class="brand-name">SCSSA</div>
          <div class="brand-sub">自进化安全智能体</div>
        </div>
      </div>
      <el-menu :default-active="route.path" router class="admin-menu" background-color="transparent">
        <el-menu-item v-for="m in menus" :key="m.path" :index="m.path">
          <el-icon><component :is="m.icon" /></el-icon>
          <span>{{ m.label }}</span>
          <span v-if="m.path === '/admin/approvals' && pendingApprovals" class="menu-badge">{{ pendingApprovals }}</span>
        </el-menu-item>
      </el-menu>
      <div class="aside-foot">
        <router-link class="foot-link" to="/screen">
          <el-icon><Monitor /></el-icon> 返回监控大屏
        </router-link>
      </div>
    </aside>

    <div class="admin-main">
      <header class="admin-header">
        <div class="page-title">{{ route.meta.title }}</div>
        <div class="header-right">
          <span class="live-dot" />
          <span class="live-text">数据流在线</span>
          <span class="clock mono">{{ clock }}</span>
        </div>
      </header>
      <main class="admin-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<style scoped>
.admin-root {
  display: flex;
  height: 100vh;
  background:
    radial-gradient(1200px 600px at 80% -10%, rgba(34, 211, 238, 0.08), transparent 60%),
    var(--bg-page);
}
.admin-aside {
  width: 216px;
  flex: none;
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--line-soft);
  background: linear-gradient(180deg, #0a1830, #081226);
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px 18px 14px;
}
.brand-logo {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: grid;
  place-items: center;
  font-size: 22px;
  font-weight: 700;
  color: #02131f;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  box-shadow: 0 0 18px rgba(34, 211, 238, 0.45);
}
.brand-name {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 1px;
}
.brand-sub {
  font-size: 11px;
  color: var(--txt-dim);
  letter-spacing: 2px;
}
.admin-menu {
  flex: 1;
  border-right: none;
  padding: 8px 10px;
}
.admin-menu :deep(.el-menu-item) {
  height: 46px;
  border-radius: 8px;
  margin-bottom: 4px;
  color: var(--txt);
}
.admin-menu :deep(.el-menu-item.is-active) {
  background: linear-gradient(90deg, rgba(34, 211, 238, 0.16), rgba(59, 130, 246, 0.08));
  color: var(--accent);
  box-shadow: inset 2px 0 0 var(--accent);
}
.menu-badge {
  margin-left: auto;
  min-width: 18px;
  height: 18px;
  line-height: 18px;
  text-align: center;
  border-radius: 9px;
  font-size: 11px;
  background: var(--crit);
  color: #fff;
  padding: 0 5px;
}
.aside-foot {
  padding: 14px;
  border-top: 1px solid var(--line-soft);
}
.foot-link {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--accent);
  font-size: 13px;
  text-decoration: none;
  opacity: 0.9;
}
.foot-link:hover {
  opacity: 1;
}
.admin-main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.admin-header {
  height: 58px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  border-bottom: 1px solid var(--line-soft);
}
.page-title {
  font-size: 18px;
  font-weight: 600;
  letter-spacing: 1px;
}
.header-right {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--txt);
  font-size: 13px;
}
.live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--ok);
  box-shadow: 0 0 8px var(--ok);
  animation: pulse 1.6s infinite;
}
.live-text {
  color: var(--ok);
  letter-spacing: 1px;
}
.clock {
  color: var(--txt-strong);
  font-size: 14px;
  margin-left: 8px;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.admin-content {
  flex: 1;
  overflow: auto;
  padding: 20px 24px;
}
</style>
