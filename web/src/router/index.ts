import { createRouter, createWebHistory } from 'vue-router'
import AdminLayout from '@/layouts/AdminLayout.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/screen' },
    {
      path: '/screen',
      name: 'screen',
      component: () => import('@/views/screen/ScreenView.vue'),
      meta: { title: '监控大屏' },
    },
    {
      path: '/admin',
      component: AdminLayout,
      redirect: '/admin/alerts',
      children: [
        {
          path: 'alerts',
          name: 'alerts',
          component: () => import('@/views/alerts/AlertsView.vue'),
          meta: { title: '告警历史' },
        },
        {
          path: 'rules',
          name: 'rules',
          component: () => import('@/views/rules/RulesView.vue'),
          meta: { title: '规则管理' },
        },
        {
          path: 'approvals',
          name: 'approvals',
          component: () => import('@/views/approvals/ApprovalsView.vue'),
          meta: { title: 'A3 审批' },
        },
        {
          path: 'suggestions',
          name: 'suggestions',
          component: () => import('@/views/suggestions/SuggestionsView.vue'),
          meta: { title: '规则建议' },
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('@/views/settings/SettingsView.vue'),
          meta: { title: '设置' },
        },
      ],
    },
  ],
})

export default router
