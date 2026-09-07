import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/index.css'

import App from './App.vue'
import router from './router'
import { startFeed } from './api/mockDb'

// 统一使用 Element Plus 深色主题
document.documentElement.classList.add('dark')

const app = createApp(App)
app.use(ElementPlus, { locale: zhCn })
for (const [key, comp] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, comp)
}
app.use(router)
app.mount('#app')

// 开发期内置 Mock 实时告警流（切真实后端后移除）
startFeed()
