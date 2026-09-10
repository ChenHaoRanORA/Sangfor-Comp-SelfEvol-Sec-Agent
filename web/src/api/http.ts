/** 真实后端 HTTP 客户端（FastAPI，同源 /api；Vite 开发代理到 127.0.0.1:8000） */
import axios from 'axios'

export const http = axios.create({ baseURL: '', timeout: 15000 })

http.interceptors.response.use(
  (r) => r,
  (err) => {
    const status = err?.response?.status
    const detail = err?.response?.data?.detail
    console.error(`[api] HTTP ${status ?? 'ERR'}`, detail || err?.message)
    return Promise.reject(err)
  },
)
