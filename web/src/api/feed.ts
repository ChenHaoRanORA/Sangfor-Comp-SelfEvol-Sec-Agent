/** Agent 事件实时流：后端 /ws/feed（时间压缩回放）的 WebSocket 客户端。
 *
 * 与旧 mock subscribeFeed 同签名（onFeed -> 退订函数），供多个页面共享一条连接：
 * - 断线自动重连（指数退避），重连后继续收广播；
 * - 收到 {kind:'alert', alert} 时通知监听者（大屏实时流 / 告警页角标）。
 */
import type { Alert } from './types'

export type FeedKind = 'alert' | 'rule-update' | 'approval'
export interface FeedEvent {
  kind: FeedKind
  alert?: Alert
  rule?: never
  created?: boolean
}

const listeners = new Set<(e: FeedEvent) => void>()
let ws: WebSocket | null = null
let reconnectTimer: number | undefined
let attempts = 0

function url(): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws/feed`
}

function scheduleReconnect() {
  if (ws?.readyState === WebSocket.CONNECTING) return
  const delay = Math.min(10000, 800 * 2 ** Math.min(attempts, 6))
  reconnectTimer = window.setTimeout(connect, delay)
}

function connect() {
  try {
    ws = new WebSocket(url())
  } catch {
    scheduleReconnect()
    return
  }
  ws.onopen = () => {
    attempts = 0
    console.info('[feed] 已连接后端事件流')
  }
  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data) as { kind: string; alert?: Alert }
      if (msg.kind === 'alert' && msg.alert) {
        listeners.forEach((fn) => fn({ kind: 'alert', alert: msg.alert }))
      }
    } catch {
      /* 忽略非法帧 */
    }
  }
  ws.onclose = () => scheduleReconnect()
  ws.onerror = () => {
    attempts += 1
    ws?.close()
  }
}

export function subscribeFeed(fn: (e: FeedEvent) => void): () => void {
  listeners.add(fn)
  if (!ws) connect()
  return () => {
    listeners.delete(fn)
    if (listeners.size === 0 && ws) {
      ws.close()
      ws = null
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer)
        reconnectTimer = undefined
      }
    }
  }
}
