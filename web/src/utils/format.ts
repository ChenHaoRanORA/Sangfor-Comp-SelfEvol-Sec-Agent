import { pad2 } from './rand'

/** 时间戳(ms) -> MM-DD HH:mm:ss */
export function fmtTime(ms: number): string {
  const d = new Date(ms)
  return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

/** 时间戳(ms) -> 今天 HH:mm */
export function fmtHM(ms: number): string {
  const d = new Date(ms)
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

/** HH:mm:ss 走时时钟 */
export function nowClock(): string {
  const d = new Date()
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

/** 相对时间（分钟/小时/天） */
export function fmtAgo(ms: number): string {
  const diff = Date.now() - ms
  if (diff < 60_000) return '刚刚'
  const m = Math.floor(diff / 60_000)
  if (m < 60) return `${m} 分钟前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时前`
  return `${Math.floor(h / 24)} 天前`
}

/** 数字千分位 */
export function fmtNum(n: number): string {
  return n.toLocaleString('en-US')
}
