/** 可复现伪随机（mulberry32），保证每次刷新数据形状稳定又略有差异 */
function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5)
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export const rnd = mulberry32(Date.now() % 2147483647)

export const rint = (min: number, max: number) => Math.floor(rnd() * (max - min + 1)) + min

export const pick = <T>(arr: readonly T[]): T => arr[Math.floor(rnd() * arr.length)]

export const chance = (p: number) => rnd() < p

export function weightedPick<T>(entries: readonly { value: T; weight: number }[]): T {
  const total = entries.reduce((s, e) => s + e.weight, 0)
  let acc = 0
  const r = rnd() * total
  for (const e of entries) {
    acc += e.weight
    if (r <= acc) return e.value
  }
  return entries[entries.length - 1].value
}

export const pad2 = (n: number) => String(n).padStart(2, '0')
