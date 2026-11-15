export function fmtNum(n: number, digits = 1): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(digits)
}
export function fmtGb(n: number): string {
  return n >= 1024 ? `${fmtNum(n / 1024)} TiB` : `${fmtNum(n)} GiB`
}
export function fmtMem(mb: number): string { return fmtGb(mb / 1024) }
export function pct(part: number, whole: number): number {
  return whole > 0 ? Math.max(0, Math.min(100, (part / whole) * 100)) : 0
}
export function fmtDuration(seconds: number): string {
  if (seconds <= 0) return 'none expected'
  if (seconds < 60) return `~${Math.round(seconds)} s`
  const m = Math.round(seconds / 60)
  return m < 60 ? `~${m} min` : `~${fmtNum(m / 60)} h`
}
