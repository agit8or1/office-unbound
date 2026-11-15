// Pure chart math, kept out of components so it is unit-tested. SVG output uses attributes/classes only (CSP: no inline styles).
export interface Pt { t: number; v: number }

export function niceMax(max: number): number {
  if (!isFinite(max) || max <= 0) return 1
  const p = Math.pow(10, Math.floor(Math.log10(max)))
  const n = max / p
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
}

export interface Scale { x: (t: number) => number; y: (v: number) => number }
export function makeScale(w: number, h: number, pad: { l: number; r: number; t: number; b: number }, t0: number, t1: number, vmax: number): Scale {
  const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b
  const span = t1 - t0 || 1
  return { x: (t) => pad.l + ((t - t0) / span) * iw, y: (v) => pad.t + ih - (Math.min(v, vmax) / (vmax || 1)) * ih }
}

/** Polyline path; breaks the line where consecutive samples are further apart than `gap` ms (missing data is not interpolated). */
export function linePath(pts: Pt[], s: Scale, gap = Infinity): string {
  let d = '', prev: Pt | null = null
  for (const p of pts) {
    d += (prev && p.t - prev.t <= gap ? 'L' : 'M') + s.x(p.t).toFixed(1) + ' ' + s.y(p.v).toFixed(1)
    prev = p
  }
  return d
}
export function areaPath(pts: Pt[], s: Scale, baseline: number): string {
  if (pts.length < 2) return ''
  const first = pts[0]!, last = pts[pts.length - 1]!
  return linePath(pts, s) + `L${s.x(last.t).toFixed(1)} ${baseline}L${s.x(first.t).toFixed(1)} ${baseline}Z`
}

export function nearest(pts: Pt[], t: number): Pt | null {
  let best: Pt | null = null
  for (const p of pts) if (!best || Math.abs(p.t - t) < Math.abs(best.t - t)) best = p
  return best
}

export interface Arc { dash: number; offset: number; frac: number }
/** Donut segments as stroke-dasharray values on a circle of circumference c. */
export function donutArcs(values: number[], c: number): Arc[] {
  const total = values.reduce((a, b) => a + Math.max(0, b), 0)
  let acc = 0
  return values.map((v) => {
    const frac = total ? Math.max(0, v) / total : 0
    const a = { dash: frac * c, offset: -acc * c, frac }
    acc += frac
    return a
  })
}

export const RANGES = [
  { value: '1h', label: '1h', ms: 3600e3 },
  { value: '24h', label: '24h', ms: 24 * 3600e3 },
  { value: '7d', label: '7d', ms: 7 * 24 * 3600e3 },
  { value: '30d', label: '30d', ms: 30 * 24 * 3600e3 },
] as const

export function fmtAxisTime(t: number, rangeMs: number): string {
  const d = new Date(t)
  if (rangeMs <= 24 * 3600e3) return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
