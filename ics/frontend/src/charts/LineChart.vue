<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { areaPath, fmtAxisTime, linePath, makeScale, nearest, niceMax, type Pt } from './geometry'

export interface Series { name: string; points: Pt[] }
const props = withDefaults(defineProps<{ series: Series[]; rangeMs: number; fmt?: (v: number) => string; yMax?: number; height?: number }>(), { height: 210 })
const W = ref(480) // tracks the rendered width so axis text stays a readable size
const pad = { l: 44, r: 10, t: 10, b: 24 }
const H = computed(() => props.height)
const t1 = computed(() => Date.now())
const t0 = computed(() => t1.value - props.rangeMs)
const vmax = computed(() => props.yMax ?? niceMax(Math.max(0, ...props.series.flatMap((s) => s.points.map((p) => p.v)))))
const scale = computed(() => makeScale(W.value, H.value, pad, t0.value, t1.value, vmax.value))
const f = computed(() => props.fmt ?? ((v: number) => String(Math.round(v * 10) / 10)))
const gap = computed(() => props.rangeMs / 12)
const yTicks = computed(() => [0, 0.5, 1].map((k) => ({ v: vmax.value * k, y: scale.value.y(vmax.value * k) })))
const xTicks = computed(() => [0, 1 / 3, 2 / 3, 1].map((k) => ({ t: t0.value + props.rangeMs * k, x: scale.value.x(t0.value + props.rangeMs * k) })))
const base = computed(() => scale.value.y(0))
const paths = computed(() => props.series.map((s, i) => ({ name: s.name, cls: i + 1, d: linePath(s.points, scale.value, gap.value), area: i === 0 ? areaPath(s.points, scale.value, base.value) : '' })))

const wrap = ref<HTMLElement | null>(null)
let ro: ResizeObserver | undefined
onMounted(() => { const el = wrap.value; if (!el) return; W.value = Math.max(240, el.clientWidth); ro = new ResizeObserver(() => { W.value = Math.max(240, el.clientWidth) }); ro.observe(el) })
onUnmounted(() => ro?.disconnect())
const tip = ref<{ x: number; y: number; text: string; cx: number } | null>(null)
function move(e: PointerEvent) {
  const el = wrap.value; if (!el) return
  const r = el.getBoundingClientRect()
  const px = ((e.clientX - r.left) / r.width) * W.value
  const t = t0.value + ((px - pad.l) / (W.value - pad.l - pad.r)) * props.rangeMs
  const parts: string[] = []; let at: Pt | null = null
  for (const s of props.series) { const p = nearest(s.points, t); if (p) { at = at ?? p; parts.push((props.series.length > 1 ? s.name + ' ' : '') + f.value(p.v)) } }
  if (!at) { tip.value = null; return }
  tip.value = { x: (scale.value.x(at.t) / W.value) * r.width, y: (scale.value.y(at.v) / H.value) * r.height, cx: scale.value.x(at.t), text: `${parts.join(' · ')} at ${fmtAxisTime(at.t, props.rangeMs)}` }
}
const empty = computed(() => props.series.every((s) => s.points.length === 0))
</script>
<template>
  <div ref="wrap" class="chartwrap" @pointermove="move" @pointerleave="tip = null">
    <svg class="lc" :viewBox="`0 0 ${W} ${H}`" role="img" :aria-label="'Time series: ' + series.map((s) => s.name).join(', ')">
      <g v-for="t in yTicks" :key="t.v"><line class="grid-l" :x1="pad.l" :x2="W - pad.r" :y1="t.y" :y2="t.y" /><text class="axis" :x="pad.l - 6" :y="t.y + 3" text-anchor="end">{{ f(t.v) }}</text></g>
      <text v-for="t in xTicks" :key="t.t" class="axis" :x="t.x" :y="H - 6" text-anchor="middle">{{ fmtAxisTime(t.t, rangeMs) }}</text>
      <template v-if="!empty">
        <path v-if="paths[0]?.area" class="area" :class="'a1'" :d="paths[0].area" />
        <path v-for="p in paths" :key="p.name" class="ln" :class="'s' + p.cls" :d="p.d" />
        <line v-if="tip" class="cross" :x1="tip.cx" :x2="tip.cx" :y1="pad.t" :y2="base" />
      </template>
    </svg>
    <div v-if="tip" class="chart-tip" :style="{ left: tip.x + 'px', top: tip.y + 'px' }">{{ tip.text }}</div>
  </div>
</template>
