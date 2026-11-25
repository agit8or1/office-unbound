// UI audit 2026-11-25 (console): sentence-case badges, identifier columns, 24 h axis labels, calm KPI tones, stylesheet guards.
import { describe, expect, it } from 'vitest'
import { createApp, h } from 'vue'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fmtAxisTime } from './charts/geometry'
import StatusBadge from './ui/StatusBadge.vue'
import DataTable from './ui/DataTable.vue'
import StatCard from './ui/StatCard.vue'

function mount(comp: object, props: Record<string, unknown> = {}) {
  const el = document.createElement('div')
  createApp({ render: () => h(comp, props) }).mount(el)
  return el
}
const css = readFileSync(resolve(process.cwd(), 'src/style.css'), 'utf8')  // vitest runs from ics/frontend

describe('badges', () => {
  it('keep the label text and capitalise only its first letter (no Title Case)', () => {
    const el = mount(StatusBadge, { s: 'high', text: 'high risk' })
    expect(el.querySelector('.badge.warn > .bt')?.textContent).toBe('high risk')
    expect(css).toMatch(/\.badge > \.bt::first-letter \{ text-transform: uppercase; \}/)
    expect(css).not.toMatch(/\.badge, \.chip \{[^}]*text-transform: capitalize/)
  })
})

describe('tables', () => {
  it('keep the identifier column on one line', () => {
    const el = mount(DataTable, { cols: [{ key: 'name', label: 'Name' }, { key: 's', label: 'Status' }], rows: [{ name: 'ou-mail-gateway-primary-eu-west-01', s: 'ok' }], rowKey: (r: { name: string }) => r.name })
    const tds = el.querySelectorAll('td')
    expect(tds[0]!.classList.contains('ident')).toBe(true)
    expect(tds[1]!.classList.contains('ident')).toBe(false)
    expect(css).toMatch(/td\.ident \{ white-space: nowrap; \}/)
  })
})

describe('chart axis', () => {
  it('tells the two ends of a 24 h axis apart', () => {
    const t = Date.UTC(2026, 10, 25, 1, 30)
    expect(fmtAxisTime(t, 24 * 3600e3)).not.toBe(fmtAxisTime(t - 24 * 3600e3, 24 * 3600e3))
    expect(fmtAxisTime(t, 3600e3)).toMatch(/\d{2}.\d{2}/)
  })
})

describe('KPI strip', () => {
  it('colours only the value of a real problem; healthy and idle stay ink', () => {
    const bad = mount(StatCard, { label: 'Active incidents', value: 1, tone: 'bad' })
    expect(bad.querySelector('.stat.bad .val')?.textContent).toBe('1')
    expect(css).toMatch(/\.stat\.bad \.val, \.stat\.bad \.lbl svg \{ color: var\(--bad\); \}/)
    expect(css).not.toMatch(/\.stat\.ok[^{]*\{[^}]*color/)
    // no coloured top borders and no line-coloured grid background (an empty cell showed as a grey block)
    expect(css).not.toMatch(/border-top-color: var\(--warn\)/)
    expect(css).toMatch(/\.statgrid \{[^}]*background: var\(--surface\)/)
  })
})

describe('shell', () => {
  it('hides the menu button on wide screens and the closed drawer from the keyboard', () => {
    expect(css).toMatch(/\.top \.menu-btn \{ display: none; \}/)
    expect(css).toMatch(/\.side \{ position: fixed;[^}]*visibility: hidden/)
    expect(css).toMatch(/\.side\.open \{[^}]*visibility: visible/)
  })
})
