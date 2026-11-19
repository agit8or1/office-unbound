import { describe, expect, it } from 'vitest'
import { NAV } from './nav'
import { routes } from './routes'

// Owner report 2026-11-19: "'system' appears twice in the menu" (a merge had added a second, ungated System entry and route).
describe('navigation has no duplicates', () => {
  it('each menu target and label appears once', () => {
    const items = NAV.flatMap((g) => g.items)
    const targets = items.filter((i) => i.to).map((i) => i.to)
    expect(targets.filter((t, i) => targets.indexOf(t) !== i)).toEqual([])
    const labels = items.map((i) => i.label)
    expect(labels.filter((l, i) => labels.indexOf(l) !== i)).toEqual([])
  })
  it('each route name and path is defined once', () => {
    const names = routes.map((r) => r.name).filter(Boolean)
    expect(names.filter((n, i) => names.indexOf(n) !== i)).toEqual([])
    const paths = routes.map((r) => r.path)
    expect(paths.filter((p, i) => paths.indexOf(p) !== i)).toEqual([])
  })
  it('System is admin-only in the menu and the route (the API requires admin)', () => {
    expect(NAV.flatMap((g) => g.items).find((i) => i.to === '/system')?.min).toBe('admin')
    expect(routes.find((r) => r.path === '/system')?.meta?.min).toBe('admin')
  })
})
