// Owner 2026-11-20: "all tiles should be clickable": every StatCard in a view links to the page that explains it.
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

function vueFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => { const p = join(dir, f); return statSync(p).isDirectory() ? vueFiles(p) : p.endsWith('.vue') ? [p] : [] })
}

describe('stat tiles', () => {
  it('every tile has a link target', () => {
    const missing: string[] = []
    for (const f of vueFiles(join(__dirname, 'views'))) {
      for (const m of readFileSync(f, 'utf8').matchAll(/<StatCard\b[\s\S]*?\/>/g)) if (!/\s:?to=/.test(m[0])) missing.push(`${f}: ${m[0].slice(0, 60)}`)
    }
    expect(missing).toEqual([])
  })
})
