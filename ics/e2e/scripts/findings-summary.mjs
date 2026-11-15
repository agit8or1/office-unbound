// Groups results/findings.jsonl (one JSON object per line, written by lib/helpers.finding) into a readable summary.
import fs from 'node:fs'
const f = 'results/findings.jsonl'
if (!fs.existsSync(f)) { console.log('[e2e] no findings recorded'); process.exit(0) }
const rows = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
const groups = new Map()
for (const r of rows) {
  const k = `${r.category} | ${r.route} | ${r.detail}`
  const g = groups.get(k) ?? { ...r, projects: new Set() }
  g.projects.add(r.project)
  groups.set(k, g)
}
const byCat = {}
for (const g of groups.values()) (byCat[g.category] ??= []).push(g)
console.log(`\n[e2e] findings: ${groups.size} distinct (${rows.length} raw)`)
for (const [cat, list] of Object.entries(byCat).sort()) {
  console.log(`\n## ${cat} (${list.length})`)
  for (const g of list) console.log(`- [${[...g.projects].join(',')}] ${g.route}: ${g.detail}`)
}
