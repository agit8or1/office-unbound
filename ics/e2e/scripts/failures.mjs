// Lists failing tests (project, title, first error lines) from results/report.json
import fs from 'node:fs'
const r = JSON.parse(fs.readFileSync('results/report.json', 'utf8'))
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, '')
function walk(s) {
  for (const x of s.suites ?? []) walk(x)
  for (const sp of s.specs ?? []) for (const te of sp.tests) for (const rs of te.results)
    if (rs.status === 'failed' || rs.status === 'timedOut')
      console.log(`${te.projectName} | ${sp.title} :: ${strip(rs.error?.message ?? '').split('\n').filter(Boolean).slice(0, 4).join(' | ').slice(0, 300)}`)
}
for (const s of r.suites) walk(s)
