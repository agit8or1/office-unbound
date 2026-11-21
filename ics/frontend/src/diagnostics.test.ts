import { describe, expect, it } from 'vitest'
import { body, choices, type DiagSources } from './diagnostics'

const SRC: DiagSources = { deployment: 'acme', max_lines: 300, units: ['nginx', 'php8.3-fpm', 'gromox-zcore', 'keycloak'], files: ['nginx-error', 'php8.3-fpm'],
  greps: ['error', 'php'], vms: [{ name: 'acme-gw', components: ['groupware'], enrolled: true, available: true, suggested_units: ['php8.3-fpm', 'gromox-zcore', 'unknown'], suggested_files: ['php8.3-fpm'] }] }

describe('diagnostics panel helpers', () => {
  it('lists the VM suggestions first, then every other allowlisted name, never an unknown one', () => {
    expect(choices(SRC, 'acme-gw', 'unit')).toEqual({ suggested: ['php8.3-fpm', 'gromox-zcore'], other: ['nginx', 'keycloak'] })
    expect(choices(SRC, 'acme-gw', 'file')).toEqual({ suggested: ['php8.3-fpm'], other: ['nginx-error'] })
    expect(choices(SRC, 'nope', 'unit').suggested).toEqual([])
  })
  it('builds exactly the closed request: one of unit/file, lines clamped, since only for a journal', () => {
    expect(body({ vm: 'acme-gw', kind: 'unit', name: 'php8.3-fpm', lines: 50, since: 60, grep: 'php' })).toEqual({ vm: 'acme-gw', unit: 'php8.3-fpm', lines: 50, since_minutes: 60, grep: 'php' })
    expect(body({ vm: 'acme-gw', kind: 'file', name: 'nginx-error', lines: 5000, since: 60, grep: '' })).toEqual({ vm: 'acme-gw', file: 'nginx-error', lines: 300 })
    expect(body({ vm: 'acme-gw', kind: 'unit', name: 'nginx', lines: 0, since: null, grep: '' })).toEqual({ vm: 'acme-gw', unit: 'nginx', lines: 1 })
  })
})
