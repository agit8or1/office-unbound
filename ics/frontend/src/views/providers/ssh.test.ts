import { describe, expect, it } from 'vitest'
import { FP_RE, newChoice, newForm, newSshSecrets, onboardParams, policyOf, previewParams, sameFingerprint, sessionBody, suggestName, validateChoice, validateForm, wipeSsh } from './ssh'

describe('ssh onboarding model', () => {
  it('maps the plain-language rights onto the existing policy presets', () => {
    const c = newChoice()
    c.nodes = ['pve06']; c.storages = ['local-lvm']
    expect(policyOf(c)).toMatchObject({ preset: 'deploy', scope_mode: 'single_node', service_user: 'officeunbound', scope: { nodes: ['pve06'], pools: ['officeunbound'] } })
    c.rights = 'inventory'
    expect(policyOf(c)).toMatchObject({ preset: 'monitoring', scope: { pools: [] } })
    c.rights = 'import'
    expect(policyOf(c)).toMatchObject({ preset: 'custom', capabilities: ['monitor', 'deploy', 'storage', 'template_clone'] })
    c.rights = 'custom'; c.advanced = ['monitor', 'backup']
    expect(policyOf(c)).toMatchObject({ preset: 'custom', capabilities: ['monitor', 'backup'] })
    c.mode = 'whole_cluster'
    expect(policyOf(c).scope.nodes).toEqual([])
  })
  it('validates the choice', () => {
    const c = newChoice()
    expect(Object.keys(validateChoice(c)).sort()).toEqual(['nodes', 'storages'])
    c.nodes = ['pve06']; c.storages = ['a']; c.pool = "bad'pool"
    expect(validateChoice(c).pool).toBeTruthy()
    c.pool = 'officeunbound'
    expect(validateChoice(c)).toEqual({})
  })
  it('validates the connection form and never puts a secret in the wrong place', () => {
    const f = newForm(), s = newSshSecrets()
    expect(Object.keys(validateForm(f, s)).sort()).toEqual(['host', 'password'])
    f.host = 'pve06.example.net'; s.password = 'pw-1'
    expect(validateForm(f, s)).toEqual({})
    expect(sessionBody(f, s)).toEqual({ host: 'pve06.example.net', port: 22, username: 'root', password: 'pw-1' })
    f.auth = 'key'; s.privateKey = '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----'; s.passphrase = 'pp'
    const b = sessionBody(f, s)
    expect(b).toMatchObject({ private_key: s.privateKey, passphrase: 'pp' }); expect('password' in b).toBe(false)
    f.host = 'a;id'; expect(validateForm(f, s).host).toBeTruthy()
    wipeSsh(s); expect(s).toEqual({ password: '', privateKey: '', passphrase: '' })
  })
  it('compares fingerprints exactly', () => {
    const fp = 'SHA256:' + 'a'.repeat(43)
    expect(FP_RE.test(fp)).toBe(true)
    expect(sameFingerprint(' ' + fp + '\n', fp)).toBe(true)
    expect(sameFingerprint(fp.slice(0, -1) + 'b', fp)).toBe(false)
    expect(sameFingerprint(fp, null)).toBe(false)
  })
  it('builds action params without credentials', () => {
    const p = previewParams('sid', newChoice(), 'onb', null, '')
    expect(JSON.stringify(p)).not.toMatch(/password|private_key/)
    expect(p).toMatchObject({ ssh_session_id: 'sid', name: 'onb' })
    expect(previewParams('sid', newChoice(), 'onb', 'ep1', '10.0.0.5')).toMatchObject({ endpoint_id: 'ep1', ics_address: '10.0.0.5' })
    expect(onboardParams('sid', { preview_id: 'pv', bind_hash: 'h' } as never, 'onb', null)).toEqual({ ssh_session_id: 'sid', preview_id: 'pv', bind_hash: 'h', name: 'onb' })
    expect(suggestName('PVE06.example.net')).toBe('pve06')
  })
})
