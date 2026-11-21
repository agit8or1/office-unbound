import { describe, expect, it } from 'vitest'
import { splitDeployments, type Deployment } from './infra'

const d = (id: string, status: string, updated: string): Deployment => ({ endpointId: null, id, name: id, status, profile: 'custom', updated, created: null })

describe('deployments list order', () => {
  it('shows live deployments first, newest change first, and keeps destroyed ones apart', () => {
    const { live, gone } = splitDeployments([d('e2e-fo1', 'destroyed', '2026-11-18T10:00:00Z'), d('ou-test2', 'destroyed', '2026-11-20T22:00:00Z'),
      d('officeunbound2', 'active', '2026-11-21T04:20:00Z'), d('lab', 'failed', '2026-11-19T00:00:00Z')])
    expect(live.map((x) => x.id)).toEqual(['officeunbound2', 'lab'])
    expect(gone.map((x) => x.id)).toEqual(['ou-test2', 'e2e-fo1'])
  })
})
