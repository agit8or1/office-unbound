// Regression (owner 2026-11-20: "Job director ... path.job_id: Input should be a valid UUID"): router links change the URL with pushState,
// which fires no 'hashchange'; the legacy route must follow every navigation, so #/users/directory never becomes a job id on #/jobs.
import { describe, expect, it } from 'vitest'
import { route, syncRoute } from './store'

describe('legacy route follows router navigation', () => {
  it('drops the previous page argument', () => {
    history.pushState(null, '', '#/users/directory')
    syncRoute()
    expect(route.value).toEqual({ page: 'users', arg: 'directory' })
    history.pushState(null, '', '#/jobs')   // what a router-link does: no hashchange event
    syncRoute()                             // router.afterEach
    expect(route.value).toEqual({ page: 'jobs', arg: '' })
  })
})
