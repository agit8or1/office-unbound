// One submitted plan, from POST /plans to a finished job. Components render `view` and `job`; secrets are in the request body only.
import { computed, onBeforeUnmount, ref } from 'vue'
import { post } from '../../api'
import type { PlanCreated } from '../../api'
import { api, msg, watchRun } from './api'
import { errorText, runView, type JobRow, type PlanRow, type RunView } from './model'

export function useRun() {
  const busy = ref(false)
  const created = ref<(PlanCreated & { customer_approval_id?: string }) | null>(null)
  const plan = ref<PlanRow | null>(null)
  const job = ref<JobRow | null>(null)
  const error = ref('')
  const signal = { aborted: false }
  onBeforeUnmount(() => { signal.aborted = true })
  const view = computed<RunView | null>(() => (created.value ? runView(plan.value, job.value) : null))
  function reset() { created.value = null; plan.value = null; job.value = null; error.value = ''; busy.value = false }
  /** Submit an action and wait for its job. Resolves with the finished job, or null if rejected / not submitted. */
  async function start(action: string, params: Record<string, unknown>): Promise<JobRow | null> {
    reset(); busy.value = true
    try {
      created.value = await api.submit(action, params)
    } catch (e) { error.value = msg(e); busy.value = false; return null }
    const j = await watchRun(created.value, (p, jb) => { plan.value = p; job.value = jb }, signal)
    busy.value = false
    if (j?.status === 'failed') error.value = errorText(j.error)
    return j
  }
  /** Single-admin mode: the requester (an admin) approves their own plan; the server re-checks everything. */
  async function approve(): Promise<void> {
    if (!created.value) return
    error.value = ''
    try { await post(`plans/${created.value.plan_id}/approve`) } catch (e) { error.value = msg(e) }
  }
  return { busy, created, plan, job, error, view, start, reset, approve }
}
export type Run = ReturnType<typeof useRun>
