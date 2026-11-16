// Guest bootstrap health: one plain-language status and next step per VM. Input is GET /deployments/{slug}/bootstrap.
import type { BootstrapVm } from './api'

export type BootTone = 'ok' | 'warn' | 'bad' | 'idle'
export interface BootView { key: string; tone: BootTone; label: string; detail: string; next: string }

/** Priority: a replay alarm beats everything, then rate limiting, then the stored state. */
export function bootstrapView(v: BootstrapVm): BootView {
  if (v.replay_alarm) {
    return { key: 'replay', tone: 'bad', label: 'Replay alarm',
      detail: `Someone presented the one-time start-up secret of this VM again (${v.replay_alarm.count} time${v.replay_alarm.count === 1 ? '' : 's'}). It was rejected.`
        + (v.replay_alarm.stopped_deployment ? ' The deployment of this VM was stopped as a precaution.' : ''),
      next: 'Treat the VM as suspect: check who can reach its start-up data (a cloned disk or a leaked template can cause this), delete the VM and deploy it again. Details are in the audit log under "guest.bootstrap".' }
  }
  if (v.rate_limited) {
    return { key: 'limited', tone: 'warn', label: 'Rate-limited',
      detail: 'This VM contacted Office Unbound too often in the last minute, so further attempts are being ignored for a short while.',
      next: 'Wait one minute. If it stays limited, the guest is probably retrying in a loop: check its network and time settings.' }
  }
  switch (v.state) {
    case 'pending': return { key: 'pending', tone: 'warn', label: 'Waiting for the VM to call in',
      detail: v.attempts ? `The VM has not completed its first contact. ${v.attempts} attempt${v.attempts === 1 ? ' was' : 's were'} rejected.` : 'The VM has not contacted Office Unbound yet.',
      next: 'Normal for the first minutes after start. If it takes longer, open the VM console: it needs network access to Office Unbound and the correct time.' }
    case 'reported': return { key: 'reported', tone: 'warn', label: 'Called in, enrolling',
      detail: 'The VM reported in and its management agent is being enrolled.', next: 'Nothing to do. This takes a few seconds.' }
    case 'enrolled': return { key: 'enrolled', tone: 'ok', label: 'Enrolled', detail: 'The VM is enrolled and its start-up secret has been used up.', next: 'Nothing to do.' }
    case 'sealed': return { key: 'sealed', tone: 'ok', label: 'Enrolled and sealed', detail: 'The VM is enrolled and its start-up data was removed from the hypervisor.', next: 'Nothing to do.' }
    case 'expired': return { key: 'expired', tone: 'bad', label: 'Start-up window expired',
      detail: 'The VM did not call in before its one-time secret expired.', next: 'Deploy the VM again to get a new secret. Check network and DNS from the VM to Office Unbound first.' }
    case 'revoked': return { key: 'revoked', tone: 'idle', label: 'Revoked', detail: 'The start-up secret was withdrawn on purpose.', next: 'Deploy the VM again if it is still needed.' }
    case 'failed': return { key: 'failed', tone: 'bad', label: 'Bootstrap failed', detail: 'The VM could not be enrolled safely and its secret was destroyed.',
      next: 'Open the deployment events for the reason, then deploy the VM again.' }
  }
  return { key: 'unknown', tone: 'idle', label: 'Unknown', detail: 'The state is not recognised.', next: 'Refresh the page.' }
}

export function worstTone(vs: BootView[]): BootTone {
  return vs.some((v) => v.tone === 'bad') ? 'bad' : vs.some((v) => v.tone === 'warn') ? 'warn' : vs.length ? 'ok' : 'idle'
}

export function summary(vs: BootView[]): string {
  if (!vs.length) return 'No guest bootstrap records for this deployment.'
  const need = vs.filter((v) => v.tone === 'bad').length, wait = vs.filter((v) => v.tone === 'warn').length
  if (need) return `${need} VM${need === 1 ? ' needs' : 's need'} attention.`
  if (wait) return `${wait} VM${wait === 1 ? ' is' : 's are'} still starting up.`
  return 'All VMs are enrolled.'
}
