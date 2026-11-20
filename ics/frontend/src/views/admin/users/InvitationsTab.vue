<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref } from 'vue'
import { ApiError, post, type PlanCreated } from '../../../api'
import { fmtTime, hasRole } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import StatusChip from './StatusChip.vue'
import ActionDialog from './ActionDialog.vue'
import { ago, cliCommand, copyText, outcomeText, submitPlan, USERNAME_RE, type Invitation } from './users'

defineProps<{ invitations: Invitation[] }>()
const emit = defineEmits<{ changed: [] }>()
const isAdmin = computed(() => hasRole('admin'))
const f = reactive({ username: '', role: 'operator' })
const err = ref<ApiError | null>(null), done = ref<PlanCreated | null>(null), doneName = ref(''), busy = ref(false)
const valid = computed(() => USERNAME_RE.test(f.username.trim()))
async function invite() {
  err.value = null; done.value = null; busy.value = true
  try {
    done.value = await submitPlan('user.invite', { username: f.username.trim(), role: f.role })
    doneName.value = f.username.trim(); f.username = ''
    emit('changed')
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
const copied = ref('')
const revoking = ref<string | null>(null)
const tokenText: Record<string, string> = { not_issued: 'Not issued yet', issued: 'Issued', expired: 'Expired', none: 'None' }
// owner 2026-11-20: "yes, show tokens in the console": an admin issues it here after a fresh authenticator code; shown once, audited
const issuing = ref(''), code = ref(''), tokBusy = ref(false), tokErr = ref<ApiError | null>(null)
const shown = ref<{ username: string; token: string; expires_at: string } | null>(null)
const enrollUrl = `${window.location.origin}/ui/#/enroll`
let hideTimer: number | undefined
onBeforeUnmount(() => { shown.value = null; if (hideTimer) window.clearTimeout(hideTimer) })
async function issue() {
  tokBusy.value = true; tokErr.value = null
  try {
    shown.value = await post<{ username: string; token: string; expires_at: string }>(`invitations/${encodeURIComponent(issuing.value)}/token`, { totp_code: code.value.replace(/\s/g, '') })
    issuing.value = ''; emit('changed')
    if (hideTimer) window.clearTimeout(hideTimer)
    hideTimer = window.setTimeout(() => { shown.value = null }, 120000)   // not left on screen; it is never shown again
  } catch (e) { tokErr.value = e as ApiError } finally { tokBusy.value = false; code.value = '' }
}
async function copyTok() { if (shown.value && await copyText(shown.value.token)) { copied.value = 'token'; setTimeout(() => (copied.value = ''), 2000) } }
</script>
<template>
  <section class="ux-stack">
    <div class="ux-card ux-explain">
      <h2>How an invitation works</h2>
      <ol class="ux-steps">
        <li><strong>Invite.</strong> An administrator invites the person here. The account has no password and no authenticator, so nobody, including the inviter, can sign in as it.</li>
        <li><strong>Issue the one-time token.</strong> An administrator presses "Issue token" below and confirms with a fresh authenticator code. The token is shown once (it is never listed again), valid for 24 hours, and recorded in the audit log.</li>
        <li><strong>Hand it over out of band.</strong> Give the token to the person in person or by phone, never by the same channel as the username.</li>
        <li><strong>They enroll themselves.</strong> The person opens the enrollment page, chooses their own password and registers an authenticator app. Only then does the account become Active.</li>
      </ol>
    </div>

    <div v-if="isAdmin" class="ux-card">
      <h2>Invite a viewer or operator</h2>
      <form class="ux-inline-form" @submit.prevent="invite">
        <label>Username<input v-model="f.username" required maxlength="64" autocomplete="off" placeholder="e.g. jsmith"></label>
        <label>Role<select v-model="f.role"><option value="viewer">viewer</option><option value="operator">operator</option></select></label>
        <button class="primary" :disabled="!valid || busy">Create invitation</button>
      </form>
      <p class="muted small">Approver and admin accounts have their own guided approval flow: <a href="#/users/privileged/create">Create a privileged account</a>.</p>
      <ErrorBox :error="err" />
      <div v-if="done" class="alert ok" role="status"><strong>{{ doneName }}</strong> invited. {{ outcomeText(done) }} Next: once the plan is approved, press "Issue token" next to the name below.</div>
    </div>

    <div class="ux-card">
      <div class="ux-scroll" tabindex="0" role="region" aria-label="Scrollable table">
        <table v-if="invitations.length" class="ux-table stack">
          <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>One-time token</th><th class="ux-hide-sm">Invited by</th><th class="ux-hide-sm">Invited</th><th><span class="sr">Actions</span></th></tr></thead>
          <tbody>
            <tr v-for="i in invitations" :key="i.id">
              <td><strong>{{ i.username }}</strong></td>
              <td data-label="Role"><span class="chip" :class="i.privileged ? 'warn' : 'info'">{{ i.role }}</span></td>
              <td data-label="Status"><StatusChip :status="i.status" /></td>
              <td data-label="One-time token">{{ tokenText[i.token] }}<span v-if="i.token === 'issued'" class="muted"> until {{ fmtTime(i.token_expires_at) }}</span></td>
              <td data-label="Invited by" class="ux-hide-sm">{{ i.invited_by ?? 'host CLI' }}</td>
              <td data-label="Invited" class="ux-hide-sm">{{ ago(i.invited_at) }}</td>
              <td class="ux-actions">
                <button v-if="isAdmin && i.status !== 'revoked'" class="ghost" :data-testid="'issue-' + i.username" @click="issuing = i.username; shown = null; tokErr = null">{{ i.token === 'issued' ? 'Issue new token' : 'Issue token' }}</button>
                <button v-if="isAdmin && i.status !== 'revoked'" class="ghost" @click="revoking = i.username">Revoke</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">No pending invitations. Everyone who was invited has enrolled.</p>
      </div>
    </div>
    <div v-if="issuing" class="ux-card" data-testid="issue-token">
      <h2>Issue the one-time token for {{ issuing }}</h2>
      <form class="ux-inline-form" @submit.prevent="issue">
        <label>Your authenticator code<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8" placeholder="123456"></label>
        <button class="primary" :disabled="tokBusy">{{ tokBusy ? 'Issuing…' : 'Issue token' }}</button>
        <button type="button" class="ghost" @click="issuing = ''">Cancel</button>
      </form>
      <p class="muted small">A new code from your authenticator app (not the one you signed in with). A token issued earlier for this person stops working.</p>
      <ErrorBox :error="tokErr" />
    </div>
    <div v-if="shown" class="ux-card alert ok" role="status" data-testid="token-shown">
      <h2>One-time token for {{ shown.username }}</h2>
      <p><code class="mono">{{ shown.token }}</code> <button class="ghost" @click="copyTok">{{ copied === 'token' ? 'Copied' : 'Copy' }}</button></p>
      <p class="small">Give it to {{ shown.username }} by a different channel than the username (in person or by phone). They open <a :href="enrollUrl">{{ enrollUrl }}</a>,
        enter the username and this token, choose a password and register an authenticator. Valid until {{ fmtTime(shown.expires_at) }}. It is hidden after 2 minutes and not shown again.</p>
      <button class="ghost" @click="shown = null">Done, hide it</button>
    </div>
    <div class="ux-card">
      <h2>Recovery on the ICS host</h2>
      <pre class="code mono">{{ cliCommand('USERNAME') }}</pre>
      <p class="muted small">Run it from the ICS install directory as the service user. For recovery only: it also resets an existing person's password and authenticator (the console issues tokens only for people who have not enrolled yet).</p>
    </div>
    <ActionDialog v-if="revoking" title="Revoke invitation" action="user.revoke_invite" :params="{ username: revoking }" confirm-label="Revoke invitation" danger
                  :note="`${revoking} will never be able to enroll, and a one-time token that was already issued stops working.`" @close="revoking = null" @done="emit('changed')" />
  </section>
</template>
