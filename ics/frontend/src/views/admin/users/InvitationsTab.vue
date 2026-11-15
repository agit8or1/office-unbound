<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { ApiError, type PlanCreated } from '../../../api'
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
async function copy(u: string) { if (await copyText(cliCommand(u))) { copied.value = u; setTimeout(() => (copied.value = ''), 2000) } }
const revoking = ref<string | null>(null)
const tokenText: Record<string, string> = { not_issued: 'Not issued yet', issued: 'Issued on host', expired: 'Expired', none: 'None' }
</script>
<template>
  <section class="ux-stack">
    <div class="ux-card ux-explain">
      <h2>How an invitation works</h2>
      <ol class="ux-steps">
        <li><strong>Invite.</strong> An administrator invites the person here. The account has no password and no authenticator, so nobody, including the inviter, can sign in as it.</li>
        <li><strong>Issue the one-time token on the host.</strong> For safety the token is never shown in this console or returned by the API. A host operator runs the command below on the ICS server; it prints the token once and it is valid for 24 hours.</li>
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
      <div v-if="done" class="alert ok" role="status"><strong>{{ doneName }}</strong> invited. {{ outcomeText(done) }} Next: issue the one-time token on the host (see below).</div>
    </div>

    <div class="ux-card">
      <div class="ux-scroll">
        <table v-if="invitations.length" class="ux-table">
          <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>One-time token</th><th class="ux-hide-sm">Invited by</th><th class="ux-hide-sm">Invited</th><th><span class="sr">Actions</span></th></tr></thead>
          <tbody>
            <tr v-for="i in invitations" :key="i.id">
              <td><strong>{{ i.username }}</strong></td>
              <td><span class="chip" :class="i.privileged ? 'warn' : 'info'">{{ i.role }}</span></td>
              <td><StatusChip :status="i.status" /></td>
              <td>{{ tokenText[i.token] }}<span v-if="i.token === 'issued'" class="muted"> until {{ fmtTime(i.token_expires_at) }}</span></td>
              <td class="ux-hide-sm">{{ i.invited_by ?? 'host CLI' }}</td>
              <td class="ux-hide-sm">{{ ago(i.invited_at) }}</td>
              <td class="ux-actions">
                <button v-if="i.status !== 'revoked'" class="ghost" @click="copy(i.username)">{{ copied === i.username ? 'Copied' : 'Copy token command' }}</button>
                <button v-if="isAdmin && i.status !== 'revoked'" class="ghost" @click="revoking = i.username">Revoke</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">No pending invitations. Everyone who was invited has enrolled.</p>
      </div>
    </div>
    <div class="ux-card">
      <h2>Command to run on the ICS host</h2>
      <pre class="code mono">{{ cliCommand('USERNAME') }}</pre>
      <p class="muted small">Run it from the ICS install directory as the service user. It also resets an existing person's password and authenticator, so use it for recovery only when you mean to.</p>
    </div>
    <ActionDialog v-if="revoking" title="Revoke invitation" action="user.revoke_invite" :params="{ username: revoking }" confirm-label="Revoke invitation" danger
                  :note="`${revoking} will never be able to enroll, and a one-time token that was already issued stops working.`" @close="revoking = null" @done="emit('changed')" />
  </section>
</template>
