<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ApiError, get } from '../../../api'
import { fmtTime, go, hasRole } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import StatusChip from './StatusChip.vue'
import { ACTION_LABEL, ago, cliCommand, copyText, type UserDetail } from './users'

const props = defineProps<{ id: string }>()
const d = ref<UserDetail | null>(null), err = ref<ApiError | null>(null), copied = ref(false)
const isAdmin = computed(() => hasRole('admin'))
async function load() {
  d.value = null; err.value = null
  try { d.value = await get<UserDetail>(`users/${props.id}`) } catch (e) { err.value = e as ApiError }
}
onMounted(load)
watch(() => props.id, load)
const signins = computed(() => (d.value?.recent_events ?? []).filter((e) => e.action.startsWith('auth.')).slice(0, 8))
const changes = computed(() => (d.value?.recent_events ?? []).filter((e) => e.action.startsWith('user.')).slice(0, 8))
async function copy() { if (d.value) { copied.value = await copyText(cliCommand(d.value.username)); setTimeout(() => (copied.value = false), 2000) } }
</script>
<template>
  <div class="ux-drawer-wrap">
    <div class="ux-scrim" @click="go('users', 'directory')"></div>
    <aside class="ux-drawer" role="dialog" aria-modal="true" :aria-label="d ? 'User ' + d.username : 'User details'">
      <header class="ux-drawer-head">
        <div><h2>{{ d?.username ?? 'User' }}</h2><div v-if="d" class="row"><StatusChip :status="d.status" /><span class="chip" :class="d.privileged ? 'warn' : 'info'">{{ d.role }}</span></div></div>
        <button class="ghost" @click="go('users', 'directory')">Close</button>
      </header>
      <ErrorBox :error="err" />
      <p v-if="!d && !err" class="muted">Loading…</p>
      <div v-if="d" class="ux-drawer-body">
        <dl class="kv">
          <dt>Created by</dt><dd>{{ d.created_by ?? 'host CLI (bootstrap)' }} <span class="muted">{{ fmtTime(d.created_at) }}</span></dd>
          <dt>Role set by</dt><dd>{{ d.role_set_by ?? '-' }} <span v-if="d.role_set_at" class="muted">{{ fmtTime(d.role_set_at) }}</span></dd>
          <dt>Last sign-in</dt><dd>{{ ago(d.last_login_at) }}<span v-if="d.last_login_ip" class="mono muted"> from {{ d.last_login_ip }}</span></dd>
          <dt>MFA</dt><dd>{{ d.mfa_enrolled ? 'Authenticator enrolled (required)' : 'Not enrolled yet' }}</dd>
          <dt>Active sessions</dt><dd>{{ d.active_sessions }}</dd>
        </dl>

        <div v-if="d.status === 'invited'" class="alert info">
          <strong>Waiting for enrollment.</strong> This account has no credentials. A host operator issues a one-time token on the ICS host and hands it over out of band:
          <pre class="code mono">{{ cliCommand(d.username) }}</pre>
          <button class="ghost" @click="copy">{{ copied ? 'Copied' : 'Copy command' }}</button>
        </div>

        <h3>Pending plans</h3>
        <ul v-if="d.pending_plans_detail.length" class="plain">
          <li v-for="p in d.pending_plans_detail" :key="p.id"><a :href="'#/plans/' + p.id" class="mono">{{ p.action }}</a> <span class="chip warn">{{ p.risk }}</span> <span class="muted">{{ ago(p.created_at) }}</span></li>
        </ul>
        <p v-else class="muted small">Nothing waiting for approval.</p>

        <h3>Sessions</h3>
        <template v-if="isAdmin">
          <ul v-if="d.sessions?.length" class="plain">
            <li v-for="(s, i) in d.sessions" :key="i">Signed in {{ ago(s.created_at) }}, last active {{ ago(s.last_seen) }}, expires {{ fmtTime(s.expires_at) }}</li>
          </ul>
          <p v-else class="muted small">No active sessions.</p>
        </template>
        <p v-else class="muted small">{{ d.active_sessions }} active. Session details are visible to administrators.</p>

        <h3>Recent sign-ins</h3>
        <ul v-if="signins.length" class="plain ux-events">
          <li v-for="(e, i) in signins" :key="i"><span :class="e.action === 'auth.login_failed' ? 'chip warn' : 'chip info'">{{ ACTION_LABEL[e.action] ?? e.action }}</span>
            {{ ago(e.at) }}<span v-if="e.ip" class="mono muted"> {{ e.ip }}</span><span v-if="e.reason" class="muted"> ({{ e.reason.replace('_', ' ') }})</span></li>
        </ul>
        <p v-else class="muted small">No sign-ins recorded.</p>

        <h3>Role history</h3>
        <ol class="ux-timeline">
          <li v-for="(h, i) in d.role_history" :key="i">
            <strong>{{ h.kind === 'invited' ? 'Invited as ' + h.role : (h.previous_role ?? '?') + ' to ' + h.role }}</strong>
            <span class="muted"> by {{ h.by ?? 'host CLI' }}, {{ fmtTime(h.at) }}</span>
            <div v-if="h.justification" class="small">Justification: {{ h.justification }}</div>
            <a v-if="h.plan_id" class="small" :href="'#/plans/' + h.plan_id">View plan</a>
          </li>
        </ol>

        <h3>Account changes</h3>
        <ul v-if="changes.length" class="plain"><li v-for="(e, i) in changes" :key="i">{{ ACTION_LABEL[e.action] ?? e.action }} <span class="muted">{{ ago(e.at) }}</span></li></ul>
        <p v-else class="muted small">None recorded.</p>

        <div v-if="isAdmin && d.status !== 'invited' && d.status !== 'revoked'" class="row">
          <a class="ux-btn" :href="'#/users/privileged/change/' + d.username">Change role…</a>
        </div>
      </div>
    </aside>
  </div>
</template>
