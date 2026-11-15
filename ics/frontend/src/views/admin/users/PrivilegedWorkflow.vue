<script setup lang="ts">
// Guided approval workflow for privileged access: grant a role to an existing user, change a role, or create a privileged account.
// Final step submits ONE high-risk plan (user.set_role or user.invite) with the justification inside the approved params.
import { computed, ref } from 'vue'
import { ApiError, get, ROLES, type PlanCreated, type Role } from '../../../api'
import { go, session, useLoad } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import { PRIVILEGED, submitPlan, USERNAME_RE, type DirUser, type Policy } from './users'

const props = defineProps<{ mode: 'grant' | 'create' | 'change'; preset: string; users: DirUser[] }>()
const policy = useLoad(() => get<Policy>('access-policy'))
const need = computed(() => policy.data.value?.approvals.find((a) => a.risk === 'high')?.required ?? 2)

const step = ref(1)
const username = ref(props.preset)
const role = ref<Role>(props.mode === 'change' ? 'operator' : 'approver')
const justification = ref('')
const ack = ref(false), busy = ref(false), err = ref<ApiError | null>(null), result = ref<PlanCreated | null>(null)

const me = computed(() => session.user?.username)
const candidates = computed(() => props.users.filter((u) => u.username !== me.value && (u.status === 'active' || u.status === 'locked' || u.status === 'invited')))
const target = computed(() => props.users.find((u) => u.username === username.value) ?? null)
const roleChoices = computed<Role[]>(() => props.mode === 'change' ? ROLES.filter((r) => r !== target.value?.role) : PRIVILEGED.filter((r) => r !== target.value?.role))
const grants = computed(() => PRIVILEGED.includes(role.value))
const title = computed(() => ({ grant: 'Grant privileged role', create: 'Create privileged account', change: 'Change role' }[props.mode]))
const create = computed(() => props.mode === 'create')
const nameOk = computed(() => (create.value ? USERNAME_RE.test(username.value.trim()) : !!target.value))
const reasonOk = computed(() => justification.value.trim().length >= 10)
const steps = ['Who', 'Role and reason', 'Review', 'Submitted']
function next() { if (!roleChoices.value.includes(role.value)) role.value = roleChoices.value[0]; step.value = 2 }
async function submit() {
  busy.value = true; err.value = null
  const name = username.value.trim()
  try {
    result.value = create.value
      ? await submitPlan('user.invite', { username: name, role: role.value, justification: justification.value.trim() })
      : await submitPlan('user.set_role', { username: name, role: role.value, justification: justification.value.trim() })
    step.value = 4
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <section class="ux-stack">
    <div class="ux-card">
      <div class="ux-split-head"><h2>{{ title }}</h2><button class="ghost" @click="go('users', 'privileged')">Cancel</button></div>
      <ol class="ux-stepper" aria-label="Progress">
        <li v-for="(s, i) in steps" :key="s" :aria-current="step === i + 1 ? 'step' : undefined" :class="{ done: step > i + 1 }"><span class="ux-dot">{{ i + 1 }}</span> {{ s }}</li>
      </ol>

      <div v-if="step === 1" class="ux-form">
        <template v-if="create">
          <label>Username for the new account
            <input v-model="username" maxlength="64" autocomplete="off" placeholder="e.g. jsmith" aria-describedby="uhelp"></label>
          <p id="uhelp" class="muted small">Letters, digits and . _ @ -. The account is created without any credentials; the person sets their own after you and two approvers are done.</p>
        </template>
        <template v-else>
          <label>Account
            <select v-model="username"><option value="" disabled>Choose a user…</option>
              <option v-for="u in candidates" :key="u.id" :value="u.username">{{ u.username }} (currently {{ u.role }})</option></select></label>
          <p v-if="target" class="muted small">{{ target.username }} is {{ target.status }} with role {{ target.role }}{{ target.role_set_by ? ', set by ' + target.role_set_by : '' }}.</p>
        </template>
        <div class="row end"><button class="primary" :disabled="!nameOk" @click="next">Continue</button></div>
      </div>

      <div v-if="step === 2" class="ux-form">
        <fieldset class="ux-roles"><legend>{{ mode === 'create' ? 'Role of the new account' : 'New role' }}</legend>
          <label v-for="r in roleChoices" :key="r" class="inline ux-radio">
            <input v-model="role" type="radio" :value="r" name="role"> <strong>{{ r }}</strong>
            <span class="muted small">{{ policy.data.value?.roles.find((x) => x.role === r)?.summary }}</span></label>
        </fieldset>
        <label>Justification (required, shown to the approvers and kept in the audit log)
          <textarea v-model="justification" rows="3" maxlength="500" placeholder="Why does this person need this access, and for how long?"></textarea></label>
        <p class="small" :class="reasonOk ? 'muted' : ''">{{ justification.trim().length }}/500, at least 10 characters.</p>
        <div class="row end"><button class="ghost" @click="step = 1">Back</button><button class="primary" :disabled="!reasonOk || (mode !== 'change' && !PRIVILEGED.includes(role))" @click="step = 3">Review</button></div>
      </div>

      <div v-if="step === 3" class="ux-form">
        <dl class="kv ux-review">
          <dt>Action</dt><dd>{{ create ? 'Create account' : 'Change role' }} <strong>{{ username.trim() }}</strong></dd>
          <dt>Role</dt><dd><span v-if="target">{{ target.role }} → </span><strong>{{ role }}</strong></dd>
          <dt>Risk</dt><dd><span class="chip warn">high</span></dd>
          <dt>Justification</dt><dd class="wrap">{{ justification.trim() }}</dd>
        </dl>
        <div class="alert warn ux-rules">
          <strong>What happens next</strong>
          <ol>
            <li>Nothing changes now. A plan is created and recorded with your name and the justification above.</li>
            <li><strong>{{ need }} approvers</strong> must approve it. You cannot approve your own plan, and neither can anyone you created or elevated.</li>
            <li v-if="create">After approval the account exists <strong>without credentials</strong>. A host operator issues a one-time token (Invitations tab); the person then chooses their own password and authenticator.</li>
            <li v-else>After approval the role changes immediately on the next job run{{ grants ? '' : ', and any elevated rights are removed' }}.</li>
          </ol>
        </div>
        <div v-if="grants" class="alert info ux-rules">
          <strong>Provenance rule.</strong> You will be recorded as the person who {{ create ? 'created' : 'elevated' }} <strong>{{ username.trim() }}</strong>.
          As an {{ role }} they will never be able to approve plans that <em>you</em> request. This stops one admin from creating their own approvers.
        </div>
        <label class="inline"><input v-model="ack" type="checkbox"> I understand that this grants {{ role }} access and needs {{ need }} independent approvals.</label>
        <ErrorBox :error="err" />
        <div class="row end"><button class="ghost" @click="step = 2">Back</button>
          <button class="primary" :disabled="!ack || busy" @click="submit">{{ busy ? 'Submitting…' : 'Submit for approval' }}</button></div>
      </div>

      <div v-if="step === 4 && result" class="ux-form">
        <div class="alert ok" role="status"><strong>Submitted.</strong> Plan <span class="mono">{{ result.plan_id.slice(0, 8) }}</span> is waiting for {{ result.approvals_required }} approvals.</div>
        <p>Ask two approvers (not you, and not anyone you created or elevated) to open the plan in Approvals and approve it.</p>
        <div class="row">
          <a class="ux-btn primary" :href="'#/plans/' + result.plan_id">Open in Approvals</a>
          <button class="ghost" @click="go('users', 'directory')">Back to directory</button>
        </div>
      </div>
    </div>
  </section>
</template>
