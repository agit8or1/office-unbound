<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ApiError, post, ROLES, type PlanCreated } from '../api'
import ErrorBox from '../components/ErrorBox.vue'

const inv = reactive({ username: '', role: 'operator' })
const ierr = ref<ApiError | null>(null), iok = ref('')
async function invite() {
  ierr.value = null; iok.value = ''
  try {
    await post('users', { username: inv.username.trim(), role: inv.role })
    iok.value = `Invite created for ${inv.username.trim()}. A host operator must now issue the one-time enrollment token with the ics CLI (issue-enrollment) and hand it over out of band.`
    inv.username = ''
  } catch (e) { ierr.value = e as ApiError }
}
const pl = reactive({ action: 'user.set_role', username: '', role: 'approver' })
const perr = ref<ApiError | null>(null), pok = ref<PlanCreated | null>(null)
async function plan() {
  perr.value = null; pok.value = null
  try {
    pok.value = await post<PlanCreated>('plans', { action: pl.action, params: { username: pl.username.trim(), role: pl.role } })
    pl.username = ''
  } catch (e) { perr.value = e as ApiError }
}
</script>
<template>
  <div class="page">
    <h1>Users</h1>
    <p class="muted">The API has no user list yet, so existing accounts cannot be shown here.</p>
    <div class="cols">
      <form class="panel formgrid" @submit.prevent="invite" aria-labelledby="h1">
        <h2 id="h1">Invite viewer or operator</h2>
        <ErrorBox :error="ierr" />
        <div v-if="iok" class="alert ok" role="status">{{ iok }}</div>
        <label>Username<input v-model="inv.username" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}"></label>
        <label>Role<select v-model="inv.role"><option>viewer</option><option>operator</option></select></label>
        <div><button class="primary">Create invite</button></div>
      </form>
      <form class="panel formgrid" @submit.prevent="plan" aria-labelledby="h2">
        <h2 id="h2">Role change or privileged account (plan)</h2>
        <p class="muted small">High risk: needs two approvers, none of whom you created or elevated. Approver and admin accounts can only be created this way.</p>
        <ErrorBox :error="perr" />
        <div v-if="pok" class="alert ok" role="status">Plan <a :href="'#/plans/' + pok.plan_id" class="mono">{{ pok.plan_id }}</a> created, waiting for approval.</div>
        <label>Action<select v-model="pl.action">
          <option value="user.set_role">Change role of an existing user</option>
          <option value="user.create">Create approver/admin account (invite)</option>
        </select></label>
        <label>Username<input v-model="pl.username" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._@\-]{0,63}"></label>
        <label>Role<select v-model="pl.role"><option v-for="r in ROLES" :key="r">{{ r }}</option></select></label>
        <div><button class="primary">Create plan</button></div>
      </form>
    </div>
  </div>
</template>
