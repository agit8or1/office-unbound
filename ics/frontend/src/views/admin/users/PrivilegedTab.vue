<script setup lang="ts">
import { computed } from 'vue'
import { get, type Plan } from '../../../api'
import { hasRole, useLoad } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import StatusChip from './StatusChip.vue'
import { ago, type DirUser } from './users'

const props = defineProps<{ users: DirUser[] }>()
const isAdmin = computed(() => hasRole('admin'))
const priv = computed(() => props.users.filter((u) => u.privileged))
const plans = useLoad(() => get<Plan[]>('plans?status=pending_approval'), 15000)
const pending = computed(() => (plans.data.value ?? []).filter((p) => p.action.startsWith('user.') && p.status === 'pending_approval'))
const LABEL: Record<string, string> = { 'user.set_role': 'Role change', 'user.invite': 'New account', 'user.create': 'New account', 'user.disable': 'Disable', 'user.enable': 'Enable' }
</script>
<template>
  <section class="ux-stack">
    <div class="ux-card ux-explain">
      <div class="ux-split-head">
        <div><h2>Privileged access</h2>
          <p class="muted">Approvers and admins can approve changes to infrastructure and to other people's access. Every grant is a high-risk plan with a written justification, two approvers, and a permanent record of who granted it.</p></div>
        <div v-if="isAdmin" class="row">
          <a class="ux-btn primary" href="#/users/privileged/grant">Grant privileged role</a>
          <a class="ux-btn" href="#/users/privileged/create">Create privileged account</a>
        </div>
      </div>
      <p v-if="!isAdmin" class="muted small">Only administrators can request privileged access changes.</p>
    </div>
    <div class="ux-card">
      <h2 class="ux-pad">Privileged accounts <span class="chip info">{{ priv.length }}</span></h2>
      <div class="ux-scroll" tabindex="0" role="region" aria-label="Scrollable table">
        <table v-if="priv.length" class="ux-table stack">
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Role granted by</th><th class="ux-hide-sm">Created by</th><th>Last sign-in</th></tr></thead>
          <tbody><tr v-for="u in priv" :key="u.id">
            <td><a :href="'#/users/directory/' + u.id"><strong>{{ u.username }}</strong></a></td>
            <td data-label="Role"><span class="chip warn">{{ u.role }}</span></td><td data-label="Status"><StatusChip :status="u.status" /></td>
            <td data-label="Role granted by">{{ u.role_set_by ?? 'host CLI (bootstrap)' }}</td><td class="ux-hide-sm" data-label="Created by">{{ u.created_by ?? 'host CLI' }}</td><td data-label="Last sign-in">{{ ago(u.last_login_at) }}</td>
          </tr></tbody>
        </table>
        <p v-else class="empty">No privileged accounts yet.</p>
      </div>
    </div>
    <div class="ux-card">
      <h2 class="ux-pad">Waiting for approval <span class="chip info">{{ pending.length }}</span></h2>
      <ErrorBox :error="plans.error.value" />
      <ul v-if="pending.length" class="plain ux-pad">
        <li v-for="p in pending" :key="p.id"><a :href="'#/plans/' + p.id">{{ LABEL[p.action] ?? p.action }}: <strong>{{ p.params.username }}</strong></a>
          <span v-if="p.params.role"> to {{ p.params.role }}</span> <span class="chip warn">{{ p.risk }} risk</span>
          <span class="muted"> requested by {{ p.requested_by_username ?? '?' }}, {{ p.approval_count ?? 0 }} of {{ p.approvals_required ?? 2 }} approvals</span></li>
      </ul>
      <p v-else class="empty">No user-management plans are waiting.</p>
    </div>
  </section>
</template>
