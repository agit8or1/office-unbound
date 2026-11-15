<script setup lang="ts">
import { computed, ref } from 'vue'
import { ROLES, type Role } from '../../../api'
import { fmtTime, go, hasRole, session } from '../../../store'
import StatusChip from './StatusChip.vue'
import ActionDialog from './ActionDialog.vue'
import { ago, type DirUser, type UserStatus } from './users'

const props = defineProps<{ users: DirUser[]; selected: string }>()
const emit = defineEmits<{ changed: [] }>()
const q = ref(''), role = ref<Role | ''>(''), status = ref<UserStatus | ''>('')
const isAdmin = computed(() => hasRole('admin'))
const STATUSES: UserStatus[] = ['active', 'invited', 'locked', 'disabled', 'revoked']
const counts = computed(() => Object.fromEntries(STATUSES.map((s) => [s, props.users.filter((u) => u.status === s).length])))
const rows = computed(() => props.users.filter((u) =>
  (!status.value || u.status === status.value) && (!role.value || u.role === role.value) &&
  (!q.value.trim() || u.username.toLowerCase().includes(q.value.trim().toLowerCase()))))

interface Dlg { title: string; action: string; params: Record<string, unknown>; confirmLabel: string; danger?: boolean; note: string }
const dlg = ref<Dlg | null>(null)
const me = computed(() => session.user?.username)
function ask(u: DirUser, kind: 'disable' | 'enable' | 'sessions' | 'revoke') {
  const hi = u.privileged
  dlg.value = {
    disable: { title: `Disable ${u.username}`, action: 'user.disable', params: { username: u.username }, confirmLabel: 'Request disable', danger: true,
      note: `Ends all of their sessions and blocks sign-in. ${hi ? 'This is a privileged account, so the request needs two approvers.' : 'Needs one approver other than you.'}` },
    enable: { title: `Enable ${u.username}`, action: 'user.enable', params: { username: u.username }, confirmLabel: 'Request enable',
      note: `Lets the account sign in again with its existing password and authenticator. ${hi ? 'Privileged account: two approvers.' : 'Needs one approver other than you.'}` },
    sessions: { title: `Revoke sessions of ${u.username}`, action: 'user.revoke_sessions', params: { username: u.username }, confirmLabel: 'Revoke sessions', danger: true,
      note: 'Signs them out everywhere right away. They can sign in again. Needs no approval.' },
    revoke: { title: `Revoke invitation for ${u.username}`, action: 'user.revoke_invite', params: { username: u.username }, confirmLabel: 'Revoke invitation', danger: true,
      note: 'The account can never be enrolled and any one-time token already issued stops working.' },
  }[kind]
}
const open = (u: DirUser) => go('users', 'directory/' + u.id)
function onDone() { emit('changed') }
</script>
<template>
  <section class="ux-stack">
    <div class="ux-toolbar">
      <label class="ux-search"><span class="sr">Search users</span>
        <input v-model="q" type="search" placeholder="Search by username" autocomplete="off"></label>
      <label class="inline"><span class="sr">Role</span>
        <select v-model="role" aria-label="Filter by role"><option value="">All roles</option><option v-for="r in ROLES" :key="r" :value="r">{{ r }}</option></select></label>
      <div class="ux-chips" role="group" aria-label="Filter by status">
        <button :aria-pressed="status === ''" @click="status = ''">All <span class="ux-n">{{ users.length }}</span></button>
        <button v-for="s in STATUSES" :key="s" :aria-pressed="status === s" :disabled="!counts[s]" @click="status = status === s ? '' : s">
          <span style="text-transform: capitalize">{{ s }}</span> <span class="ux-n">{{ counts[s] }}</span></button>
      </div>
    </div>
    <div class="ux-card">
      <div class="ux-scroll">
        <table v-if="rows.length" class="ux-table">
          <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th class="ux-hide-sm">MFA</th><th class="ux-hide-sm">Sessions</th><th class="ux-hide-sm">Created by</th><th><span class="sr">Actions</span></th></tr></thead>
          <tbody>
            <tr v-for="u in rows" :key="u.id" :class="{ sel: u.id === selected }">
              <td><a :href="'#/users/directory/' + u.id" class="ux-user" @click.prevent="open(u)"><strong>{{ u.username }}</strong></a>
                <span v-if="u.username === me" class="ux-you">you</span>
                <span v-if="u.pending_plans" class="chip warn" title="Plans waiting for approval">{{ u.pending_plans }} pending</span></td>
              <td><span class="chip" :class="u.privileged ? 'warn' : 'info'">{{ u.role }}</span></td>
              <td><StatusChip :status="u.status" /></td>
              <td :title="fmtTime(u.last_login_at)">{{ ago(u.last_login_at) }}<span v-if="u.last_login_ip" class="muted mono"> {{ u.last_login_ip }}</span></td>
              <td class="ux-hide-sm">{{ u.mfa_enrolled ? 'Enrolled' : 'Not enrolled' }}</td>
              <td class="ux-hide-sm">{{ u.active_sessions }}</td>
              <td class="ux-hide-sm">{{ u.created_by ?? 'host CLI' }}</td>
              <td class="ux-actions">
                <template v-if="isAdmin && u.username !== me">
                  <button v-if="u.status === 'active' || u.status === 'locked'" class="ghost" @click="ask(u, 'disable')">Disable</button>
                  <button v-if="u.status === 'disabled'" class="ghost" @click="ask(u, 'enable')">Enable</button>
                  <button v-if="u.active_sessions" class="ghost" @click="ask(u, 'sessions')">Revoke sessions</button>
                  <button v-if="u.status === 'invited'" class="ghost" @click="ask(u, 'revoke')">Revoke invite</button>
                  <a v-if="u.status !== 'invited' && u.status !== 'revoked'" class="ux-btn" :href="'#/users/privileged/change/' + u.username">Change role</a>
                </template>
                <button class="ghost" :aria-label="'Details for ' + u.username" @click="open(u)">Details</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">No users match these filters.</p>
      </div>
    </div>
    <p v-if="!isAdmin" class="muted small">Account changes can be requested by administrators. You can browse the directory and see who holds which role.</p>
    <ActionDialog v-if="dlg" v-bind="dlg" @close="dlg = null" @done="onDone" />
  </section>
</template>
