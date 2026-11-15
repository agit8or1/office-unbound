<script setup lang="ts">
// Users & roles: directory, invitations, privileged access, roles & permissions, access policies.
// Sub-routes live in the hash arg: users/<tab>[/<id|mode>[/<username>]] (e.g. #/users/directory/<uuid>, #/users/privileged/grant).
import { computed } from 'vue'
import { get } from '../../../api'
import { go, route, useLoad } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import DirectoryTab from './DirectoryTab.vue'
import InvitationsTab from './InvitationsTab.vue'
import PrivilegedTab from './PrivilegedTab.vue'
import PrivilegedWorkflow from './PrivilegedWorkflow.vue'
import RolesTab from './RolesTab.vue'
import PoliciesTab from './PoliciesTab.vue'
import UserDrawer from './UserDrawer.vue'
import type { DirUser, Invitation } from './users'
import './users.css'

const TABS = [
  { id: 'directory', label: 'Directory' }, { id: 'invitations', label: 'Invitations' }, { id: 'privileged', label: 'Privileged access' },
  { id: 'roles', label: 'Roles & permissions' }, { id: 'policies', label: 'Access policies' },
]
const parts = computed(() => route.value.arg.split('/'))
const tab = computed(() => (TABS.some((t) => t.id === parts.value[0]) ? parts.value[0] : 'directory'))
const sub = computed(() => parts.value[1] ?? '')
const subName = computed(() => decodeURIComponent(parts.value[2] ?? ''))

const users = useLoad(() => get<DirUser[]>('users'), 30000)
const invites = useLoad(() => get<Invitation[]>('invitations'))
const pendingInv = computed(() => (invites.data.value ?? []).filter((i) => i.status === 'pending').length)
const workflow = computed(() => (tab.value === 'privileged' && ['grant', 'create', 'change'].includes(sub.value) ? (sub.value as 'grant' | 'create' | 'change') : null))
const refresh = () => { void users.reload(); void invites.reload() }
</script>
<template>
  <div class="page ux">
    <div class="head"><h1>Users &amp; roles</h1><span class="muted small">Who can sign in, what they can do, and how access is granted</span></div>
    <nav class="ux-tabs" aria-label="Users and roles sections">
      <a v-for="t in TABS" :key="t.id" :href="'#/users/' + t.id" :aria-current="tab === t.id ? 'page' : undefined" @click.prevent="go('users', t.id)">
        {{ t.label }}<span v-if="t.id === 'invitations' && pendingInv" class="ux-n">{{ pendingInv }}</span></a>
    </nav>
    <ErrorBox :error="users.error.value" />
    <p v-if="!users.data.value && !users.error.value" class="muted" role="status">Loading users…</p>
    <template v-if="users.data.value">
      <DirectoryTab v-if="tab === 'directory'" :users="users.data.value" :selected="sub" @changed="refresh" />
      <InvitationsTab v-else-if="tab === 'invitations'" :invitations="invites.data.value ?? []" @changed="refresh" />
      <PrivilegedWorkflow v-else-if="workflow" :key="workflow + subName" :mode="workflow" :preset="subName" :users="users.data.value" />
      <PrivilegedTab v-else-if="tab === 'privileged'" :users="users.data.value" />
      <RolesTab v-else-if="tab === 'roles'" :users="users.data.value" />
      <PoliciesTab v-else />
      <UserDrawer v-if="tab === 'directory' && sub" :id="sub" :key="sub" />
    </template>
  </div>
</template>
