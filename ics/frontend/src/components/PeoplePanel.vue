<script setup lang="ts">
// People of one deployment: read live from its directory; add an administrator or a user, change a password or role, lock/unlock, delete.
// Every change is a typed, audited action (directory.account.set / .lock / .delete). Owner 2026-11-20: "I should be able to create tenant(s)
// admin accounts from the console ... those accounts can login and do admin functions and also use like a regular account".
import { computed, ref } from 'vue'
import { get, type ApiError } from '../api'
import { useLoad } from '../store'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import ErrorBox from './ErrorBox.vue'
import RunPanel from '../views/providers/RunPanel.vue'
import { useRun } from '../views/providers/run'

interface Person { username: string; email: string; name: string; role: 'admin' | 'user' | 'none'; locked: boolean; system: boolean }
interface People { available: boolean; reason: string | null; deployment: string; domain: string | null; people: Person[]; truncated: boolean }
const props = defineProps<{ slug: string }>()
const enc = encodeURIComponent(props.slug)
const err = ref<ApiError | null>(null)
const data = useLoad(async () => { try { err.value = null; return await get<People>(`deployments/${enc}/people`) } catch (e) { err.value = e as ApiError; return null } }, 0)

const form = ref({ username: '', name: '', role: 'admin' as 'admin' | 'user', password: '' })
const editing = ref(false)
const pwOk = computed(() => /^[A-Za-z0-9_-]{8,128}$/.test(form.value.password))
const userOk = computed(() => /^[a-z][a-z0-9.-]{0,30}[a-z0-9]$/.test(form.value.username))
const nameOk = computed(() => !form.value.name || (form.value.name.length <= 61 && form.value.name.split(/\s+(.*)/s).filter(Boolean).every((x) => /^[A-Za-z][A-Za-z .'-]{0,62}$/.test(x))))
const run = useRun()
const what = ref('')
async function save() {
  if (!pwOk.value || !userOk.value || !nameOk.value) return
  what.value = (editing.value ? 'Updating ' : 'Adding ') + form.value.username
  await run.start('directory.account.set', { deployment: props.slug, username: form.value.username, password: form.value.password, role: form.value.role,
    ...(form.value.name ? { display_name: form.value.name } : {}) })
  form.value.password = ''
  void data.reload()
}
function edit(p: Person) { editing.value = true; form.value = { username: p.username, name: p.name, role: p.role === 'admin' ? 'admin' : 'user', password: '' } }
function reset() { editing.value = false; form.value = { username: '', name: '', role: 'admin', password: '' } }
async function lock(p: Person) { what.value = (p.locked ? 'Unlocking ' : 'Locking ') + p.username; await run.start('directory.account.lock', { deployment: props.slug, username: p.username, locked: !p.locked }); void data.reload() }
async function remove(p: Person) {
  if (!window.confirm(`Delete ${p.username}? They can no longer sign in; their mailbox content is kept but becomes unreachable.`)) return
  what.value = 'Deleting ' + p.username; await run.start('directory.account.delete', { deployment: props.slug, username: p.username }); void data.reload()
}
const ROLE: Record<string, string> = { admin: 'Administrator', user: 'User', none: 'No access groups' }
</script>
<template>
  <Card title="People" :hint="data.data.value?.available ? `${data.data.value.people.length} in ${data.data.value.domain}` : 'From the deployment directory'" flush data-testid="people-panel">
    <template #actions><Button size="sm" variant="ghost" @click="data.reload()">Refresh</Button></template>
    <ErrorBox :error="err" />
    <p v-if="data.data.value && !data.data.value.available" class="muted small pad" data-testid="people-unavailable">{{ data.data.value.reason }}
      People can be managed once the deployment's identity VM answers (deployments created before 0.8.0 need recreating).</p>
    <table v-if="data.data.value?.people.length" class="dense"><thead><tr><th>User</th><th>Name</th><th>Role</th><th>Status</th><th></th></tr></thead>
      <tbody><tr v-for="p in data.data.value.people" :key="p.username">
        <td><b>{{ p.username }}</b><div class="muted small">{{ p.email }}</div></td>
        <td>{{ p.name }}</td>
        <td>{{ ROLE[p.role] }}<span v-if="p.system" class="muted small"> (deployment administrator)</span></td>
        <td><StatusBadge :s="p.locked ? 'warning' : 'ok'" :text="p.locked ? 'Locked' : 'Active'" /></td>
        <td class="pp-act">
          <template v-if="!p.system">
            <Button size="sm" variant="ghost" @click="edit(p)">Change</Button>
            <Button size="sm" variant="ghost" @click="lock(p)">{{ p.locked ? 'Unlock' : 'Lock' }}</Button>
            <Button size="sm" variant="ghost" @click="remove(p)">Delete</Button>
          </template>
          <span v-else class="muted small">Password under "Open your apps"</span>
        </td>
      </tr></tbody></table>
    <p v-else-if="data.data.value?.available" class="muted small pad">No people yet.</p>
    <form v-if="data.data.value?.available" class="pp-form pad" @submit.prevent="save">
      <h4>{{ editing ? 'Change ' + form.username : 'Add a person' }}</h4>
      <label class="small">User name<input v-model.trim="form.username" :disabled="editing" autocomplete="off" placeholder="jane"></label>
      <label class="small">Full name<input v-model.trim="form.name" autocomplete="off" placeholder="Jane Doe"></label>
      <label class="small">Role
        <select v-model="form.role"><option value="admin">Administrator (manages the organisation; also uses mail, files, documents)</option>
          <option value="user">User (mail, files, documents)</option></select></label>
      <label class="small">Password<input v-model="form.password" type="password" autocomplete="new-password" minlength="8" maxlength="128"></label>
      <Button size="sm" type="submit" :disabled="!pwOk || !userOk || !nameOk" :loading="run.busy.value">{{ editing ? 'Save' : 'Add person' }}</Button>
      <Button v-if="editing" size="sm" variant="ghost" type="button" @click="reset">Cancel</Button>
      <p class="muted small">Signs in as {{ form.username || 'name' }}@{{ data.data.value?.domain ?? 'domain' }} at the portal; gets a mailbox. Password: at least 8 characters, letters, digits, - and _. Changes need approval and are recorded in the audit log.</p>
    </form>
    <div class="pad"><RunPanel v-if="run.created.value" :run="run" :what="what" /></div>
  </Card>
</template>
<style scoped>
.pad { padding: 4px 16px 12px; } .pp-act { white-space: nowrap; text-align: right; }
.pp-form { display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: end; border-top: 1px solid var(--line); margin-top: 6px; }
.pp-form h4 { width: 100%; margin: 10px 0 0; font-size: 14px; }
.pp-form label { display: grid; gap: 2px; } .pp-form input { width: 12em; } .pp-form select { max-width: 26em; }
.pp-form p { width: 100%; margin: 4px 0 0; }
</style>
