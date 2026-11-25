<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { Store } from '../store'
import type { AppInfo, Backend } from '../api'
import { STATE_LABEL, errorText } from '../api'
const props = defineProps<{ store: Store; api: Backend }>()
const s = props.store.s
const info = ref<AppInfo | null>(null)
const msg = ref('')
const confirmRemove = ref('')
onMounted(async () => {
  try { info.value = await props.api.appInfo() } catch (e) { msg.value = errorText(e) }
})
async function toggleAutostart(e: Event) {
  const on = (e.target as HTMLInputElement).checked
  try { if (info.value) info.value.autostart = await props.api.setAutostart(on) } catch (err) { msg.value = errorText(err) }
}
async function remove(id: string) {
  if (confirmRemove.value !== id) { confirmRemove.value = id; return }
  confirmRemove.value = ''
  await props.store.simple({ type: 'remove_account', account_id: id })
}
</script>
<template>
  <section>
    <header class="pagehead"><h1>Settings</h1></header>
    <h2>Accounts</h2>
    <table class="tbl">
      <thead><tr><th>Organisation</th><th>Account</th><th>Status</th><th></th></tr></thead>
      <tbody>
        <tr v-for="a in s.accounts" :key="a.id">
          <td>{{ a.deployment }}</td><td>{{ a.label }}</td><td><span class="badge" :class="a.state">{{ STATE_LABEL[a.state] }}</span></td>
          <td class="actions">
            <button v-if="a.state !== 'signed_out'" type="button" @click="store.simple({ type: 'sign_out', account_id: a.id })">Sign out</button>
            <button type="button" class="danger" @click="remove(a.id)">{{ confirmRemove === a.id ? 'Confirm remove' : 'Remove' }}</button>
          </td>
        </tr>
      </tbody>
    </table>
    <p class="muted small">Removing an account signs it out and deletes its stored sign-in from this computer. Files you synced stay where they are.</p>
    <button type="button" @click="store.addAccount()">Add another account</button>

    <h2>Startup and background</h2>
    <label class="check"><input type="checkbox" :checked="info?.autostart" @change="toggleAutostart" /> Start Office Unbound when I sign in to Windows (in the tray)</label>
    <label class="check"><input type="checkbox" :checked="s.paused" @change="store.simple({ type: 'set_paused', paused: ($event.target as HTMLInputElement).checked })" /> Pause background activity</label>
    <p class="muted small">Closing the window keeps Office Unbound running in the tray. Use "Quit Office Unbound" in the tray menu to stop it completely.</p>

    <h2>About and diagnostics</h2>
    <dl class="facts" v-if="info">
      <dt>App</dt><dd class="mono">{{ info.version }} (alpha, not code-signed)</dd>
      <dt>Agent</dt><dd class="mono">{{ s.agentVersion || 'not running' }}</dd>
      <dt>Data</dt><dd class="mono">{{ info.data_dir }}</dd>
      <dt>Log</dt><dd class="mono">{{ info.log_file }}</dd>
    </dl>
    <p class="muted small">Logs never contain passwords or tokens. Nothing is sent anywhere unless you send it.</p>
    <p v-if="msg || s.error" class="bad" role="alert">{{ msg || s.error }}</p>
  </section>
</template>
