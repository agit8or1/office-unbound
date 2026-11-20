<script setup lang="ts">
// Open your apps: links to a deployment's applications, hosts-file lines (until public DNS exists), the deployment CA certificate and the
// administrator's sign-in. The password is shown only after a fresh authenticator code and is never kept in the page longer than asked.
import { computed, onBeforeUnmount, ref } from 'vue'
import { get, post, type ApiError } from '../api'
import { useLoad } from '../store'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import ErrorBox from './ErrorBox.vue'

interface App { id: string; title: string; url: string; description: string }
interface Access {
  deployment: string; ready: boolean; domain?: string; apps: App[]; hosts: { address: string; names: string[] }[]
  clients: { imap: { host: string; port: number; security: string }; smtp: { host: string; port: number; security: string }; activesync: string; caldav: string } | null
  ca_pem: string | null; admin: { username: string; email: string; password_available: boolean } | null; note?: string
}
const props = defineProps<{ slug: string }>()
const enc = encodeURIComponent(props.slug)
const data = useLoad(() => get<Access>(`deployments/${enc}/access`).catch(() => null), 30000)
const a = computed(() => data.data.value)
const hostsText = computed(() => (a.value?.hosts ?? []).map((h) => `${h.address}  ${h.names.join(' ')}`).join('\n'))

const code = ref(''), busy = ref(false), err = ref<ApiError | null>(null), pw = ref(''), copied = ref('')
let timer: number | undefined
async function reveal() {
  busy.value = true; err.value = null
  try {
    const r = await post<{ username: string; password: string }>(`deployments/${enc}/admin-password`, { totp_code: code.value.replace(/\s/g, '') })
    pw.value = r.password
    timer = window.setTimeout(hide, 120000)
  } catch (e) { err.value = e as ApiError } finally { busy.value = false; code.value = '' }
}
function hide() { pw.value = ''; if (timer) window.clearTimeout(timer) }
onBeforeUnmount(hide)
async function copy(what: string, v: string) {
  try { await navigator.clipboard.writeText(v); copied.value = what; window.setTimeout(() => { copied.value = '' }, 2000) } catch { copied.value = '' }
}
function downloadCa() {
  if (!a.value?.ca_pem) return
  const url = URL.createObjectURL(new Blob([a.value.ca_pem], { type: 'application/x-pem-file' }))
  const l = document.createElement('a'); l.href = url; l.download = `${props.slug}-ca.crt`; l.click(); URL.revokeObjectURL(url)
}
</script>
<template>
  <Card v-if="a" title="Open your apps" :hint="a.ready ? a.domain : undefined" data-testid="apps-panel">
    <p v-if="!a.ready" class="muted small">{{ a.note }}</p>
    <template v-else>
      <ul class="ap-apps">
        <li v-for="x in a.apps" :key="x.id"><a :href="x.url" target="_blank" rel="noopener noreferrer"><b>{{ x.title }}</b></a>
          <span class="muted small">{{ x.description }}</span><code class="small">{{ x.url }}</code></li>
      </ul>

      <h4>1. Let your computer find the names</h4>
      <p class="small">The deployment uses <b>{{ a.domain }}</b>, which has no public DNS yet. Add these lines to your hosts file
        (Windows: <code>C:\Windows\System32\drivers\etc\hosts</code>, macOS/Linux: <code>/etc/hosts</code>, as administrator):</p>
      <pre class="ap-pre" data-testid="apps-hosts">{{ hostsText }}</pre>
      <Button size="sm" variant="secondary" @click="copy('hosts', hostsText)">{{ copied === 'hosts' ? 'Copied' : 'Copy lines' }}</Button>

      <h4>2. Trust the deployment's certificate</h4>
      <p class="small">Each deployment has its own certificate authority, limited to {{ a.domain }}. Import it as a trusted root (Windows: double-click,
        "Install certificate", Local machine, "Trusted Root Certification Authorities"; macOS: Keychain Access, System, set to Always Trust;
        Firefox: Settings, Certificates, Import). Without it the browser shows a warning.</p>
      <Button size="sm" variant="secondary" :disabled="!a.ca_pem" @click="downloadCa">Download certificate</Button>

      <h4>3. Sign in</h4>
      <p class="small">User <code>{{ a.admin?.username }}</code> (or <code>{{ a.admin?.email }}</code>): the same password for every app and for mail apps.</p>
      <div v-if="pw" class="ap-pw" data-testid="apps-password"><code>{{ pw }}</code>
        <Button size="sm" variant="secondary" @click="copy('pw', pw)">{{ copied === 'pw' ? 'Copied' : 'Copy' }}</Button>
        <Button size="sm" variant="ghost" @click="hide">Hide</Button><span class="muted small">Hidden again after 2 minutes.</span></div>
      <form v-else-if="a.admin?.password_available" class="ap-reveal" @submit.prevent="reveal">
        <label class="small">Authenticator code<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8" placeholder="123456"></label>
        <Button size="sm" type="submit" :loading="busy">Show password</Button>
        <span class="muted small">A new code from your authenticator app (not the one you signed in with); showing it is recorded in the audit log.</span>
      </form>
      <p v-else class="muted small">No administrator password is stored for this deployment.</p>
      <ErrorBox :error="err" />

      <template v-if="a.clients">
        <h4>Mail apps (Outlook, Thunderbird, phones)</h4>
        <table class="dense small"><tbody>
          <tr><td>Incoming (IMAP)</td><td><code>{{ a.clients.imap.host }}</code> port {{ a.clients.imap.port }}, {{ a.clients.imap.security }}</td></tr>
          <tr><td>Outgoing (SMTP)</td><td><code>{{ a.clients.smtp.host }}</code> port {{ a.clients.smtp.port }}, {{ a.clients.smtp.security }}, normal password</td></tr>
          <tr><td>Exchange ActiveSync</td><td><code>{{ a.clients.activesync }}</code></td></tr>
          <tr><td>Calendar and contacts (CalDAV/CardDAV)</td><td><code>{{ a.clients.caldav }}</code></td></tr>
        </tbody></table>
        <p class="muted small">Mail between addresses of this deployment works now; mail to and from the internet needs your public address and domain.</p>
      </template>
    </template>
  </Card>
</template>
<style scoped>
.ap-apps { list-style: none; margin: 0 0 8px; padding: 0; display: grid; gap: 8px; }
.ap-apps li { display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline; }
.ap-apps code { overflow-wrap: anywhere; }
h4 { margin: 16px 0 4px; font-size: 14px; }
.ap-pre { background: var(--bg-2, rgba(127,127,127,.1)); padding: 8px 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; margin: 6px 0; }
.ap-reveal, .ap-pw { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; }
.ap-reveal label { display: grid; gap: 2px; } .ap-reveal input { width: 9em; }
.ap-pw code { font-size: 14px; padding: 4px 8px; background: var(--bg-2, rgba(127,127,127,.1)); border-radius: 4px; overflow-wrap: anywhere; }
</style>
