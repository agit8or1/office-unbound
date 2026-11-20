<script setup lang="ts">
// Open your apps: links to a deployment's applications, hosts-file lines (until public DNS exists), the deployment CA certificate and the
// administrator's sign-in. The password is shown only after a fresh authenticator code and is never kept in the page longer than asked.
import { computed, onBeforeUnmount, ref } from 'vue'
import { get, post, type ApiError } from '../api'
import { useLoad } from '../store'
import Card from '../ui/Card.vue'
import Button from '../ui/Button.vue'
import ErrorBox from './ErrorBox.vue'
import RunPanel from '../views/providers/RunPanel.vue'
import { useRun } from '../views/providers/run'

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

const code = ref(''), busy = ref(false), err = ref<ApiError | null>(null), pw = ref(''), pwUser = ref(''), copied = ref('')
const which = ref<'directory' | 'keycloak'>('directory')
// the sign-in service's own admin console (Keycloak master realm, user kcadmin): same host as the Account app
const kcConsole = computed(() => { const acc = a.value?.apps.find((x) => x.id === 'edge'); try { return acc ? new URL(acc.url).origin + '/admin/' : null } catch { return null } })
// set a sign-in account (directory person + mailbox): typed action directory.account.set, the password only in the plan's encrypted secret
const acct = ref({ username: 'admin', password: '' })
const acctRun = useRun()
const pwOk = computed(() => /^[A-Za-z0-9_-]{8,128}$/.test(acct.value.password))
const userOk = computed(() => /^[a-z][a-z0-9.-]{0,30}[a-z0-9]$/.test(acct.value.username))
async function setAccount() {
  if (!pwOk.value || !userOk.value) return
  await acctRun.start('directory.account.set', { deployment: props.slug, username: acct.value.username, password: acct.value.password })
  acct.value.password = ''
}
let timer: number | undefined
async function reveal() {
  busy.value = true; err.value = null
  try {
    const r = await post<{ username: string; password: string }>(`deployments/${enc}/admin-password`, { totp_code: code.value.replace(/\s/g, ''), which: which.value })
    pw.value = r.password; pwUser.value = r.username
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
const portal = computed(() => a.value?.apps.find((x) => x.id === 'portal') ?? a.value?.apps[0] ?? null)
</script>
<template>
  <Card v-if="a" title="Open your apps" :hint="a.ready ? a.domain : undefined" data-testid="apps-panel">
    <p v-if="!a.ready" class="muted small">{{ a.note }}</p>
    <template v-else>
      <p v-if="portal" class="ap-portal" data-testid="apps-portal">Everyone signs in once at <a :href="portal.url" target="_blank" rel="noopener noreferrer"><b>{{ portal.url }}</b></a>;
        the portal opens files, documents and mail without a second sign-in.</p>
      <details class="small"><summary>Direct addresses (for mail apps and troubleshooting)</summary>
        <ul class="ap-apps">
          <li v-for="x in a.apps" :key="x.id"><b>{{ x.title }}</b> <span class="muted">{{ x.description }}</span> <code>{{ x.url }}</code></li>
        </ul></details>

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
      <p v-if="kcConsole" class="small">Sign-in service administration (sessions, sign-in policy, clients): <a :href="kcConsole" target="_blank" rel="noopener noreferrer">{{ kcConsole }}</a>,
        user <code>kcadmin</code>. Add people in <b>People</b> below (that also creates their mailbox and app access).</p>
      <div v-if="pw" class="ap-pw" data-testid="apps-password"><span class="small">{{ pwUser }}:</span> <code>{{ pw }}</code>
        <Button size="sm" variant="secondary" @click="copy('pw', pw)">{{ copied === 'pw' ? 'Copied' : 'Copy' }}</Button>
        <Button size="sm" variant="ghost" @click="hide">Hide</Button><span class="muted small">Hidden again after 2 minutes.</span></div>
      <form v-else-if="a.admin?.password_available" class="ap-reveal" @submit.prevent="reveal">
        <label class="small">Authenticator code<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8" placeholder="123456"></label>
        <label class="small">Password of<select v-model="which"><option value="directory">{{ a.admin?.username }} (every app)</option>
          <option value="keycloak">kcadmin (sign-in service console)</option></select></label>
        <Button size="sm" type="submit" :loading="busy">Show password</Button>
        <span class="muted small">A new code from your authenticator app (not the one you signed in with); showing it is recorded in the audit log.</span>
      </form>
      <p v-else class="muted small">No administrator password is stored for this deployment.</p>
      <ErrorBox :error="err" />
      <p class="muted small">Add people, administrators and passwords in <b>People</b> below.</p>

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
