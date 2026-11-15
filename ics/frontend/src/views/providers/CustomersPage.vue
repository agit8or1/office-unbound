<script setup lang="ts">
// Administration > Customers & approval policies: who owns which infrastructure, how changes are approved, and the customer approval requests.
import { computed, reactive, ref } from 'vue'
import { useLoad, hasRole } from '../../store'
import { ago } from '../../format'
import PageHeader from '../../ui/PageHeader.vue'
import Card from '../../ui/Card.vue'
import Button from '../../ui/Button.vue'
import Drawer from '../../ui/Drawer.vue'
import EmptyState from '../../ui/EmptyState.vue'
import StatusBadge from '../../ui/StatusBadge.vue'
import ErrorBox from '../../components/ErrorBox.vue'
import { Banner, Field, HelpNote } from '../../wizards/kit'
import RunPanel from './RunPanel.vue'
import { api, load, msg, type Customer, type CustomerApproval } from './api'
import { useRun } from './run'
import './providers.css'

const state = useLoad(async () => {
  const [c, a] = await Promise.all([load(() => api.customers()), load(() => api.approvals())])
  return { customers: c.state === 'ok' ? c.data : [], approvals: a.state === 'ok' ? a.data : [], unavailable: c.state === 'unavailable' }
}, 30000)
const d = computed(() => state.data.value)
const isAdmin = computed(() => hasRole('admin'))
const MODE: Record<Customer['provisioning_mode'], { title: string; text: string }> = {
  auto: { title: 'Run after ICS approval', text: 'Changes follow normal approval by your own operators. For infrastructure you own.' },
  customer_approval: { title: 'Customer must approve', text: 'Every change that grants access or changes infrastructure also needs the customer\'s own approval through a private link.' },
  monitoring_only: { title: 'Monitoring only', text: 'Office Unbound may look but never change anything. All changes are refused.' },
}
const CATS: [string, string][] = [['delete_guest', 'Deleting a VM or container'], ['remove_storage', 'Removing storage'], ['network_change', 'Changing networks'], ['expand_permissions', 'Granting more access'], ['revoke_credential', 'Revoking a credential']]
const custName = (id: string) => d.value?.customers.find((c) => c.id === id)?.name ?? 'Customer'
const APPROVAL_LABEL: Record<string, string> = { draft: 'Not sent yet', pending: 'Waiting for the customer', approved: 'Approved', rejected: 'Rejected', changes_requested: 'Changes requested', cancelled: 'Cancelled', expired: 'Expired', completed: 'Completed', provisioned: 'Completed' }
const aTone = (s: string) => (s === 'approved' || s === 'completed' || s === 'provisioned' ? 'ok' : s === 'rejected' || s === 'expired' ? 'bad' : s === 'cancelled' ? 'idle' : 'warn')

// ---- edit / create
const edit = ref<Customer | 'new' | null>(null)
const form = reactive({ name: '', msp_owned: false, mode: 'customer_approval' as Customer['provisioning_mode'], contact_name: '', contact_email: '', extra: {} as Record<string, number> })
const run = useRun()
const errors = ref<Record<string, string>>({})
function open(c: Customer | 'new') {
  run.reset(); errors.value = {}; edit.value = c
  if (c === 'new') Object.assign(form, { name: '', msp_owned: false, mode: 'customer_approval', contact_name: '', contact_email: '', extra: {} })
  else Object.assign(form, { name: c.name, msp_owned: c.msp_owned, mode: c.provisioning_mode, contact_name: c.contact_name ?? '', contact_email: c.contact_email ?? '', extra: { ...c.extra_approvals } })
}
async function save() {
  const e: Record<string, string> = {}
  if (edit.value === 'new' && !/^[A-Za-z0-9][A-Za-z0-9 _.&()-]{0,99}$/.test(form.name)) e.name = 'Use letters, digits and spaces (up to 100 characters).'
  if (form.mode === 'auto' && !form.msp_owned) e.mode = 'Automatic provisioning is only for infrastructure you (the MSP) own.'
  if (form.contact_email && !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/.test(form.contact_email)) e.contact_email = 'Enter a valid email address.'
  errors.value = e
  if (Object.keys(e).length) return
  const extra = Object.fromEntries(Object.entries(form.extra).filter(([, v]) => v > 0))
  const common = { provisioning_mode: form.mode, extra_approvals: extra, ...(form.contact_name ? { contact_name: form.contact_name } : {}), ...(form.contact_email ? { contact_email: form.contact_email } : {}) }
  const job = edit.value === 'new'
    ? await run.start('customer.create', { name: form.name, msp_owned: form.msp_owned, ...common })
    : await run.start('customer.update', { customer_id: (edit.value as Customer).id, ...common })
  if (job?.status === 'succeeded') void state.reload()
}
const cancelErr = ref('')
async function cancel(a: CustomerApproval) { cancelErr.value = ''; try { await api.cancelApproval(a.id); await state.reload() } catch (e) { cancelErr.value = msg(e) } }
const pending = computed(() => (d.value?.approvals ?? []).filter((a) => ['draft', 'pending', 'changes_requested'].includes(a.status)))
</script>

<template>
  <div class="pv">
    <PageHeader title="Customers and approval policies" sub="Who owns each environment and how changes to it must be approved." help="Customers never get an Office Unbound account. They approve through a single-use link.">
      <template #actions><Button v-if="isAdmin" variant="primary" icon="plus" @click="open('new')">Add a customer</Button></template>
    </PageHeader>
    <ErrorBox v-if="state.error.value" :error="state.error.value" />
    <EmptyState v-if="d?.unavailable" icon="users" title="Customers are not available on this server" text="This ICS version does not provide the customer API." />
    <template v-else-if="d">
      <Banner v-if="!isAdmin" kind="info" title="View only">Customer policies are changed by administrators.</Banner>
      <div class="pv-cards">
        <Card v-for="c in d.customers" :key="c.id">
          <template #actions><span v-if="c.disabled_at" class="badge idle">Disabled</span><span v-else class="badge" :class="c.provisioning_mode === 'monitoring_only' ? 'info' : c.provisioning_mode === 'customer_approval' ? 'warn' : 'ok'">{{ MODE[c.provisioning_mode].title }}</span></template>
          <h2 class="pv-h2">{{ c.name }}</h2>
          <p class="muted small">{{ c.msp_owned ? 'Owned by your organisation' : 'Customer-owned infrastructure' }}. {{ MODE[c.provisioning_mode].text }}</p>
          <dl class="pv-dl"><dt>Contact</dt><dd>{{ c.contact_name || '-' }}<template v-if="c.contact_email"> &middot; {{ c.contact_email }}</template></dd>
            <dt>Extra approvers</dt><dd>{{ Object.entries(c.extra_approvals ?? {}).filter(([, v]) => v).map(([k, v]) => `${CATS.find((x) => x[0] === k)?.[1] ?? k}: +${v}`).join('; ') || 'none' }}</dd></dl>
          <Button v-if="isAdmin" size="sm" @click="open(c)">Edit policy</Button>
        </Card>
      </div>

      <Card title="Customer approval requests" hint="Approvals sent to customers through a private link" flush>
        <Banner v-if="cancelErr" kind="bad">{{ cancelErr }}</Banner>
        <div v-if="d.approvals.length" class="tablewrap"><table><thead><tr><th>Request</th><th>Customer</th><th>Status</th><th>Decision</th><th>Link expires</th><th></th></tr></thead><tbody>
          <tr v-for="a in d.approvals" :key="a.id"><td>{{ a.title }}<div class="muted small mono">{{ a.proposal_hash.slice(0, 10) }}</div></td><td>{{ custName(a.customer_id) }}</td>
            <td><span class="badge" :class="aTone(a.status)">{{ APPROVAL_LABEL[a.status] ?? a.status }}</span></td>
            <td class="small"><template v-if="a.decided_at">{{ a.approver_name }} ({{ a.approver_email }}), {{ ago(a.decided_at) }}<div v-if="a.approver_statement" class="muted">"{{ a.approver_statement }}"</div><div v-if="a.decision_note" class="muted">{{ a.decision_note }}</div></template><span v-else class="muted">-</span></td>
            <td class="small">{{ a.token_expires_at ? new Date(a.token_expires_at).toLocaleString() : '-' }}</td>
            <td><Button v-if="['draft', 'pending', 'changes_requested'].includes(a.status)" size="sm" variant="ghost" @click="cancel(a)">Cancel</Button></td></tr>
        </tbody></table></div>
        <EmptyState v-else compact icon="inbox" title="No approval requests yet" text="They are created from the connection wizard when you send a setup package for customer approval." />
        <p v-if="pending.length" class="muted small pv-pad">A sent link is shown only once. If it was lost, cancel the request and send a new one.</p>
      </Card>
    </template>

    <Drawer v-if="edit" :title="edit === 'new' ? 'Add a customer' : 'Policy for ' + (edit as Customer).name" @close="edit = null">
      <div class="wz pv-flow">
        <Field v-if="edit === 'new'" label="Customer name" :error="errors.name" v-slot="{ id, invalid }"><input :id="id" v-model="form.name" type="text" :aria-invalid="invalid" /></Field>
        <label v-if="edit === 'new'" class="wz-choice"><input v-model="form.msp_owned" type="checkbox" /> <span>This infrastructure belongs to my organisation (not a customer)</span></label>
        <h3>How are changes approved?</h3>
        <div class="wz-cards" role="radiogroup" aria-label="Approval policy">
          <button v-for="(x, k) in MODE" :key="k" type="button" class="wz-pick" role="radio" :aria-checked="form.mode === k" :aria-pressed="form.mode === k" @click="form.mode = k as Customer['provisioning_mode']"><b>{{ x.title }}</b><span class="muted small">{{ x.text }}</span></button>
        </div>
        <p v-if="errors.mode" class="bad-text" role="alert">{{ errors.mode }}</p>
        <HelpNote title="Advanced details: extra approvers for sensitive changes">
          <p class="muted small">Add distinct Office Unbound approvers (0 to 3) for risky changes.</p>
          <div class="wz-grid"><Field v-for="c in CATS" :key="c[0]" :label="c[1]" v-slot="{ id }"><input :id="id" v-model.number="form.extra[c[0]]" type="number" min="0" max="3" placeholder="0" /></Field></div>
        </HelpNote>
        <div class="wz-grid two"><Field label="Contact name" optional v-slot="{ id }"><input :id="id" v-model="form.contact_name" type="text" /></Field><Field label="Contact email" optional :error="errors.contact_email" v-slot="{ id }"><input :id="id" v-model="form.contact_email" type="email" /></Field></div>
        <Banner kind="info" title="This is itself a controlled change">Policy changes need two approvers and are written to the audit log.</Banner>
        <div class="wz-row"><button type="button" class="wz-btn primary" :disabled="run.busy.value" @click="save">{{ run.busy.value ? 'Submitting...' : 'Submit change' }}</button><button type="button" class="wz-btn" @click="edit = null">Close</button></div>
        <RunPanel :run="run" what="Updating the customer policy" />
      </div>
    </Drawer>
  </div>
</template>
