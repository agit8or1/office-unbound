<script setup lang="ts">
// Step 5: the generated layout exactly as POST /deployments/size returned it (same plan function as the approved plan).
import { computed } from 'vue'
import { Banner, fmtGb, fmtMem } from '../kit'
import { ARCH_INFO, issueText, recommendationText, serviceLabel, summarize, vmEvidence, type SizeResponse, type WizardModel } from './sizing'
const props = defineProps<{ r: SizeResponse; m: WizardModel; busy: boolean }>()
const emit = defineEmits<{ (e: 'regenerate'): void }>()
const s = computed(() => summarize(props.r))
const vms = computed(() => props.r.vms ?? [])
const flags = computed(() => props.r.estimates_flags ?? [])
const rec = computed(() => recommendationText(props.r))
const risks = computed(() => props.r.risks ?? [])
const sev = (x: string | undefined) => (x === 'error' ? 'bad' : x === 'info' ? 'info' : 'warn')
const est = computed(() => props.r.estimated_supported_workload)

function ov(name: string) { return props.m.vmOverrides[name] ?? (props.m.vmOverrides[name] = {}) }
function setCores(name: string, v: string) { const n = Number(v); ov(name).cores = v.trim() && Number.isInteger(n) && n > 0 ? n : undefined }
function setMem(name: string, v: string) { const n = Number(v); ov(name).memory_mb = v.trim() && n > 0 ? Math.round(n * 1024) : undefined }
const memGb = (name: string) => { const x = props.m.vmOverrides[name]?.memory_mb; return x ? String(x / 1024) : '' }
const hasOverrides = computed(() => Object.values(props.m.vmOverrides).some((o) => o.cores || o.memory_mb))
function clearOverrides() { props.m.vmOverrides = {}; emit('regenerate') }
</script>

<template>
  <div class="dw-review">
    <div class="wz-card">
      <p v-if="rec" class="dw-rec-big">{{ rec }}</p>
      <p v-else class="dw-bad"><b>No recommendation:</b> nothing fits the approved infrastructure with these inputs.</p>
      <p class="muted">This plan uses the <b>{{ r.selected ? ARCH_INFO[r.selected].title : '-' }}</b> layout with <b>{{ vms.length }}</b> VM{{ vms.length === 1 ? '' : 's' }}.
        <span v-if="r.recommended && r.selected !== r.recommended.architecture">You chose it instead of the recommended {{ ARCH_INFO[r.recommended.architecture].title }} layout.</span></p>
    </div>

    <Banner v-for="(e, i) in r.errors" :key="'e' + i" :kind="e.severity === 'error' ? 'bad' : 'warn'">{{ e.message }}</Banner>
    <Banner v-for="(e, i) in r.plan_blocking ?? []" :key="'b' + i" kind="bad" title="Blocks deployment">{{ issueText(e) }}</Banner>
    <Banner v-if="r.shortfall" kind="bad" title="Not enough capacity">{{ r.shortfall.message }}
      <ul class="dw-list"><li v-for="(a, i) in r.shortfall.alternatives" :key="i">{{ a.message ?? issueText(a) }}</li></ul>
    </Banner>

    <div class="wz-card">
      <h2>Virtual machines ({{ vms.length }})</h2>
      <div class="wz-table-wrap"><table>
        <caption class="dw-sr">Planned virtual machines</caption>
        <thead><tr><th>VM</th><th>Services</th><th class="num">vCPU</th><th class="num">Memory</th><th class="num">Storage</th><th>Node</th><th>Sizing</th></tr></thead>
        <tbody>
          <tr v-for="v in vms" :key="v.name">
            <td><b class="mono">{{ v.name }}</b><div v-if="v.depends_on.length" class="small muted">needs {{ v.depends_on.join(', ') }}</div></td>
            <td>{{ v.services.length ? v.services.map(serviceLabel).join(', ') : v.components.join(', ') }}</td>
            <td class="num">{{ v.cores }}</td><td class="num">{{ fmtMem(v.memory_mb) }}</td><td class="num">{{ fmtGb(v.disk_gb) }}</td>
            <td>{{ v.node ?? 'planner picks' }}</td>
            <td><span class="wz-chip" :class="vmEvidence(v, flags) === 'estimate' ? 'warn' : 'ok'">{{ vmEvidence(v, flags) }}</span></td>
          </tr>
        </tbody>
        <tfoot><tr><th>Total</th><th></th><th class="num">{{ s.vcpu }}</th><th class="num">{{ fmtMem(s.memoryMb) }}</th><th class="num">{{ fmtGb(s.storageGb) }}</th><th colspan="2"></th></tr></tfoot>
      </table></div>
      <dl v-if="s.headroom" class="wz-dl mt">
        <dt>Left over: vCPU</dt><dd :class="{ 'dw-bad': s.headroom.vcpu < 0 }">{{ s.headroom.vcpu }}</dd>
        <dt>Left over: memory</dt><dd :class="{ 'dw-bad': s.headroom.memoryMb < 0 }">{{ fmtMem(s.headroom.memoryMb) }}</dd>
        <dt>Left over: storage</dt><dd :class="{ 'dw-bad': s.headroom.storageGb < 0 }">{{ fmtGb(s.headroom.storageGb) }}</dd>
      </dl>

      <details class="wz-help">
        <summary>Adjust individual VMs</summary>
        <p class="small">Leave a field empty to keep the computed value. Values below a service's documented minimum are refused. Regenerating only recalculates; nothing is created.</p>
        <div class="wz-table-wrap"><table>
          <thead><tr><th>VM</th><th>vCPU</th><th>Memory (GiB)</th></tr></thead>
          <tbody><tr v-for="v in vms" :key="v.name">
            <td class="mono">{{ v.name }}</td>
            <td><input type="number" min="1" class="dw-num" :aria-label="`vCPU for ${v.name}`" :placeholder="String(v.cores)" :value="m.vmOverrides[v.name]?.cores ?? ''" @change="setCores(v.name, ($event.target as HTMLInputElement).value)" /></td>
            <td><input type="number" min="0.25" step="0.25" class="dw-num" :aria-label="`Memory in GiB for ${v.name}`" :placeholder="String(v.memory_mb / 1024)" :value="memGb(v.name)" @change="setMem(v.name, ($event.target as HTMLInputElement).value)" /></td>
          </tr></tbody>
        </table></div>
        <div class="wz-row mt">
          <button type="button" class="wz-btn" :disabled="busy" @click="emit('regenerate')">{{ busy ? 'Recalculating…' : 'Regenerate plan' }}</button>
          <button v-if="hasOverrides" type="button" class="wz-btn" :disabled="busy" @click="clearOverrides">Reset adjustments</button>
        </div>
      </details>
    </div>

    <div class="wz-card">
      <h2>Estimated supported workload <span class="wz-chip warn">estimate</span></h2>
      <p v-if="est?.capacity_bound_users">This layout fits the approved capacity up to about <b>{{ est.capacity_bound_users }}</b> users{{ m.type === 'msp' ? ' per customer' : '' }}.</p>
      <p class="small muted">{{ est?.basis }}</p>
      <p v-if="r.validated === false" class="small">Your workload is above what has been tested in the lab for at least one service; the figures are model estimates.</p>
      <details v-if="r.evidence?.length" class="wz-help"><summary>Tested vs. estimated, per service</summary>
        <ul class="dw-list">
          <li v-for="e in r.evidence" :key="e.component"><b>{{ e.component }}</b>:
            <span class="wz-chip" :class="e.within_validated ? 'ok' : 'warn'">{{ e.within_validated ? 'measured' : 'estimate' }}</span>
            <span v-if="e.validated?.reference" class="muted"> tested with {{ e.validated.reference }}</span>
            <span v-if="e.exceeds?.length" class="muted"> &middot; above test: {{ e.exceeds.join(', ') }}</span></li>
        </ul>
      </details>
      <details v-if="r.assumptions?.length" class="wz-help"><summary>Assumptions</summary>
        <ul class="dw-list"><li v-for="(a, i) in r.assumptions" :key="i">{{ a }}</li></ul>
      </details>
    </div>

    <div class="wz-card">
      <h2>Risks and shortages</h2>
      <p v-if="!risks.length && r.fits" class="muted">No risks reported.</p>
      <ul v-else class="wz-checks"><li v-for="(k, i) in risks" :key="i"><span class="wz-chip" :class="sev(k.severity)">{{ k.severity ?? 'warning' }}</span><span>{{ k.message }}</span></li></ul>
      <p v-if="r.production_ready === false && m.type !== 'evaluation'" class="small">Not production ready: {{ (r.production_ready_blockers ?? []).join('; ') }}.</p>
    </div>

    <div class="wz-card">
      <h2>Availability and recovery</h2>
      <dl class="wz-dl">
        <dt>High availability</dt><dd>{{ r.recovery?.application_ha ? 'Yes, services run as replicas on separate nodes.' : 'No. Services are not replicated.' }}</dd>
        <dt>If a node fails</dt><dd>{{ r.recovery?.host_failure ?? '-' }}</dd>
        <dt>Backups</dt><dd>{{ r.backup?.destination ?? 'none chosen' }}, keep {{ r.backup?.retention_days }} days, at most {{ r.backup?.rpo_hours }} h of data loss<span v-if="r.backup?.estimated_backup_gb"> &middot; about {{ fmtGb(r.backup.estimated_backup_gb) }} backup space <span class="wz-chip warn">estimate</span></span></dd>
        <dt>Updates</dt><dd>{{ r.updates?.mode === 'maintenance_window' ? 'In the window ' + (r.updates?.window ?? '') : 'Manual' }}<span v-if="r.updates?.note" class="muted"> &middot; {{ r.updates.note }}</span></dd>
      </dl>
    </div>

    <div v-if="r.scaling_recommendations?.length" class="wz-card">
      <h2>Scaling recommendations</h2>
      <ul class="dw-list"><li v-for="(x, i) in r.scaling_recommendations" :key="i">{{ x.message }}</li></ul>
    </div>
  </div>
</template>
