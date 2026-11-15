<script setup lang="ts">
// Exact outcome of a provisioning plan: what will be created/changed in Proxmox, what conflicts exist, and who enforces which limit.
import { computed } from 'vue'
import { Banner } from '../../wizards/kit'
import { ENFORCER_LABEL, reviewVerdict, splitEnforcement, stepRows, type EnforcementNote, type PlanPreviewOut } from './model'
const props = defineProps<{ preview: PlanPreviewOut; showNoop?: boolean; extraEnforcement?: EnforcementNote[] }>()
const rows = computed(() => stepRows(props.preview.plan.steps, props.showNoop))
const noops = computed(() => props.preview.plan.steps.filter((s) => s.op === 'noop').length)
const verdict = computed(() => reviewVerdict(props.preview))
const enf = computed(() => splitEnforcement(props.preview.plan.enforcement ?? []))
const summary = computed(() => Object.entries(props.preview.summary ?? {}).filter(([k, v]) => v && k !== 'noop'))
</script>
<template>
  <div class="pv-plan">
    <Banner v-for="b in verdict.blockers" :key="b" kind="bad" title="Cannot be applied as it stands">{{ b }}</Banner>
    <Banner v-for="c in preview.plan.conflicts" :key="c" kind="warn" title="Conflict handled safely">{{ c }}</Banner>
    <Banner v-for="w in preview.plan.warnings" :key="w" kind="warn">{{ w }}</Banner>
    <p class="muted small" v-if="summary.length">{{ summary.map(([k, v]) => `${v} to ${k}`).join(', ') }}<template v-if="noops">, {{ noops }} already in place</template>. Plan fingerprint <span class="mono">{{ preview.plan_hash.slice(0, 12) }}</span>: the change that runs is bound to exactly this plan.</p>

    <h3>Accounts, roles and permissions</h3>
    <div class="wz-table-wrap"><table class="pv-table">
      <thead><tr><th>Action</th><th>Type</th><th>Name / path</th><th>Detail</th></tr></thead>
      <tbody>
        <tr v-for="(r, i) in rows" :key="i" :class="['pv-op-' + r.op]">
          <td><span class="wz-chip" :class="r.tone === 'info' ? 'info' : r.tone === 'warn' ? 'warn' : r.tone === 'bad' ? 'bad' : ''">{{ r.opLabel }}</span></td>
          <td>{{ r.kindLabel }}</td><td class="mono">{{ r.target }}</td>
          <td>{{ r.what }}<div v-if="r.reason" class="muted small">{{ r.reason }}</div><span v-if="r.high" class="wz-chip bad">high impact</span></td>
        </tr>
        <tr v-if="!rows.length"><td colspan="4" class="muted">Nothing to change: everything is already in place.</td></tr>
      </tbody>
    </table></div>

    <template v-if="preview.plan.elevated?.length">
      <h3>Elevated privileges</h3>
      <Banner v-for="e in preview.plan.elevated" :key="e.privilege + e.path" :kind="e.approved ? 'warn' : 'bad'" :title="e.privilege + ' on ' + e.path">{{ e.why }}<template v-if="e.what_it_grants"> It grants: {{ e.what_it_grants }}</template> {{ e.approved ? 'Explicitly approved in this policy.' : 'Not approved: the plan is blocked until it is.' }}</Banner>
    </template>
    <template v-if="preview.plan.consequences?.length"><h3>Consequences</h3><ul class="pv-list"><li v-for="c in preview.plan.consequences" :key="c">{{ c }}</li></ul></template>

    <h3>Who enforces what</h3>
    <div class="pv-enf">
      <div class="pv-enf-col" data-who="proxmox"><h4>Enforced by Proxmox</h4><p class="muted small">Holds even if Office Unbound is compromised.</p>
        <ul class="pv-list"><li v-for="e in enf.proxmox" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
      <div class="pv-enf-col" data-who="ics"><h4>Enforced by Office Unbound only</h4><p class="muted small">Proxmox would allow more. Office Unbound refuses it.</p>
        <ul class="pv-list"><li v-for="e in [...enf.ics, ...(extraEnforcement ?? [])]" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
      <div v-if="enf.notEnforced.length" class="pv-enf-col" data-who="none"><h4>Not enforced yet</h4><p class="muted small">Recorded in the policy, but nothing applies it today.</p>
        <ul class="pv-list"><li v-for="e in enf.notEnforced" :key="e.control"><b>{{ e.control }}</b><div class="muted small">{{ e.detail }}</div></li></ul></div>
    </div>
    <p class="muted small">{{ ENFORCER_LABEL.proxmox }} means a Proxmox permission rejects the request. Anything else depends on Office Unbound behaving correctly.</p>
  </div>
</template>
