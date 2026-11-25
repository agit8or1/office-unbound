<script setup lang="ts">
import { computed } from 'vue'
import { get, type Attempt, type Check, type CheckResult } from '../api'
import { fmtTime, go, pretty, route, short, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import Status from '../components/Status.vue'
import PageHeader from '../ui/PageHeader.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Segmented from '../ui/Segmented.vue'
import Button from '../ui/Button.vue'
import TechText from '../ui/TechText.vue'

const checks = useLoad(() => get<Check[]>('checks'), 5000)
const selId = computed(() => route.value.arg)
const sel = computed(() => checks.data.value?.find((c) => c.id === selId.value) ?? null)
const results = useLoad(async () => (selId.value ? get<CheckResult[]>(`checks/${selId.value}/results?limit=50`) : []), 5000)
const attempts = useLoad(async () => (selId.value ? get<Attempt[]>(`checks/${selId.value}/remediation`) : []), 5000)
const counts = computed(() => {
  const c = { ok: 0, warning: 0, critical: 0, unknown: 0 }
  for (const x of checks.data.value ?? []) c[x.state]++
  return c
})
</script>
<template>
  <div class="page">
    <PageHeader title="Health checks" sub="Continuous checks of your services, with automatic remediation where a policy exists." help="Each check runs on an interval. Flap damping requires several consecutive failures before an incident opens.">
      <template #actions><Button size="sm" icon="refresh" :loading="checks.loading.value" @click="checks.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="checks.error.value" />
    <div v-if="checks.data.value?.length" class="statgrid" role="status">
      <div class="stat idle"><div class="lbl">Healthy</div><div class="val">{{ counts.ok }}</div></div>
      <div class="stat" :class="counts.warning ? 'warn' : 'idle'"><div class="lbl">Warning</div><div class="val">{{ counts.warning }}</div></div>
      <div class="stat" :class="counts.critical ? 'bad' : 'idle'"><div class="lbl">Critical</div><div class="val">{{ counts.critical }}</div></div>
      <div class="stat idle"><div class="lbl">Unknown</div><div class="val">{{ counts.unknown }}</div></div>
    </div>
    <Skeleton v-if="!checks.data.value && !checks.error.value" />
    <div class="split">
      <section class="card flush">
        <div class="scroll" tabindex="0" role="region" aria-label="Scrollable table">
          <table v-if="checks.data.value?.length">
            <thead><tr><th>Check</th><th>Kind</th><th>State</th><th>Last result</th><th>Every</th><th>Auto-fix</th></tr></thead>
            <tbody>
              <tr v-for="c in checks.data.value" :key="c.id" :class="{ sel: c.id === selId }">
                <td class="ident"><a :href="'#/checks/' + c.id">{{ c.name }}</a><span v-if="!c.enabled" class="muted"> (disabled)</span></td>
                <td class="mono">{{ c.kind }}</td>
                <td><Status :s="c.state" /></td>
                <td class="wrap msg"><TechText :text="c.last_message" fallback="not run yet" /><span v-if="c.last_run_at" class="muted small"> · {{ fmtTime(c.last_run_at) }}</span></td>
                <td class="num">{{ c.interval_seconds }} s</td>
                <td>{{ c.remediation ? String(c.remediation.runbook) + ' ' + String(c.remediation.unit ?? c.remediation.path ?? '') : '-' }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyState v-else-if="checks.data.value" icon="check" title="No health checks yet" text="Checks you create appear here with live results, latency and remediation history." />
        </div>
      </section>
      <section v-if="selId" class="card detail" aria-label="Check details">
        <div class="head"><h2>{{ sel?.name ?? short(selId) }}</h2><Button size="sm" variant="ghost" icon="x" @click="go('checks')">Close</Button></div>
        <template v-if="sel">
          <dl class="kv">
            <dt>State</dt><dd><Status :s="sel.state" /> <span class="muted small">flap damping: {{ sel.fail_threshold }} failures to alert, {{ sel.recover_threshold }} ok to recover</span></dd>
            <dt>Since</dt><dd>{{ fmtTime(sel.last_state_change_at) }}</dd>
            <dt>Latency</dt><dd>{{ sel.last_latency_ms ?? '-' }} ms</dd>
            <dt>Incident</dt><dd><a v-if="sel.active_incident_id" :href="'#/incidents/' + sel.active_incident_id">{{ short(sel.active_incident_id) }}</a><span v-else class="muted">none</span></dd>
            <dt>Password</dt><dd>{{ sel.has_secret ? 'stored in the vault (never shown)' : 'none' }}</dd>
          </dl>
          <h3>Configuration</h3><pre class="code" tabindex="0">{{ pretty(sel.config) }}</pre>
          <h3>Remediation policy</h3><pre v-if="sel.remediation" class="code" tabindex="0">{{ pretty(sel.remediation) }}</pre><p v-else class="muted">None.</p>
          <h3>Remediation attempts</h3>
          <table v-if="attempts.data.value?.length">
            <thead><tr><th>#</th><th>Runbook</th><th>Status</th><th>Verified</th><th>When</th><th>Job</th></tr></thead>
            <tbody><tr v-for="a in attempts.data.value" :key="a.id">
              <td>{{ a.attempt_no }}</td><td class="mono">{{ a.runbook }}</td><td><Status :s="a.status" /></td>
              <td>{{ a.verified === null ? '-' : a.verified ? 'recovered' : 'not recovered' }}</td><td>{{ fmtTime(a.at) }}</td>
              <td><a v-if="a.job_id" :href="'#/jobs/' + a.job_id" class="mono">{{ short(a.job_id) }}</a><span v-else-if="a.plan_id">awaiting approval</span></td>
            </tr></tbody>
          </table>
          <p v-else class="muted">No attempts.</p>
          <h3>Recent results</h3>
          <div class="scroll short" tabindex="0" role="region" aria-label="Scrollable table">
            <table v-if="results.data.value?.length">
              <thead><tr><th>Time</th><th>Result</th><th class="num">ms</th><th>Message</th></tr></thead>
              <tbody><tr v-for="r in results.data.value" :key="r.id"><td>{{ fmtTime(r.at) }}</td><td><Status :s="r.status" /></td><td class="num">{{ r.latency_ms ?? '-' }}</td><td class="wrap msg-sm"><TechText :text="r.message" /></td></tr></tbody>
            </table>
            <p v-else class="muted">No results yet.</p>
          </div>
        </template>
        <p v-else-if="checks.data.value" class="muted">Check not found.</p>
      </section>
    </div>
  </div>
</template>
