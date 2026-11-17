<script setup lang="ts">
// "Next steps" checklist for one cluster. Each item is read from the API (templates, image releases, plans, jobs, checks, deployments);
// what cannot be read is shown as Unknown. The primary button continues into the first step that can be acted on now.
import { computed } from 'vue'
import { get } from '../../api'
import { useLoad } from '../../store'
import { hasPath } from '../../router'
import { asList, normDeployment } from '../../infra'
import Button from '../../ui/Button.vue'
import { nextSteps, primaryStep, STATE_LABEL, STATE_TONE, type NextStep, type NsCheck, type NsJob, type NsPlan, type NsReleases, type NsTemplate } from './nextSteps'
import { load, type Loaded } from './api'
import type { ProviderEndpoint } from './model'

const props = defineProps<{ id: string; heading?: string; fallbackTo?: string; fallbackLabel?: string; hideWhenDone?: boolean }>()

function ok<T>(r: Loaded<T>): T | null { return r.state === 'ok' ? r.data : null }
const data = useLoad(async (): Promise<{ steps: NextStep[] | null }> => {
  const [ep, rel, tpl, cat, plans, jobs, checks, deps] = await Promise.all([
    load(() => get<ProviderEndpoint>(`endpoints/${props.id}`)),
    load(() => get<{ configured: boolean; releases: { release: string; verified: boolean; version?: number }[] }>('images/releases')),
    load(() => get<NsTemplate[]>(`infra/templates?endpoint=${encodeURIComponent(props.id)}`)),
    load(() => get<{ os_images?: { template: string }[] }>('catalog/components')),
    load(() => get<NsPlan[]>('plans?limit=200')),
    load(() => get<NsJob[]>('jobs')),
    load(() => get<NsCheck[]>('checks')),
    load(() => get<unknown>('deployments')),
  ])
  const e = ok(ep)
  if (!e) return { steps: null }
  const releases: NsReleases = rel.state === 'ok' ? { state: 'ok', ...rel.data } : rel.state === 'forbidden' ? { state: 'forbidden' } : null
  const c = ok(cat), d = ok(deps)
  return { steps: nextSteps({
    ep: { id: e.id, name: e.name, enabled: e.enabled !== false, provision: e.credentials.provision.present, pools: e.scope.allowed_pools ?? [] },
    releases, templates: ok(tpl), catalogTemplates: c ? (c.os_images ?? []).map((o) => o.template).filter(Boolean) : null,
    plans: ok(plans), jobs: ok(jobs), checks: ok(checks), deployments: d === null ? null : asList(d).map(normDeployment),
    canDeploy: hasPath('/deployments/new'),
  }) }
}, 30000)
const steps = computed(() => data.data.value?.steps ?? null)
const primary = computed(() => (steps.value ? primaryStep(steps.value) : null))
</script>

<template>
  <section v-if="!(hideWhenDone && steps && steps.every((s) => s.state === 'done'))" class="card ns" aria-labelledby="ns-h" data-testid="next-steps">
    <h2 id="ns-h">{{ heading ?? 'Next steps' }}</h2>
    <p v-if="data.error.value || (data.data.value && !steps)" class="muted small">The next steps could not be loaded for this cluster.</p>
    <p v-else-if="!steps" class="muted small">Checking what is already set up…</p>
    <template v-else>
      <ol class="ns-list">
        <li v-for="(s, i) in steps" :key="s.id" :class="'ns-' + s.state">
          <span class="ns-num" aria-hidden="true">{{ s.state === 'done' ? '&#10003;' : i + 1 }}</span>
          <div class="ns-body">
            <div class="ns-title"><b>{{ s.title }}</b> <span class="badge" :class="STATE_TONE[s.state]">{{ STATE_LABEL[s.state] }}</span></div>
            <p class="muted small">{{ s.reason }}</p>
          </div>
          <Button v-if="s !== primary" class="ns-go" size="sm" :to="s.to" :aria-label="`${s.action}: ${s.title}`">{{ s.action }}</Button>
        </li>
      </ol>
      <div class="ns-actions">
        <Button v-if="primary" variant="primary" :to="primary.to">Continue: {{ primary.action }}</Button>
        <Button v-else-if="fallbackTo" variant="primary" :to="fallbackTo">{{ fallbackLabel ?? 'Continue' }}</Button>
        <slot :primary="primary" />
      </div>
    </template>
  </section>
</template>

<style scoped>
.ns { display: grid; gap: 10px; text-align: left; }
.ns h2 { margin: 0; font-size: 1.05rem; }
.ns-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.ns-list li { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-start; padding: 10px 12px; border: 1px solid var(--line); border-radius: var(--radius); }
.ns-list li.ns-done { border-color: var(--ok); }
.ns-list li.ns-blocked { border-color: var(--bad); }
.ns-num { flex: none; width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-weight: 600; border: 2px solid var(--line-strong); color: var(--muted); }
.ns-done .ns-num { border-color: var(--ok); color: var(--ok); }
.ns-pending .ns-num, .ns-waiting .ns-num { border-color: var(--accent); color: var(--accent); }
.ns-body { flex: 1 1 200px; min-width: 0; }
.ns-body p { margin: 2px 0 0; }
.ns-title { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.ns-go { flex: none; align-self: center; }
.ns-actions { display: flex; flex-wrap: wrap; gap: 8px; }
</style>
