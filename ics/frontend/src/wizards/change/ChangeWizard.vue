<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import type { Component, DiscNetwork, DiscNode, EnvResource, Environment, Loaded, PlanCreated } from '../api'
import { Banner, CapacityList, DiffTable, Field, Unavailable, WizardShell, fmtDuration, useWizard } from '../kit'
import JobSteps from '../kit/JobSteps.vue'
import { CHANGE_TYPES, applyDefaults, assertSubmittable, buildChange, buildChangeParams, changeKey, changeSteps, needsWindow, newChangeModel, typeById, validateReview } from './state'

const m = reactive(newChangeModel())
const wz = useWizard(changeSteps, m)
const envs = ref<Loaded<Environment[]> | null>(null)
const resources = ref<Loaded<EnvResource[]> | null>(null)
const nodes = ref<Loaded<DiscNode[]> | null>(null)
const networks = ref<Loaded<DiscNetwork[]> | null>(null)
const comps = ref<Loaded<Component[]> | null>(null)
const previewing = ref(false)
const previewError = ref('')
const submitting = ref(false)
const submitError = ref('')
const created = ref<PlanCreated | null>(null)
const err = (k: string) => wz.m.errors[k]

onMounted(async () => {
  ;[envs.value, nodes.value, networks.value, comps.value] = await Promise.all([
    load(() => api.environments()), load(() => api.infra<DiscNode>('nodes')), load(() => api.infra<DiscNetwork>('networks')), load(() => api.components()),
  ])
})
watch(() => m.envId, async (id) => { resources.value = id ? await load(() => api.resources(id)) : null })

const type = computed(() => typeById(m.type))
const onReview = computed(() => wz.current.value.id === 'review')
const resourceOptions = (kind: 'vm' | 'service' | undefined) => (resources.value?.state === 'ok' ? resources.value.data.filter((r) => r.kind === kind) : [])
function chooseType(id: string) { if (m.type !== id) { m.type = id; applyDefaults(m) } }

async function refreshPreview() {
  previewError.value = ''; m.confirmed = false
  const key = changeKey(m)
  previewing.value = true
  try { m.preview = await api.previewChange(m.envId, buildChange(m)); m.previewKey = key }
  catch (e) { m.preview = null; m.previewKey = null; previewError.value = e instanceof Error ? e.message : String(e) }
  finally { previewing.value = false }
}
watch(() => wz.m.index, (i) => { if (changeSteps[i].id === 'review' && !created.value) void refreshPreview() })
watch(() => changeKey(m), () => { m.confirmed = false })

const stale = computed(() => !!m.preview && m.previewKey !== changeKey(m))
const reviewErr = computed(() => validateReview(m))
const canSubmit = computed(() => { try { assertSubmittable(m, onReview.value); return true } catch { return false } })
async function submit() {
  submitError.value = ''
  try { assertSubmittable(m, onReview.value) } catch (e) { submitError.value = (e as Error).message; return }
  submitting.value = true
  try { created.value = await api.submitPlan('deployment.change', buildChangeParams(m)) }
  catch (e) { submitError.value = e instanceof Error ? e.message : String(e) }
  finally { submitting.value = false }
}
const riskKind = (r: string) => (r === 'high' ? 'bad' : r === 'medium' ? 'warn' : 'ok')
</script>

<template>
  <WizardShell
    title="Change an environment" subtitle="Edit the desired state of a deployment. You see the impact first; nothing changes until the plan is approved and run."
    :steps="changeSteps" :index="wz.m.index" :reached="wz.m.reached" :hide-nav="onReview" :hide-next="onReview" :busy="previewing || submitting"
    @next="wz.next()" @back="wz.back()" @goto="wz.goto($event)"
  >
    <div v-show="wz.current.value.id === 'environment'" class="wz-card">
      <h2>Which environment?</h2>
      <Unavailable v-if="envs?.state === 'unavailable'" what="Environments" endpoint="GET /api/v1/deployments" :status="envs.status" />
      <Banner v-else-if="envs?.state === 'error'" kind="bad">{{ envs.message }}</Banner>
      <Banner v-else-if="envs?.state === 'ok' && !envs.data.length" kind="info" title="No environments yet">Create one with <a href="#/deployments/new">New deployment</a>.</Banner>
      <Field label="Environment" :error="err('envId')" v-slot="{ id, invalid }">
        <select :id="id" v-model="m.envId" :aria-invalid="invalid"><option value="">Select…</option><option v-for="e in envs?.state === 'ok' ? envs.data : []" :key="e.id" :value="e.id">{{ e.name }} ({{ e.profile }}, {{ e.status }})</option></select>
      </Field>
    </div>

    <div v-show="wz.current.value.id === 'type'">
      <p v-if="err('type')" class="bad-text" role="alert">{{ err('type') }}</p>
      <div class="wz-cards" role="group" aria-label="Change types">
        <button v-for="t in CHANGE_TYPES" :key="t.id" type="button" class="wz-pick" :aria-pressed="m.type === t.id" @click="chooseType(t.id)"><b>{{ t.label }}</b><span class="muted">{{ t.description }}</span></button>
      </div>
    </div>

    <div v-show="wz.current.value.id === 'details'" class="wz-card">
      <h2>{{ type?.label ?? 'Details' }}</h2>
      <Unavailable v-if="resources?.state === 'unavailable'" what="Environment resources" endpoint="GET /api/v1/deployments/{id}/resources" :status="resources.status" />
      <div class="wz-grid">
        <template v-for="f in type?.fields ?? []" :key="f.key">
          <Field v-if="f.kind !== 'bool'" :label="f.label + (f.unit && f.kind === 'number' ? ` (${f.unit})` : '')" :optional="f.optional" :error="err(f.key)" :hint="f.hint ?? f.patternHint" v-slot="{ id, invalid }">
            <select v-if="f.kind === 'resource'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="r in resourceOptions(f.resourceKind)" :key="r.logical_name" :value="r.logical_name">{{ r.logical_name }}</option></select>
            <select v-else-if="f.kind === 'node'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="n in nodes?.state === 'ok' ? nodes.data : []" :key="n.name" :value="n.name">{{ n.name }}</option></select>
            <select v-else-if="f.kind === 'network'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="n in networks?.state === 'ok' ? networks.data : []" :key="n.name + n.node" :value="n.name">{{ n.name }}</option></select>
            <select v-else-if="f.kind === 'component'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="c in comps?.state === 'ok' ? comps.data : []" :key="c.id" :value="c.id">{{ c.label }}</option></select>
            <select v-else-if="f.kind === 'choice'" :id="id" v-model="m.values[f.key]"><option v-for="c in f.choices" :key="c.value" :value="c.value">{{ c.label }}</option></select>
            <input v-else-if="f.kind === 'number'" :id="id" v-model.number="m.values[f.key]" type="number" :min="f.min" :max="f.max" :aria-invalid="invalid" />
            <input v-else :id="id" v-model.trim="m.values[f.key]" type="text" autocomplete="off" :aria-invalid="invalid" />
          </Field>
          <label v-else class="wz-choice"><input v-model="m.values[f.key]" type="checkbox" /> {{ f.label }}</label>
        </template>
      </div>
    </div>

    <div v-show="wz.current.value.id === 'review'">
      <template v-if="created">
        <Banner kind="ok" title="Change plan submitted">Plan <span class="mono">{{ created.plan_id }}</span> is {{ created.status.replace('_', ' ') }} (risk {{ created.risk }}, {{ created.approvals_required }} approval(s) required).</Banner>
        <div class="wz-card"><h2>Progress</h2>
          <template v-if="created.job_id"><p>Job <a :href="'#/jobs/' + created.job_id" class="mono">{{ created.job_id }}</a></p><JobSteps :job-id="created.job_id" /></template>
          <p v-else class="muted">The job is created when the plan is approved. Follow it under <a href="#/plans">Plans</a>.</p></div>
      </template>
      <template v-else>
        <p v-if="previewing" class="muted" role="status">Computing impact…</p>
        <Banner v-if="previewError" kind="bad" title="Could not preview this change">{{ previewError }}</Banner>
        <Unavailable v-if="previewError.startsWith('404')" what="Change preview" endpoint="POST /api/v1/deployments/{id}/changes/preview" :status="404" />
        <Banner v-if="stale" kind="warn" title="Inputs changed">This preview no longer matches your inputs. Refresh it.</Banner>
        <template v-if="m.preview">
          <Banner v-for="(e, i) in m.preview.errors" :key="'e' + i" kind="bad" title="Blocking error">{{ e.message }}</Banner>
          <Banner v-for="(w, i) in m.preview.warnings" :key="'w' + i" kind="warn" title="Warning">{{ w.message }}</Banner>
          <div class="wz-card">
            <h2>Impact summary</h2>
            <p v-if="m.preview.summary" class="muted">{{ m.preview.summary }}</p>
            <dl class="wz-dl">
              <dt>Risk</dt><dd><span class="wz-chip" :class="riskKind(m.preview.risk)">{{ m.preview.risk }}</span></dd>
              <dt>Estimated downtime</dt><dd>{{ fmtDuration(m.preview.downtime.seconds) }}</dd>
              <dt>Snapshot required</dt><dd>{{ m.preview.requires_snapshot ? 'Yes, taken automatically before the change' : 'No' }}</dd>
              <dt>Backup required</dt><dd>{{ m.preview.requires_backup ? 'Yes, a verified recent backup must exist' : 'No' }}</dd>
              <dt>Maintenance window</dt><dd>{{ m.preview.requires_maintenance_window ? 'Required (disruptive)' : 'Not required' }}</dd>
              <dt>Depends on / affects</dt><dd>{{ m.preview.dependencies.join(', ') || 'nothing else' }}</dd>
            </dl>
            <template v-if="m.preview.downtime.steps?.length"><h3>Disruptive steps</h3><ul><li v-for="s in m.preview.downtime.steps" :key="s">{{ s }}</li></ul></template>
          </div>
          <div class="wz-card"><h2>Current vs proposed</h2><DiffTable :rows="m.preview.diff" /></div>
          <div class="wz-card"><h2>Capacity impact</h2><CapacityList :lines="m.preview.capacity" /></div>
          <div v-if="needsWindow(m.preview)" class="wz-card">
            <h2>Maintenance window</h2>
            <Field label="Run during" :error="reviewErr.window" hint="Start of the agreed window (your local time)." v-slot="{ id, invalid }"><input :id="id" v-model="m.maintenanceWindow" type="datetime-local" :aria-invalid="invalid" /></Field>
            <label class="wz-choice mt"><input v-model="m.override" type="checkbox" :disabled="!!m.maintenanceWindow" /> No window: request an explicit override (needs an extra approval decision)</label>
          </div>
        </template>
        <div class="wz-card"><div class="wz-row"><button type="button" class="wz-btn" :disabled="previewing" @click="refreshPreview">Refresh preview</button><button type="button" class="wz-btn" @click="wz.goto(2)">Edit details</button></div></div>
        <Banner v-if="submitError" kind="bad" title="Not submitted">{{ submitError }}</Banner>
        <label class="wz-choice"><input v-model="m.confirmed" type="checkbox" :disabled="!m.preview || stale || m.preview.errors.length > 0" /> I have reviewed the impact and want to submit this change for approval.</label>
        <div class="wz-footer"><button type="button" class="wz-btn" @click="wz.back()">Back</button><span class="spacer"></span>
          <button type="button" class="wz-btn primary" :disabled="!canSubmit || submitting" @click="submit">{{ submitting ? 'Submitting…' : 'Submit change plan' }}</button></div>
      </template>
    </div>
  </WizardShell>
</template>
