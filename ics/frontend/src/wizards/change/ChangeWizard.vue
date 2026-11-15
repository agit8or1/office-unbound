<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, load } from '../api'
import { get } from '../../api'
import type { Component, Environment, Loaded, PlanCreated, Profile } from '../api'
import { Banner, CapacityList, DiffTable, Field, Unavailable, WizardShell, fmtDuration, useWizard } from '../kit'
import JobSteps from '../kit/JobSteps.vue'
import { CHANGE_TYPES, PLANNED_CHANGES, applyDefaults, assertSubmittable, buildChange, buildChangeParams, changeKey, changeSteps, needsWindow, newChangeModel, typeById, validateReview } from './state'

interface Window { id: string; name: string; starts_at: string; ends_at: string; active: boolean }

const m = reactive(newChangeModel())
const wz = useWizard(changeSteps, m)
const envs = ref<Loaded<Environment[]> | null>(null)
const profiles = ref<Loaded<Profile[]> | null>(null)
const comps = ref<Loaded<Component[]> | null>(null)
const windows = ref<Loaded<Window[]> | null>(null)
const currentProfile = ref<Profile | null>(null)
const previewing = ref(false)
const previewError = ref('')
const submitting = ref(false)
const submitError = ref('')
const created = ref<PlanCreated | null>(null)
const err = (k: string) => wz.m.errors[k]

onMounted(async () => {
  ;[envs.value, profiles.value, comps.value, windows.value] = await Promise.all([
    load(() => api.environments()), load(() => api.profiles()), load(() => api.components()), load(() => get<Window[]>('maintenance')),
  ])
})
watch(() => m.envId, async (slug) => {
  currentProfile.value = null
  if (!slug) return
  const d = await load(() => api.deployment(slug))
  if (d.state === 'ok' && profiles.value?.state === 'ok') currentProfile.value = profiles.value.data.find((p) => p.id === d.data.profile) ?? null
})

const type = computed(() => typeById(m.type))
const onReview = computed(() => wz.current.value.id === 'review')
// optional components of the environment's own profile; if it cannot be determined, every catalog component is not offered (never guessed)
const optionalChoices = computed(() => (currentProfile.value?.optional_components ?? []).map((id) => ({ id, label: comps.value?.state === 'ok' ? comps.value.data.find((c) => c.id === id)?.label ?? id : id })))
const activeWindows = computed(() => (windows.value?.state === 'ok' ? windows.value.data.filter((w) => w.active) : []))
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
const riskKind = (r: string) => (r === 'high' ? 'bad' : 'ok')
const fmtWindow = (w: Window) => `${w.name} (${new Date(w.starts_at).toLocaleString()} - ${new Date(w.ends_at).toLocaleString()})`
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
        <select :id="id" v-model="m.envId" :aria-invalid="invalid"><option value="">Select…</option><option v-for="e in envs?.state === 'ok' ? envs.data : []" :key="e.id" :value="e.id" :disabled="e.status !== 'active'">{{ e.name }} ({{ e.profile }}, {{ e.status }})</option></select>
      </Field>
      <p class="small muted">Only active environments can be changed.</p>
    </div>

    <div v-show="wz.current.value.id === 'type'">
      <p v-if="err('type')" class="bad-text" role="alert">{{ err('type') }}</p>
      <div class="wz-cards" role="group" aria-label="Change types">
        <button v-for="t in CHANGE_TYPES" :key="t.id" type="button" class="wz-pick" :aria-pressed="m.type === t.id" @click="chooseType(t.id)"><b>{{ t.label }}</b><span class="muted">{{ t.description }}</span></button>
      </div>
      <div class="wz-card">
        <h2>Planned</h2>
        <p class="muted small">These changes are not available yet. They will appear here when the platform can plan and run them.</p>
        <ul><li v-for="p in PLANNED_CHANGES" :key="p.label">{{ p.label }}<span v-if="p.description" class="muted small"> &mdash; {{ p.description }}</span></li></ul>
      </div>
    </div>

    <div v-show="wz.current.value.id === 'details'" class="wz-card">
      <h2>{{ type?.label ?? 'Details' }}</h2>
      <div class="wz-grid">
        <template v-for="f in type?.fields ?? []" :key="f.key">
          <Field v-if="f.kind !== 'bool'" :label="f.label + (f.unit && f.kind === 'number' ? ` (${f.unit})` : '')" :optional="f.optional" :error="err(f.key)" :hint="f.hint ?? f.patternHint" v-slot="{ id, invalid }">
            <select v-if="f.kind === 'profile'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="p in profiles?.state === 'ok' ? profiles.data : []" :key="p.id" :value="p.id">{{ p.label }}</option></select>
            <select v-else-if="f.kind === 'component'" :id="id" v-model="m.values[f.key]" :aria-invalid="invalid"><option value="">Select…</option><option v-for="c in optionalChoices" :key="c.id" :value="c.id">{{ c.label }}</option></select>
            <input v-else-if="f.kind === 'number'" :id="id" v-model.number="m.values[f.key]" type="number" :min="f.min" :max="f.max" :aria-invalid="invalid" />
            <input v-else :id="id" v-model.trim="m.values[f.key]" type="text" autocomplete="off" :aria-invalid="invalid" />
          </Field>
          <label v-else class="wz-choice"><input v-model="m.values[f.key]" type="checkbox" /> {{ f.label }}</label>
        </template>
      </div>
      <p v-if="m.type === 'optional' && !optionalChoices.length" class="small muted">This environment's profile has no optional components.</p>
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
            <dl class="wz-dl">
              <dt>Risk</dt><dd><span class="wz-chip" :class="riskKind(m.preview.risk)">{{ m.preview.risk }}</span><span v-for="r in m.preview.riskReasons" :key="r" class="muted small"> {{ r }}.</span></dd>
              <dt>Resources</dt><dd>{{ m.preview.added.length }} added, {{ m.preview.diff.length - m.preview.added.length - m.preview.removed.length }} changed fields, {{ m.preview.removed.length }} removed</dd>
              <dt>Capacity change</dt><dd>{{ m.preview.capacityImpact.vms >= 0 ? '+' : '' }}{{ m.preview.capacityImpact.vms }} VM, {{ m.preview.capacityImpact.cores >= 0 ? '+' : '' }}{{ m.preview.capacityImpact.cores }} vCPU, {{ m.preview.capacityImpact.memory_mb >= 0 ? '+' : '' }}{{ m.preview.capacityImpact.memory_mb }} MB RAM, {{ m.preview.capacityImpact.disk_gb >= 0 ? '+' : '' }}{{ m.preview.capacityImpact.disk_gb }} GB disk</dd>
              <dt>Estimated downtime</dt><dd>{{ fmtDuration(m.preview.downtime.seconds) }}</dd>
              <dt>Snapshot required</dt><dd>{{ m.preview.requires_snapshot ? 'Yes, taken automatically before the change' : 'No' }}</dd>
              <dt>Maintenance window</dt><dd>{{ m.preview.requires_maintenance ? 'Required (disruptive)' : 'Not required' }}</dd>
            </dl>
            <template v-if="m.preview.downtime.steps.length"><h3>Disruptive steps</h3><ul><li v-for="s in m.preview.downtime.steps" :key="s">{{ s }}</li></ul></template>
          </div>
          <div class="wz-card"><h2>Current vs proposed</h2><DiffTable :rows="m.preview.diff" /></div>
          <div class="wz-card"><h2>Capacity after this change</h2><CapacityList :lines="m.preview.capacity" /></div>
          <div v-if="needsWindow(m.preview)" class="wz-card">
            <h2>Maintenance window</h2>
            <Unavailable v-if="windows?.state === 'unavailable'" what="Maintenance windows" endpoint="GET /api/v1/maintenance" :status="windows.status" />
            <Field label="Run during" :error="reviewErr.window" hint="Only a window that is active right now can be used; the plan re-checks it when it runs." v-slot="{ id, invalid }">
              <select :id="id" v-model="m.maintenanceWindowId" :aria-invalid="invalid" :disabled="m.override"><option value="">None</option><option v-for="w in activeWindows" :key="w.id" :value="w.id">{{ fmtWindow(w) }}</option></select>
            </Field>
            <p v-if="!activeWindows.length" class="small muted">No maintenance window is active. Create one under <a href="#/maintenance">Maintenance</a>, or request an override.</p>
            <label class="wz-choice mt"><input v-model="m.override" type="checkbox" :disabled="!!m.maintenanceWindowId" /> No window: request an explicit override (makes the plan high risk: two approvers)</label>
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
