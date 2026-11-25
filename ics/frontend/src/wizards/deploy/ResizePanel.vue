<script setup lang="ts">
// "Re-run sizing" on a deployment: compares measured usage with the applied plan (POST /deployments/{slug}/resize-plan, writes nothing)
// and lets the operator submit the proposed deployment.change through the normal approval flow.
import { computed, ref } from 'vue'
import { Banner, fmtDuration } from '../kit'
import '../kit/kit.css'
import '../../views/providers/providers.css'
import RunPanel from '../../views/providers/RunPanel.vue'
import { useRun } from '../../views/providers/run'
import { canSubmitChange, changeParams, needsMaintenance, recommendationRows, resizeApi, type ResizeResponse, type ResizeWindow } from './resize'
const props = defineProps<{ slug: string }>()
const win = ref<ResizeWindow>('7d')
const r = ref<ResizeResponse | null>(null)
const busy = ref(false)
const error = ref('')
const override = ref(false)
const run = useRun()
const rows = computed(() => recommendationRows(r.value))
const pc = computed(() => r.value?.proposed_change ?? null)
const disruptive = computed(() => needsMaintenance(r.value))
async function rerun() {
  busy.value = true; error.value = ''; override.value = false; run.reset()
  try { r.value = await resizeApi.resizePlan(props.slug, win.value) } catch (e) { r.value = null; error.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false }
}
function submit() { if (r.value && canSubmitChange(r.value, override.value)) void run.start('deployment.change', changeParams(r.value, override.value)) }
</script>

<template>
  <section class="wz dw-resize wz-card" aria-labelledby="resize-h">
    <h2 id="resize-h">Sizing check</h2>
    <p class="muted small">Compare actual usage with the planned size. This only calculates; changes need your approval.</p>
    <div class="wz-row">
      <label for="resize-win" class="small">Usage period</label>
      <select id="resize-win" v-model="win"><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select>
      <button type="button" class="wz-btn" :disabled="busy" @click="rerun">{{ busy ? 'Calculating…' : 'Re-run sizing' }}</button>
    </div>
    <Banner v-if="error" kind="bad" title="Sizing check failed">{{ error }}</Banner>
    <template v-if="r">
      <p v-if="r.note" class="small muted">{{ r.note }}</p>
      <p v-if="!rows.length" class="muted">No changes recommended.</p>
      <div v-else class="wz-table-wrap"><table>
        <thead><tr><th>Recommendation</th><th>VM</th><th>From</th><th>To</th><th>Impact</th></tr></thead>
        <tbody><tr v-for="(x, i) in rows" :key="i">
          <td><b>{{ x.title }}</b><div class="small muted">{{ x.message }}</div></td><td class="mono">{{ x.vm || '-' }}</td><td>{{ x.from || '-' }}</td><td>{{ x.to || '-' }}</td>
          <td><span v-if="x.downtime" class="wz-chip warn">downtime</span> <span v-if="x.migration" class="wz-chip warn">data migration</span><span v-if="!x.downtime && !x.migration" class="muted">none</span></td>
        </tr></tbody>
      </table></div>
      <Banner v-if="r.model_drift?.differs" kind="info" title="Sizing models changed">{{ r.model_drift.note ?? 'The current sizing models differ from the ones this deployment was planned with.' }}</Banner>
      <template v-if="pc">
        <h3>Proposed change</h3>
        <ul class="wz-checks">
          <li><span class="wz-chip" :class="pc.requires_downtime ? 'warn' : 'ok'">{{ pc.requires_downtime ? 'downtime' : 'no downtime' }}</span><span>{{ pc.requires_downtime ? 'Affected VMs restart' : 'Runs without restarts' }}<span v-if="pc.diff?.downtime_seconds"> ({{ fmtDuration(pc.diff.downtime_seconds) }})</span>.</span></li>
          <li><span class="wz-chip" :class="pc.requires_data_migration ? 'warn' : 'ok'">{{ pc.requires_data_migration ? 'data migration' : 'no migration' }}</span><span>{{ pc.requires_data_migration ? 'Moves VMs: ' + (pc.moved_vms ?? []).join(', ') : 'No data is moved.' }}</span></li>
        </ul>
        <Banner v-for="(e, i) in pc.errors" :key="i" kind="bad" title="Blocks this change">{{ typeof e === 'string' ? e : (e as { message?: string }).message }}</Banner>
        <label v-if="disruptive" class="wz-choice mt"><input v-model="override" type="checkbox" /> <span>Run outside a maintenance window (explicit override; needs approval as a high-risk change).</span></label>
        <div class="wz-row mt"><button type="button" class="wz-btn primary" :disabled="!canSubmitChange(r, override) || run.busy.value || !!run.created.value" @click="submit">Submit change for approval</button></div>
        <RunPanel v-if="run.created.value || run.error.value" :run="run" what="Resize change" />
      </template>
    </template>
  </section>
</template>

<style>
.dw-resize { max-width: none; margin: 0; width: 100%; } /* a .wz block centres itself (margin: auto); inside the page column it spans the full width like every card */
</style>
