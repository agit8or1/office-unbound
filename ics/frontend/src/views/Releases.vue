<script setup lang="ts">
import { computed, ref } from 'vue'
import { ApiError, get, post, type PlanCreated, type PromotionCandidate, type Releases } from '../api'
import { fmtTime, session, useLoad } from '../store'
import { CHANNEL_BLURB, CHANNEL_LABEL, approverText, canPromote, componentSummary, evidenceView, pageState, promotePlanParams, promoteTitle, shortHash } from '../releases'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Button from '../ui/Button.vue'
import Drawer from '../ui/Drawer.vue'
import ErrorBox from '../components/ErrorBox.vue'

const rel = useLoad(() => get<Releases>('releases'), 30000)
const state = computed(() => pageState(rel.data.value))
const channel = (n: string) => rel.data.value?.channels.find((c) => c.name === n)
const recordsOk = computed(() => rel.data.value?.records_readable !== false)

const sel = ref<PromotionCandidate | null>(null)
const reason = ref('')
const busy = ref(false)
const err = ref<ApiError | null>(null)
const created = ref<PlanCreated | null>(null)
function open(c: PromotionCandidate) { sel.value = c; reason.value = ''; err.value = null; created.value = null }
function close() { sel.value = null }
async function submit() {
  if (!sel.value) return
  busy.value = true; err.value = null
  try {
    created.value = await post<PlanCreated>('plans', { action: 'release.promote', params: promotePlanParams(sel.value, reason.value) })
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
const may = (c: PromotionCandidate) => canPromote(c, rel.data.value!, session.user?.role ?? 'viewer')
</script>
<template>
  <div class="page">
    <PageHeader title="Releases" sub="Which package versions are in each channel, what testing says about them, and what can move forward."
                help="Packages move dev, then staging, then stable. Moving them forward is a change like any other: an administrator proposes it here and different approvers must agree in Approvals before the signed repository changes.">
      <template #actions><Button size="sm" icon="refresh" :loading="rel.loading.value" @click="rel.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="rel.error.value" />
    <Skeleton v-if="state === 'loading' && !rel.error.value" />
    <EmptyState v-else-if="state === 'not_configured'" icon="refresh" title="The package repository is not connected"
                text="This console can show channels once it is given read access to the signed package repository. Ask the person who installed Office Unbound to set ICS_RELEASE_REPO_DIR (and ICS_RELEASE_RECORDS_DIR for test results) on the server." />
    <EmptyState v-else-if="state === 'empty'" icon="inbox" title="No packages published yet" text="Build and publish a component first. It appears here in the Development channel." />
    <template v-else-if="rel.data.value">
      <div v-if="rel.data.value.records_readable === false" class="alert warn" role="status"><span class="grow">Test results cannot be read by this server, so every package shows as untested and nothing can be promoted from here.</span></div>

      <Card title="Ready to move forward" hint="Only complete, tested sets are offered. The exact files and hashes are shown before anything is proposed." data-testid="candidates">
        <EmptyState v-if="!rel.data.value.candidates.length" compact title="Nothing to promote" text="Every channel already holds what the previous one has." />
        <ul v-else class="rel-list">
          <li v-for="c in rel.data.value.candidates" :key="c.component + c.from_channel" class="rel-item" :data-testid="'cand-' + c.component + '-' + c.to_channel">
            <div class="rel-main">
              <b>{{ promoteTitle(c) }}</b>
              <div class="muted small">Now in {{ CHANNEL_LABEL[c.to_channel] }}: {{ componentSummary(channel(c.to_channel), c.component) }}</div>
              <div class="muted small">Would become: {{ componentSummary(channel(c.from_channel), c.component) }}</div>
              <ul v-if="c.blocked.length" class="small rel-block"><li v-for="b in c.blocked" :key="b">{{ b }}</li></ul>
            </div>
            <div class="rel-side">
              <StatusBadge :s="c.risk" :text="c.risk === 'high' ? 'High risk' : 'Normal risk'" />
              <span class="muted small">Needs {{ approverText(c.approvals_required) }}</span>
              <Button size="sm" variant="primary" :disabled="!may(c).ok" :title="may(c).why" @click="open(c)">Review and promote</Button>
            </div>
          </li>
        </ul>
      </Card>

      <div class="grid cols-3 rel-chans">
        <Card v-for="n in ['dev', 'staging', 'stable']" :key="n" :title="CHANNEL_LABEL[n]" :hint="CHANNEL_BLURB[n]">
          <p v-if="!channel(n)?.available" class="muted">This channel has not been indexed yet.</p>
          <p v-else-if="!channel(n)?.components.length" class="muted">Empty.</p>
          <template v-else>
            <p class="muted small">Indexed {{ fmtTime(channel(n)?.indexed_at) }}</p>
            <div v-for="c in channel(n)!.components" :key="c.component" class="rel-comp">
              <h3>{{ c.component }}</h3>
              <div class="tablewrap">
                <table class="dense" :aria-label="c.component + ' in ' + CHANNEL_LABEL[n]">
                  <thead><tr><th>Package</th><th>Version</th><th>Tests</th></tr></thead>
                  <tbody>
                    <tr v-for="p in c.packages" :key="p.file">
                      <td><span class="mono">{{ p.name }}</span><div class="muted small mono" :title="p.sha256">{{ shortHash(p.sha256) }}</div></td>
                      <td class="mono">{{ p.version }}</td>
                      <td><StatusBadge :s="evidenceView(p, recordsOk).tone === 'ok' ? 'ok' : evidenceView(p, recordsOk).tone === 'bad' ? 'failed' : evidenceView(p, recordsOk).tone === 'warn' ? 'warning' : 'idle'" :text="evidenceView(p, recordsOk).text" /></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </template>
        </Card>
      </div>
    </template>

    <Drawer v-if="sel" :title="promoteTitle(sel)" @close="close">
      <div class="rel-drawer">
        <template v-if="!created">
          <p>This proposes moving exactly these files. Nothing changes until {{ approverText(sel.approvals_required) }} other than you approve it in Approvals.</p>
          <div class="tablewrap">
            <table class="dense" aria-label="Exact package set" data-testid="promote-set">
              <thead><tr><th>File</th><th>SHA-256</th><th>Test record</th></tr></thead>
              <tbody>
                <tr v-for="p in sel.params.packages" :key="p.file">
                  <td class="mono">{{ p.file }}</td><td class="mono small" :title="p.sha256">{{ shortHash(p.sha256, 20) }}...</td>
                  <td class="mono small">{{ shortHash(sel.params.evidence.find((e) => e.sha256 === p.sha256)?.attestation_sha256, 16) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <label class="fld"><span>Reason (optional, shown to approvers)</span><textarea v-model="reason" rows="3" maxlength="500" /></label>
          <ErrorBox :error="err" />
          <div class="row">
            <Button variant="primary" :loading="busy" @click="submit">Propose promotion</Button>
            <Button variant="ghost" @click="close">Cancel</Button>
          </div>
        </template>
        <template v-else>
          <div class="alert ok" role="status"><span class="grow">Proposed. {{ created.approvals_required === 1 ? 'One approver' : created.approvals_required + ' different approvers' }} must now review it.</span></div>
          <div class="row"><Button variant="primary" :to="'/plans/' + created.plan_id">Open the approval</Button><Button variant="ghost" @click="close">Close</Button></div>
        </template>
      </div>
    </Drawer>
  </div>
</template>
<style scoped>
.rel-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 12px; }
.rel-item { display: flex; gap: 16px; justify-content: space-between; flex-wrap: wrap; padding: 12px 0; border-top: 1px solid var(--line); }
.rel-item:first-child { border-top: 0; padding-top: 0; }
.rel-main { flex: 1 1 320px; min-width: 0; }
.rel-side { display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
.rel-block { color: var(--bad); margin: 6px 0 0; padding-left: 18px; }
.rel-chans { margin-top: 18px; }
.rel-comp h3 { font-size: 13px; margin: 10px 0 4px; }
.rel-drawer { padding: 0 20px 20px; display: grid; gap: 14px; }
.fld { display: grid; gap: 4px; } .fld textarea { width: 100%; font: inherit; }
</style>
