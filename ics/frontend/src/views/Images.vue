<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ApiError, get, post, type Endpoint, type PlanCreated } from '../api'
import { useLoad } from '../store'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import EmptyState from '../ui/EmptyState.vue'
import Skeleton from '../ui/Skeleton.vue'
import Button from '../ui/Button.vue'
import Drawer from '../ui/Drawer.vue'
import ErrorBox from '../components/ErrorBox.vue'

interface ImageRelease {
  release: string; verified: boolean; reason?: string; os?: string; version?: number; image?: string; sha256?: string; date?: string
  attestation_run_id?: string; floor_version?: number | null; default_template?: string
}
const rel = useLoad(() => get<{ configured: boolean; releases: ImageRelease[] }>('images/releases'), 60000)
const eps = useLoad(() => get<Endpoint[]>('endpoints'))
const usable = computed(() => (eps.data.value ?? []).filter((e) => e.credentials.provision.present && e.scope.allowed_pools.length))

const sel = ref<ImageRelease | null>(null)
const f = ref({ endpoint_id: '', pve_node: '', pool: '', import_storage: '', target_storage: '', bridge: '', template_name: '', allow_downgrade: false })
const busy = ref(false)
const err = ref<ApiError | null>(null)
const created = ref<PlanCreated | null>(null)
const ep = computed(() => usable.value.find((e) => e.id === f.value.endpoint_id))
const downgrade = computed(() => !!sel.value && sel.value.floor_version != null && (sel.value.version ?? 0) < sel.value.floor_version)

function open(r: ImageRelease) {
  sel.value = r; err.value = null; created.value = null
  f.value = { endpoint_id: usable.value[0]?.id ?? '', pve_node: '', pool: '', import_storage: '', target_storage: '', bridge: '', template_name: r.default_template ?? '', allow_downgrade: false }
}
watch(ep, (e) => {
  if (!e) return
  f.value.pve_node = e.scope.allowed_nodes[0] ?? ''
  f.value.pool = e.scope.allowed_pools[0] ?? ''
  f.value.import_storage = e.scope.allowed_storage.includes('local') ? 'local' : (e.scope.allowed_storage[0] ?? '')
  f.value.target_storage = e.scope.allowed_storage.find((s) => s !== f.value.import_storage) ?? f.value.import_storage
})
async function submit() {
  if (!sel.value) return
  busy.value = true; err.value = null
  const v = f.value
  try {
    created.value = await post<PlanCreated>('plans', { action: 'image.import', params: {
      endpoint_id: v.endpoint_id, pve_node: v.pve_node, release: sel.value.release, expected_sha256: sel.value.sha256,
      import_storage: v.import_storage, target_storage: v.target_storage, pool: v.pool, ...(v.bridge ? { bridge: v.bridge } : {}),
      ...(v.template_name ? { template_name: v.template_name } : {}), allow_downgrade: v.allow_downgrade } })
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <div class="page">
    <PageHeader title="Images" sub="Signed golden OS images that can become Proxmox templates for new deployments."
                help="Each release is verified here with the release key and test-runner key configured on this server, and against the version already accepted for that OS. Importing one is a high-risk change: an administrator proposes it and different approvers must agree.">
      <template #actions><Button size="sm" icon="refresh" :loading="rel.loading.value" @click="rel.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="rel.error.value" />
    <Skeleton v-if="rel.loading.value && !rel.data.value && !rel.error.value" />
    <EmptyState v-else-if="rel.data.value && !rel.data.value.configured" icon="inbox" title="No image releases directory"
                text="Set ICS_GUEST_GOLDEN_RELEASES_DIR (one sub-directory per signed release) and the release and test-runner keys on the server." />
    <EmptyState v-else-if="rel.data.value && !rel.data.value.releases.length" icon="inbox" title="No releases yet" text="Copy a signed release directory from the image build host into the releases directory." />
    <Card v-else-if="rel.data.value" title="Releases" hint="Only verified releases can be imported." data-testid="image-releases">
      <div class="tablewrap" tabindex="0" role="region" aria-label="Golden image releases">
        <table class="dense" aria-label="Golden image releases">
          <thead><tr><th>Release</th><th>OS</th><th>Version</th><th>Image</th><th>Status</th><th></th></tr></thead>
          <tbody>
            <tr v-for="r in rel.data.value.releases" :key="r.release" :data-testid="'img-' + r.release">
              <td class="mono">{{ r.release }}</td>
              <td>{{ r.os ?? '-' }}</td>
              <td>{{ r.version ?? '-' }}<span v-if="r.floor_version != null" class="muted small"> (accepted: {{ r.floor_version }})</span></td>
              <td class="mono small" :title="r.sha256">{{ r.image ?? '-' }}</td>
              <td><StatusBadge :s="r.verified ? 'ok' : 'failed'" :text="r.verified ? 'Verified' : 'Not verified'" /><div v-if="!r.verified" class="muted small">{{ r.reason }}</div></td>
              <td><Button v-if="r.verified" size="sm" variant="primary" :disabled="!usable.length" :title="usable.length ? '' : 'No integration with a provisioning credential'" @click="open(r)">Import</Button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>

    <Drawer v-if="sel" :title="'Import ' + sel.release" @close="sel = null">
      <div class="img-drawer">
        <template v-if="!created">
          <p class="muted small">Image <span class="mono">{{ sel.image }}</span>, SHA-256 <span class="mono">{{ sel.sha256 }}</span>. The server checks this exact hash again before anything is uploaded.</p>
          <label class="fld"><span>Integration</span>
            <select v-model="f.endpoint_id"><option v-for="e in usable" :key="e.id" :value="e.id">{{ e.display_name || e.name }}</option></select></label>
          <template v-if="ep">
            <label class="fld"><span>Node</span><select v-model="f.pve_node"><option v-for="n in ep.scope.allowed_nodes" :key="n">{{ n }}</option></select></label>
            <label class="fld"><span>Pool</span><select v-model="f.pool"><option v-for="p in ep.scope.allowed_pools" :key="p">{{ p }}</option></select></label>
            <label class="fld"><span>Upload storage (needs the "import" content type)</span><input v-model="f.import_storage" maxlength="64" /></label>
            <label class="fld"><span>Template disk storage</span><input v-model="f.target_storage" maxlength="64" /></label>
            <label class="fld"><span>Network bridge (optional)</span><input v-model="f.bridge" maxlength="32" /></label>
          </template>
          <label class="fld"><span>Template name</span><input v-model="f.template_name" maxlength="57" /></label>
          <label v-if="downgrade" class="row"><input v-model="f.allow_downgrade" type="checkbox" />
            <span>This version is older than the one already accepted ({{ sel.floor_version }}). Import anyway (the approvers see this).</span></label>
          <ErrorBox :error="err" />
          <div class="row">
            <Button variant="primary" :loading="busy" :disabled="!ep || (downgrade && !f.allow_downgrade)" @click="submit">Propose import</Button>
            <Button variant="ghost" @click="sel = null">Cancel</Button>
          </div>
        </template>
        <template v-else>
          <div class="alert ok" role="status"><span class="grow">Proposed. {{ created.approvals_required === 1 ? 'One approver' : created.approvals_required + ' different approvers' }} must now review it.</span></div>
          <div class="row"><Button variant="primary" :to="'/plans/' + created.plan_id">Open the approval</Button><Button variant="ghost" @click="sel = null">Close</Button></div>
        </template>
      </div>
    </Drawer>
  </div>
</template>
<style scoped>
.img-drawer { padding: 0 20px 20px; display: grid; gap: 12px; }
.fld { display: grid; gap: 4px; } .fld input, .fld select { width: 100%; font: inherit; }
</style>
