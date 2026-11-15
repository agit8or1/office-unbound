<script setup lang="ts">
// Access scope: preset cards, then exactly which nodes / storage / pools / bridges / templates are authorised.
// Used by the connection wizard and by "Change access" on the permissions page.
import { computed } from 'vue'
import { Banner, Field, HelpNote } from '../../wizards/kit'
import type { Errors } from '../../wizards/kit'
import ChipList from './ChipList.vue'
import {
  CAPABILITIES, DEFAULT_POOL, FULL_ADMIN_CONSEQUENCES, NEVER_GRANTED, PRESETS, SCOPE_MODES, SINGLE_NODE_NOTES, bridgesOf, fmtBytes, fmtRanges, parseNames, parseRanges, parseVmids, poolsOf, storageChoices, suggestScope,
  type Capability, type Preset, type ScopeMode, type WizardModel,
} from './model'
const props = defineProps<{ m: WizardModel; errors: Errors; compactAdvanced?: boolean; scopeLocked?: boolean }>()
const d = computed(() => props.m.discovery)
const storages = computed(() => storageChoices(d.value, props.m.scopeMode, props.m.scope.nodes, props.m.riskOverrides))
const single = computed(() => props.m.scopeMode === 'single_node')
function pickMode(id: ScopeMode) {
  props.m.scopeMode = id
  if (id === 'whole_cluster') props.m.riskOverrides = []
  if (d.value) { const sg = suggestScope(d.value, props.m.preset, id); props.m.scope.nodes = sg.nodes; if (id === 'single_node') props.m.scope.storages = sg.storages }
}
function chooseNode(name: string) { props.m.scope.nodes.splice(0, props.m.scope.nodes.length, name); dropNonLocal() }
function dropNonLocal() { props.m.scope.storages = props.m.scope.storages.filter((n) => storages.value.find((x) => x.name === n)?.selectable ?? true) }
function toggleOverride(name: string) { toggle(props.m.riskOverrides, `shared_storage:${name}`) }
const bridges = computed(() => (d.value ? bridgesOf(d.value) : []))
const pools = computed(() => (d.value ? poolsOf(d.value) : []))
const templates = computed(() => d.value?.templates ?? [])
const nodes = computed(() => d.value?.nodes ?? [])
const existingPools = computed(() => new Set(pools.value))
const newPools = computed(() => props.m.scope.pools.filter((p) => !existingPools.value.has(p)))

function toggle(list: string[], v: string) { const i = list.indexOf(v); if (i >= 0) list.splice(i, 1); else list.push(v) }
function toggleNum(list: number[], v: number) { const i = list.indexOf(v); if (i >= 0) list.splice(i, 1); else list.push(v) }
function pick(p: Preset) {
  props.m.preset = p
  if (p !== 'full_admin') props.m.acknowledgeFullAdmin = false
  if (!props.m.scopeSuggested && d.value) { Object.assign(props.m.scope, suggestScope(d.value, p, props.m.scopeMode)); props.m.scopeSuggested = true }
}
function toggleCap(c: Capability) { const i = props.m.capabilities.indexOf(c); if (i >= 0) props.m.capabilities.splice(i, 1); else props.m.capabilities.push(c) }
const rangesText = computed({ get: () => fmtRanges(props.m.scope.vmid_ranges), set: (v: string) => { props.m.scope.vmid_ranges = parseRanges(v) } })
const protectedText = computed({ get: () => props.m.scope.protected_vmids.join(', '), set: (v: string) => { props.m.scope.protected_vmids = parseVmids(v) } })
const numOrNull = (v: unknown) => (v === '' || v === null || v === undefined ? null : Number(v))
const caps = computed(() => props.m.scope)
const showChoice = computed(() => props.m.preset !== 'full_admin')
const needsDeploy = computed(() => props.m.preset === 'deploy' || (props.m.preset === 'custom' && (props.m.capabilities.includes('deploy') || props.m.capabilities.includes('template_clone'))))
function addGrant() { props.m.customGrants.push({ path: '', privileges: [], why: '' }) }
const grantText = (g: { privileges: string[] }) => g.privileges.join(', ')
</script>

<template>
  <div class="pv-scope">
    <div class="wz-cards pv-presets" role="radiogroup" aria-label="Access level">
      <button v-for="p in PRESETS" :key="p.id" type="button" class="wz-pick" :class="{ 'pv-high': p.risk === 'high' }" role="radio" :aria-checked="m.preset === p.id" :aria-pressed="m.preset === p.id" @click="pick(p.id)">
        <span class="wz-row"><b>{{ p.title }}</b>
          <span class="wz-chip" :class="p.risk === 'high' ? 'bad' : p.risk === 'low' ? 'ok' : 'info'">{{ p.risk === 'high' ? 'High risk' : p.risk === 'low' ? 'Read only' : m.preset === p.id && p.id === 'deploy' ? 'Recommended' : 'Scoped' }}</span></span>
        <span class="muted small">{{ p.blurb }}</span>
        <ul class="pv-list small"><li v-for="c in p.can" :key="c" class="pv-yes">{{ c }}</li><li v-for="c in p.cannot" :key="c" class="pv-no">{{ c }}</li></ul>
      </button>
    </div>

    <template v-if="m.preset === 'full_admin'">
      <Banner kind="bad" title="Full cluster administration is high risk">
        <ul class="pv-list"><li v-for="c in FULL_ADMIN_CONSEQUENCES" :key="c">{{ c }}</li></ul>
        <p class="small">Prefer "Deployment &amp; management" with a dedicated pool. You can widen access later, with approval.</p>
        <label class="wz-choice"><input v-model="m.acknowledgeFullAdmin" type="checkbox" /> <span>I understand these consequences and I am authorised to grant this access.</span></label>
        <p v-if="errors.ack" class="bad-text" role="alert">{{ errors.ack }}</p>
      </Banner>
    </template>

    <template v-if="m.preset === 'custom'">
      <div class="wz-card">
        <h2>Kinds of permission</h2>
        <div class="wz-grid">
          <label v-for="c in CAPABILITIES" :key="c.id" class="wz-choice"><input type="checkbox" :checked="m.capabilities.includes(c.id)" @change="toggleCap(c.id)" /><span><b>{{ c.title }}</b><br /><span class="muted small">{{ c.text }}</span></span></label>
        </div>
        <p v-if="errors.capabilities" class="bad-text" role="alert">{{ errors.capabilities }}</p>
      </div>
    </template>

    <template v-if="showChoice">
      <p v-if="m.scopeSuggested && d" class="muted small pv-suggest">Pre-filled with suggestions from your cluster. Nothing is granted until you continue; the Review step lists the exact result.</p>
      <p v-if="errors.scope" class="bad-text" role="alert">{{ errors.scope }}</p>

      <Banner v-if="scopeLocked" kind="info" title="Scope is changed separately">This integration is set to <b>{{ single ? 'one node only' : 'the whole cluster' }}</b>. To change that, close this and use <b>Change scope</b>: it shows what Proxmox will allow before and after.</Banner>
      <div v-else class="wz-card pv-scopemode">
        <h2>How much of the cluster?</h2>
        <p class="muted small">This decides what Proxmox itself will allow the integration to reach. You can change it later.</p>
        <div class="wz-cards" role="radiogroup" aria-label="Scope">
          <button v-for="o in SCOPE_MODES" :key="o.id" type="button" class="wz-pick" role="radio" :aria-checked="m.scopeMode === o.id" :aria-pressed="m.scopeMode === o.id" @click="pickMode(o.id)">
            <span class="wz-row"><b>{{ o.title }}</b><span class="wz-chip" :class="o.id === 'single_node' ? 'ok' : 'info'">{{ o.badge }}</span></span>
            <span class="muted small">{{ o.blurb }}</span>
            <ul class="pv-list small"><li v-for="c in o.can" :key="c" class="pv-yes">{{ c }}</li><li v-for="c in o.cannot" :key="c" class="pv-no">{{ c }}</li></ul>
          </button>
        </div>
        <Banner v-if="single" kind="info" title="What this does and does not guarantee"><ul class="pv-list small"><li v-for="n in SINGLE_NODE_NOTES" :key="n">{{ n }}</li></ul></Banner>
      </div>

      <div class="wz-card">
        <h2>{{ single ? 'Which node?' : 'Nodes' }}</h2>
        <template v-if="single">
          <p class="muted small">Office Unbound will be able to see and use this node only. <span class="wz-chip ok">Enforced by Proxmox</span> for visibility and disks; <span class="wz-chip info">Office Unbound</span> also refuses placing VMs anywhere else.</p>
          <div v-if="nodes.length" class="pv-pick" role="radiogroup" aria-label="Node">
            <label v-for="n in nodes" :key="n.name" class="wz-choice pv-opt"><input type="radio" name="scope-node" :checked="caps.nodes[0] === n.name" :disabled="!n.managed || scopeLocked" @change="chooseNode(n.name)" />
              <span><b>{{ n.name }}</b> <span class="wz-chip" :class="n.status === 'online' ? 'ok' : 'warn'">{{ n.status }}</span><span v-if="!n.managed" class="muted small"> not visible to this token</span></span></label>
          </div>
          <ChipList v-else v-model="m.scope.nodes" label="Node name" placeholder="Type the node name, press Enter" />
          <p v-if="errors.nodes" class="bad-text" role="alert">{{ errors.nodes }}</p>
          <HelpNote title="Advanced: allow more than one node">
            <p class="muted small">Each extra node is another place Proxmox lets the integration act. Storage must then be local to the selected nodes.</p>
            <div v-if="nodes.length" class="pv-pick"><label v-for="n in nodes" :key="n.name" class="wz-choice pv-opt"><input type="checkbox" :checked="caps.nodes.includes(n.name)" :disabled="!n.managed || scopeLocked" @change="toggle(m.scope.nodes, n.name); dropNonLocal()" /><span><b>{{ n.name }}</b></span></label></div>
            <label class="wz-choice"><input type="checkbox" :checked="m.riskOverrides.includes('migrate')" @change="toggle(m.riskOverrides, 'migrate'); m.allowMigrate = m.riskOverrides.includes('migrate')" /> Allow moving VMs between the selected nodes <span class="wz-chip bad">high risk</span></label>
          </HelpNote>
        </template>
        <template v-else>
          <p class="muted small">Every node, including ones that join later, is visible to Office Unbound (<span class="wz-chip ok">Proxmox</span>). Office Unbound only changes nodes that exist today; add new ones later by changing the scope (<span class="wz-chip info">Office Unbound</span>).</p>
          <ul class="pv-list small"><li v-for="n in nodes" :key="n.name"><b>{{ n.name }}</b> <span class="wz-chip" :class="n.status === 'online' ? 'ok' : 'warn'">{{ n.status }}</span></li></ul>
        </template>
      </div>

      <div class="wz-card">
        <h2>Pools</h2>
        <p class="muted small">A pool is a folder of guests in Proxmox. Proxmox itself keeps the account inside it. Name a new pool and Office Unbound creates it.</p>
        <div v-if="pools.length" class="pv-pick"><label v-for="p in pools" :key="p" class="wz-choice pv-opt"><input type="checkbox" :checked="caps.pools.includes(p)" @change="toggle(m.scope.pools, p)" /><span><b>{{ p }}</b> <span class="muted small">existing</span></span></label></div>
        <div v-if="newPools.length" class="pv-pick"><label v-for="p in newPools" :key="p" class="wz-choice pv-opt"><input type="checkbox" checked @change="toggle(m.scope.pools, p)" /><span><b>{{ p }}</b> <span class="wz-chip info">new, will be created</span></span></label></div>
        <Field :label="pools.length ? 'Add a new pool' : 'Pools'" :error="errors.pools" :hint="'Suggested: ' + DEFAULT_POOL" v-slot="{ id }"><ChipList :id="id" :model-value="[]" label="New pool" placeholder="Pool name, press Enter" @update:model-value="(v) => v.forEach((x) => { if (!m.scope.pools.includes(x)) m.scope.pools.push(x) })" /></Field>
      </div>

      <div class="wz-card">
        <h2>Storage</h2>
        <p class="muted small">Where new disks may be placed. Proxmox enforces this per storage.<template v-if="single"> With one node only, just storage that exists only on that node is offered, so a disk can never be placed on another node.</template></p>
        <div v-if="storages.length" class="pv-pick">
          <label v-for="s in storages" :key="s.name" class="wz-choice pv-opt pv-wide" :class="{ 'pv-disabled': !s.selectable }"><input type="checkbox" :checked="caps.storages.includes(s.name)" :disabled="!s.selectable" @change="toggle(m.scope.storages, s.name)" />
            <span class="pv-grow"><b>{{ s.name }}</b> <span class="muted small">{{ s.type }} &middot; {{ s.content.join(', ') || 'no content types' }}<template v-if="s.shared"> &middot; shared</template></span>
              <span v-if="!s.selectable" class="wz-chip warn">not available in one-node mode</span><span v-if="!s.selectable" class="muted small">{{ s.reason }}</span>
              <span v-if="s.overridden" class="wz-chip bad">high-risk exception</span>
              <span v-if="s.total" class="pv-mini"><i :ref="(el) => { if (el) (el as HTMLElement).style.width = Math.min(100, ((s.used ?? 0) / s.total!) * 100) + '%' }"></i></span>
              <span v-if="s.total" class="muted small">{{ fmtBytes(s.total - (s.used ?? 0)) }} free of {{ fmtBytes(s.total) }}</span></span></label>
        </div>
        <ChipList v-else v-model="m.scope.storages" label="Storage names" placeholder="Storage name, press Enter" />
        <p v-if="errors.storages" class="bad-text" role="alert">{{ errors.storages }}</p>
        <HelpNote v-if="single && storages.some((x) => !x.selectable || x.overridden)" title="Advanced: use a shared storage anyway (high risk)">
          <p class="small">A shared storage lets Proxmox place disks for guests on any node. The one-node limit would then rest on Office Unbound alone. Only do this if you understand and accept that.</p>
          <label v-for="x in storages.filter((y) => !y.selectable || y.overridden)" :key="x.name" class="wz-choice"><input type="checkbox" :checked="x.overridden" @change="toggleOverride(x.name)" /> Allow <b>{{ x.name }}</b> <span class="wz-chip bad">high risk</span></label>
        </HelpNote>
      </div>

      <div class="wz-card">
        <h2>Networks</h2>
        <p class="muted small">Bridges or SDN networks new VMs may attach to. Proxmox enforces this.</p>
        <div v-if="bridges.length" class="pv-pick"><label v-for="b in bridges" :key="b.name" class="wz-choice pv-opt"><input type="checkbox" :checked="caps.networks.includes(b.name)" @change="toggle(m.scope.networks, b.name)" /><span><b>{{ b.name }}</b> <span class="muted small">{{ b.kind }}<template v-if="b.vlan_aware"> &middot; VLAN-aware</template></span></span></label></div>
        <ChipList v-else v-model="m.scope.networks" label="Bridge names" placeholder="vmbr0, press Enter" />
        <p v-if="errors.networks" class="bad-text" role="alert">{{ errors.networks }}</p>
      </div>

      <div v-if="needsDeploy || m.scope.template_vmids.length || templates.length" class="wz-card">
        <h2>Templates</h2>
        <p class="muted small">Only these template VMs may be cloned. Proxmox enforces this per template.</p>
        <div v-if="templates.length" class="pv-pick"><label v-for="t in templates" :key="t.vmid" class="wz-choice pv-opt"><input type="checkbox" :checked="caps.template_vmids.includes(t.vmid)" @change="toggleNum(m.scope.template_vmids, t.vmid)" /><span><b>{{ t.name ?? 'template' }}</b> <span class="mono muted">#{{ t.vmid }} on {{ t.node }}</span></span></label></div>
        <Field v-else label="Template VM IDs" :error="errors.templates" hint="Numbers, separated by commas." v-slot="{ id }"><input :id="id" type="text" :value="m.scope.template_vmids.join(', ')" @change="m.scope.template_vmids = parseVmids(($event.target as HTMLInputElement).value)" /></Field>
        <p v-if="errors.templates" class="bad-text" role="alert">{{ errors.templates }}</p>
      </div>

      <div v-if="m.preset === 'custom' && m.capabilities.includes('backup')" class="wz-card">
        <h2>Backup storage</h2>
        <ChipList v-model="m.scope.backup_storages" label="Backup storage" placeholder="Storage name, press Enter" />
        <p v-if="errors.backup" class="bad-text" role="alert">{{ errors.backup }}</p>
      </div>

      <HelpNote title="Advanced details: limits, guest types, account names" :open="!compactAdvanced && false">
        <p class="muted small">These limits cannot be expressed in Proxmox permissions, so Office Unbound applies them itself. They are saved with the policy; the Review step shows which are enforced today.</p>
        <div class="wz-grid">
          <Field label="Guest types" v-slot="{ id }"><div :id="id" class="wz-row"><label class="wz-choice"><input v-model="m.scope.guest_types" type="checkbox" value="qemu" /> Virtual machines</label><label class="wz-choice"><input v-model="m.scope.guest_types" type="checkbox" value="lxc" /> Containers</label></div></Field>
          <Field label="VMID ranges" :error="errors.vmid" hint="For example 9000-9099, 9200-9299" v-slot="{ id }"><input :id="id" v-model.lazy="rangesText" type="text" /></Field>
          <Field label="Never touch these VMIDs" hint="Comma separated. The Office Unbound server is always protected." v-slot="{ id }"><input :id="id" v-model.lazy="protectedText" type="text" /></Field>
          <Field label="Max CPU cores per VM" :error="errors.max_cores" optional v-slot="{ id }"><input :id="id" type="number" min="1" :value="m.scope.max_cores ?? ''" @input="m.scope.max_cores = numOrNull(($event.target as HTMLInputElement).value)" /></Field>
          <Field label="Max memory per VM (MB)" :error="errors.max_memory" optional v-slot="{ id }"><input :id="id" type="number" min="128" :value="m.scope.max_memory_mb ?? ''" @input="m.scope.max_memory_mb = numOrNull(($event.target as HTMLInputElement).value)" /></Field>
          <Field label="Max disk per VM (GB)" :error="errors.max_disk" optional v-slot="{ id }"><input :id="id" type="number" min="1" :value="m.scope.max_disk_gb ?? ''" @input="m.scope.max_disk_gb = numOrNull(($event.target as HTMLInputElement).value)" /></Field>
          <Field label="Service account name" hint="Created in the Proxmox VE realm (@pve): no password, no shell." v-slot="{ id }"><input :id="id" v-model.trim="m.serviceUser" type="text" /></Field>
          <Field label="Role name prefix" v-slot="{ id }"><input :id="id" v-model.trim="m.rolePrefix" type="text" /></Field>
          <Field label="Token name prefix" v-slot="{ id }"><input :id="id" v-model.trim="m.tokenBase" type="text" /></Field>
        </div>
        <div class="wz-row mt">
          <label v-if="!single" class="wz-choice"><input v-model="m.allowMigrate" type="checkbox" /> Allow moving VMs between nodes</label>
          <label class="wz-choice"><input v-model="m.guestAgent" type="checkbox" /> Read guest-agent information</label>
          <label v-if="!single" class="wz-choice"><input v-model="m.allowCicustom" type="checkbox" /> Allow cloud-init snippets <span class="wz-chip warn">needs extra approval</span></label>
          <p v-else class="muted small">Cloud-init snippets and VM moves are not available in one-node mode (they need access to the whole cluster).</p>
        </div>
        <template v-if="m.preset === 'custom' && m.capabilities.includes('custom')">
          <h3>Custom grants</h3>
          <p class="muted small">Extra privileges on exact ACL paths. Each is checked against the privilege list for your Proxmox version.</p>
          <div v-for="(g, i) in m.customGrants" :key="i" class="wz-grid pv-grant">
            <Field label="Path" v-slot="{ id }"><input :id="id" v-model.trim="g.path" type="text" placeholder="/storage/local" /></Field>
            <Field label="Privileges" v-slot="{ id }"><input :id="id" type="text" :value="grantText(g)" placeholder="Datastore.Audit, Datastore.AllocateSpace" @change="g.privileges = parseNames(($event.target as HTMLInputElement).value)" /></Field>
            <Field label="Why" v-slot="{ id }"><input :id="id" v-model="g.why" type="text" /></Field>
            <button type="button" class="wz-btn" @click="m.customGrants.splice(i, 1)">Remove</button>
          </div>
          <button type="button" class="wz-btn" @click="addGrant">Add a grant</button>
          <p v-if="errors.grants" class="bad-text" role="alert">{{ errors.grants }}</p>
        </template>
        <h3>Never granted, whatever you choose</h3>
        <ul class="pv-list small"><li v-for="n in NEVER_GRANTED" :key="n[0]"><span class="mono">{{ n[0] }}</span>: {{ n[1] }}</li></ul>
      </HelpNote>
    </template>
  </div>
</template>
