<script setup lang="ts">
// Step 2: what Office Unbound found. Read-only. Nothing here is authorised yet.
import { computed } from 'vue'
import { Banner, CapacityBar } from '../../../wizards/kit'
import { bridgesOf, discoverySummary, gbOf, hasUnmanaged, mergeStorage, poolsOf, type WizardModel } from '../model'
const props = defineProps<{ m: WizardModel }>()
const d = computed(() => props.m.discovery)
const storages = computed(() => (d.value ? mergeStorage(d.value.storage) : []))
const unmanaged = computed(() => (d.value ? hasUnmanaged(d.value) : []))
</script>
<template>
  <div>
    <template v-if="d">
      <Banner kind="info" title="Nothing is authorised yet">This is what exists in your cluster. Office Unbound can see it, but it may only use what you explicitly allow on the next step.</Banner>
      <div class="pv-tiles" role="list">
        <div v-for="t in discoverySummary(d)" :key="t.label" class="pv-tile" role="listitem"><b>{{ t.value }}</b><span>{{ t.label }}</span></div>
      </div>
      <Banner v-if="unmanaged.length" kind="warn" title="Some nodes are invisible to this token">{{ unmanaged.join(', ') }} cannot be audited with this token, so their capacity is unknown (not idle). They cannot be selected until the token can see them.</Banner>
      <Banner v-for="w in d.warnings" :key="w" kind="warn">{{ w }}</Banner>

      <div class="wz-card"><h2>Nodes</h2>
        <div class="wz-grid">
          <div v-for="n in d.nodes" :key="n.name" class="pv-res">
            <div class="wz-row"><b>{{ n.name }}</b><span class="wz-chip" :class="n.status === 'online' ? 'ok' : 'bad'">{{ n.status }}</span><span v-if="!n.managed" class="wz-chip warn">not visible</span></div>
            <template v-if="n.managed && n.mem_total">
              <CapacityBar label="Memory" :total="Math.round(gbOf(n.mem_total))" :used="Math.round(gbOf(n.mem_used))" unit="GiB" />
              <CapacityBar v-if="n.cpu_total" label="CPU" :total="n.cpu_total" :used="Math.round(((n.cpu_pct ?? 0) / 100) * n.cpu_total * 10) / 10" unit="cores" />
            </template>
            <p v-else class="muted small">No capacity data.</p>
          </div>
        </div>
      </div>

      <div class="wz-card"><h2>Storage</h2>
        <p v-if="!storages.length" class="muted">No storage visible.</p>
        <div v-for="s in storages" :key="s.name" class="pv-res">
          <div class="wz-row"><b>{{ s.name }}</b><span class="muted small">{{ s.type }} &middot; {{ s.content.join(', ') || 'no content types' }}<template v-if="s.shared"> &middot; shared</template></span><span v-if="!s.active" class="wz-chip warn">inactive</span></div>
          <CapacityBar v-if="s.total" label="Space" :total="Math.round(gbOf(s.total))" :used="Math.round(gbOf(s.used))" unit="GiB" />
        </div>
      </div>

      <div class="wz-grid two">
        <div class="wz-card"><h2>Networks</h2>
          <p v-if="!bridgesOf(d).length" class="muted">None visible.</p>
          <ul class="pv-list"><li v-for="b in bridgesOf(d)" :key="b.name"><b>{{ b.name }}</b> <span class="muted small">{{ b.kind }}<template v-if="b.vlan_aware"> &middot; VLAN-aware</template></span></li></ul>
        </div>
        <div class="wz-card"><h2>Templates and pools</h2>
          <p class="muted small">Templates can be cloned into new VMs. Pools group guests.</p>
          <ul class="pv-list"><li v-for="t in d.templates" :key="t.vmid"><b>{{ t.name ?? 'template' }}</b> <span class="mono muted">#{{ t.vmid }}</span></li><li v-if="!d.templates.length" class="muted">No templates found.</li></ul>
          <p class="small"><b>Pools:</b> {{ poolsOf(d).join(', ') || 'none yet' }}</p>
        </div>
      </div>
    </template>
    <template v-else>
      <Banner kind="info" title="Your cluster will be read after setup">With {{ m.method === 'admin' ? 'a temporary administrator login' : 'a setup package' }}, Office Unbound does not read the cluster before it has a token of its own. On the next step, type the names of what you want to authorise, exactly as they appear in Proxmox. The Review and Verify steps check them.</Banner>
      <div class="wz-card"><h2>What happens next</h2>
        <ul class="pv-list"><li>You choose an access level and the nodes, storage, pools and networks that are allowed.</li><li>You see every account, role and permission that will be created before anything changes.</li><li>Office Unbound verifies the result against what Proxmox actually enforces.</li></ul>
      </div>
    </template>
  </div>
</template>
