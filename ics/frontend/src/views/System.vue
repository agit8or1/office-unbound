<script setup lang="ts">
import { computed } from 'vue'
import { get, type SystemInfo } from '../api'
import { COMPONENT_LABELS, buildLabel } from '../format'
import { fmtTime, useLoad } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import Skeleton from '../ui/Skeleton.vue'

const sys = useLoad(() => get<SystemInfo>('system'))
const comps = computed(() => Object.entries(sys.data.value?.components ?? {}).map(([k, v]) => ({ key: k, label: COMPONENT_LABELS[k] ?? k, version: v })))
const ifaces = computed(() => Object.entries(sys.data.value?.interfaces ?? {}))
</script>
<template>
  <div class="page">
    <PageHeader title="System" sub="Installed Office Unbound version, build and component versions." help="All values are read from the API; nothing is hard-coded in the console." />
    <ErrorBox :error="sys.error.value" />
    <Skeleton v-if="!sys.data.value && !sys.error.value" />
    <template v-else-if="sys.data.value">
      <Card title="This installation" :hint="buildLabel(sys.data.value)">
        <dl class="kv" data-testid="build-facts">
          <dt>Product</dt><dd>{{ sys.data.value.product }}</dd>
          <dt>Version</dt><dd>{{ sys.data.value.version }}</dd>
          <dt>Commit</dt><dd class="mono">{{ sys.data.value.commit ?? 'unknown' }}<span v-if="sys.data.value.dirty"> (built with local modifications)</span></dd>
          <dt>Built</dt><dd>{{ sys.data.value.built_at ? fmtTime(sys.data.value.built_at) : 'unknown' }}</dd>
          <dt>API</dt><dd>{{ sys.data.value.api }}</dd>
          <dt>Database schema</dt><dd class="mono">{{ sys.data.value.schema?.database ?? 'not readable by the service' }} (build head {{ sys.data.value.schema?.build_head ?? 'unknown' }})</dd>
        </dl>
      </Card>
      <Card title="Pending updates" hint="Read-only comparison with the release list bundled at install time. No network check is made.">
        <div data-testid="updates">
          <p v-if="sys.data.value.updates.update_available">
            <StatusBadge s="warning" text="Update available" /> Version {{ sys.data.value.updates.latest_known }} ({{ sys.data.value.updates.latest_date }}) is newer than the installed {{ sys.data.value.updates.current }}.
            <a v-if="sys.data.value.updates.notes_url" :href="sys.data.value.updates.notes_url" target="_blank" rel="noopener noreferrer">Release notes</a>
          </p>
          <p v-else-if="sys.data.value.updates.latest_known"><StatusBadge s="ok" text="Up to date" /> Installed {{ sys.data.value.updates.current }} is the latest release known to this installation.</p>
          <p v-else class="muted">No release list is bundled with this installation.</p>
          <p class="muted">Updating is done by an operator from a clean checkout of the release tag (docs/RELEASING.md); this page never changes anything.</p>
        </div>
      </Card>
      <Card title="Component versions" flush>
        <div class="tablewrap">
          <table data-testid="components">
            <thead><tr><th>Component</th><th>Version</th></tr></thead>
            <tbody>
              <tr v-for="c in comps" :key="c.key"><td>{{ c.label }}</td><td class="mono">{{ c.version }}</td></tr>
              <tr v-for="[k, v] in ifaces" :key="k"><td>Interface: {{ k }}</td><td class="mono">{{ v }}</td></tr>
            </tbody>
          </table>
        </div>
      </Card>
    </template>
  </div>
</template>
