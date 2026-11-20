<script setup lang="ts">
import { computed } from 'vue'
import { get, type ControllerInfo, type SystemInfo as BuildSystemInfo } from '../api'
import { RUNBOOK_URL, fmtSeconds, lagState, roleLabel } from '../controller'
import { fmtBytes, fmtTime, useLoad } from '../store'
import { ago, COMPONENT_LABELS, buildLabel } from '../format'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import Skeleton from '../ui/Skeleton.vue'
import Button from '../ui/Button.vue'
import ErrorBox from '../components/ErrorBox.vue'
import TenancyCard from '../components/TenancyCard.vue'

interface Thread { name: string; state: 'ok' | 'stalled' | 'off'; last_progress_seconds: number | null }
interface SystemInfo extends BuildSystemInfo {
  migration_head: string | null; ready: boolean; checks: Record<string, boolean>; heartbeat_age_seconds: number | null
  worker_enabled: boolean; threads: Thread[]; database_bytes: number | null; disk: { total: number; free: number } | null
  backup: { known: boolean; at: string | null }; controller?: ControllerInfo
}
const sys = useLoad(() => get<SystemInfo>('system'), 15000)
const comps = computed(() => Object.entries(sys.data.value?.components ?? {}).map(([k, v]) => ({ key: k, label: COMPONENT_LABELS[k] ?? k, version: v })))
const ifaces = computed(() => Object.entries(sys.data.value?.interfaces ?? {}))
const CHECK = { database: 'Database', worker: 'Background worker', audit_chain: 'Audit log integrity' } as Record<string, string>
const THREAD = { jobs: 'Job runner', monitor: 'Health monitor', inventory: 'Inventory collector', heartbeat: 'Heartbeat' } as Record<string, string>
const tone = (s: string) => (s === 'ok' ? 'ok' : s === 'off' ? 'idle' : 'critical')
</script>
<template>
  <div class="page">
    <PageHeader title="System" sub="Version, database state, background services and backups of this console server." help="Read-only status for administrators. Nothing here changes the system.">
      <template #actions><Button size="sm" icon="refresh" :loading="sys.loading.value" @click="sys.reload()">Refresh</Button></template>
    </PageHeader>
    <ErrorBox :error="sys.error.value" />
    <Skeleton v-if="!sys.data.value && !sys.error.value" />
    <template v-if="sys.data.value">
      <div class="grid cols-2">
        <TenancyCard />
        <Card title="Status">
          <dl class="sys">
            <dt>Overall</dt><dd><StatusBadge :s="sys.data.value.ready ? 'ok' : 'critical'" :text="sys.data.value.ready ? 'Ready' : 'Not ready'" /></dd>
            <template v-for="(ok, k) in (sys.data.value.checks ?? {})" :key="k"><dt>{{ CHECK[k] ?? k }}</dt><dd><StatusBadge :s="ok ? 'ok' : 'critical'" :text="ok ? 'Healthy' : 'Needs attention'" /></dd></template>
            <dt>Last heartbeat</dt><dd>{{ sys.data.value.heartbeat_age_seconds === null ? 'none yet' : sys.data.value.heartbeat_age_seconds + ' s ago' }}</dd>
          </dl>
        </Card>
        <Card title="Software" :hint="buildLabel(sys.data.value)">
          <dl class="sys" data-testid="build-facts">
            <dt>Product</dt><dd>{{ sys.data.value.product }}</dd>
            <dt>Console version</dt><dd>{{ sys.data.value.version }}</dd>
            <dt>Commit</dt><dd class="mono">{{ sys.data.value.commit ?? 'unknown' }}<span v-if="sys.data.value.dirty"> (built with local modifications)</span></dd>
            <dt>Built</dt><dd>{{ sys.data.value.built_at ? fmtTime(sys.data.value.built_at) : 'unknown' }}</dd>
            <dt>API</dt><dd>{{ sys.data.value.api }}</dd>
            <dt>Database schema</dt><dd class="mono">{{ sys.data.value.migration_head ?? 'not readable by the service account' }} (build head {{ sys.data.value.schema?.build_head ?? 'unknown' }})</dd>
            <dt>Database size</dt><dd>{{ fmtBytes(sys.data.value.database_bytes) }}</dd>
            <dt>Disk free</dt><dd>{{ sys.data.value.disk ? fmtBytes(sys.data.value.disk.free) + ' of ' + fmtBytes(sys.data.value.disk.total) : 'unknown' }}</dd>
          </dl>
        </Card>
        <Card v-if="sys.data.value.controller" title="Controller role" hint="Which controller is in charge. Only one controller is allowed to act at a time." data-testid="controller-card">
          <dl class="sys">
            <dt>Role</dt><dd><StatusBadge :s="roleLabel(sys.data.value.controller).tone === 'ok' ? 'ok' : roleLabel(sys.data.value.controller).tone === 'warn' ? 'warning' : 'critical'" :text="roleLabel(sys.data.value.controller).text" /></dd>
            <dt>Epoch</dt><dd>{{ sys.data.value.controller.epoch ?? 'unknown' }} <span class="muted small">(raised by every takeover; agents refuse an older one)</span></dd>
            <dt v-if="sys.data.value.controller.node_name">Controller</dt><dd v-if="sys.data.value.controller.node_name">{{ sys.data.value.controller.node_name }}</dd>
            <template v-if="sys.data.value.controller.role === 'standby'">
              <dt>Replication</dt>
              <dd v-if="sys.data.value.controller.replication"><StatusBadge :s="sys.data.value.controller.replication.ok ? 'ok' : 'critical'" :text="sys.data.value.controller.replication.ok ? 'In step with the primary' : 'Behind or disconnected'" />
                <span class="muted small"> newest copied change {{ fmtSeconds(sys.data.value.controller.replication.heartbeat_age_seconds) }} old, limit {{ fmtSeconds(sys.data.value.controller.max_lag_seconds) }} ({{ lagState(sys.data.value.controller.replication) }})</span></dd>
              <dd v-else class="muted">Not available.</dd>
            </template>
            <dt>Last takeover</dt>
            <dd v-if="sys.data.value.controller.last_promotion">{{ fmtTime(sys.data.value.controller.last_promotion.at) }} by {{ sys.data.value.controller.last_promotion.by ?? 'unknown' }}<span v-if="sys.data.value.controller.last_promotion.new_epoch !== null"> (epoch {{ sys.data.value.controller.last_promotion.old_epoch }} to {{ sys.data.value.controller.last_promotion.new_epoch }})</span></dd>
            <dd v-else class="muted">This controller has never been promoted.</dd>
          </dl>
          <p class="small"><a :href="RUNBOOK_URL" target="_blank" rel="noopener noreferrer">Recovery runbook</a></p>
        </Card>
        <Card title="Background services" hint="Each service reports progress; a stalled one turns the readiness check red.">
          <p v-if="!sys.data.value.worker_enabled" class="muted">The worker is not running inside this server process.</p>
          <dl v-else class="sys">
            <template v-for="t in (sys.data.value.threads ?? [])" :key="t.name"><dt>{{ THREAD[t.name] ?? t.name }}</dt>
              <dd><StatusBadge :s="tone(t.state)" :text="t.state === 'ok' ? 'Running' : t.state === 'off' ? 'Off' : 'Stalled'" />
                <span v-if="t.last_progress_seconds !== null" class="muted small"> last progress {{ t.last_progress_seconds }} s ago</span></dd></template>
          </dl>
        </Card>
        <Card title="Backups">
          <p v-if="!sys.data.value.backup?.known" class="muted">The backup folder cannot be read by the console service, so the last run is unknown. Run backups with the host script and check the folder on the server.</p>
          <p v-else-if="!sys.data.value.backup?.at" class="muted">No backup has been found yet.</p>
          <dl v-else class="sys"><dt>Last backup</dt><dd><span :title="fmtTime(sys.data.value.backup?.at ?? null)">{{ ago(sys.data.value.backup?.at ?? null) }}</span></dd></dl>
        </Card>
      </div>
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
