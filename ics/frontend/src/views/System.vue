<script setup lang="ts">
import { get } from '../api'
import { fmtBytes, fmtTime, useLoad } from '../store'
import { ago } from '../format'
import PageHeader from '../ui/PageHeader.vue'
import Card from '../ui/Card.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import Skeleton from '../ui/Skeleton.vue'
import Button from '../ui/Button.vue'
import ErrorBox from '../components/ErrorBox.vue'

interface Thread { name: string; state: 'ok' | 'stalled' | 'off'; last_progress_seconds: number | null }
interface SystemInfo {
  version: string; migration_head: string | null; ready: boolean; checks: Record<string, boolean>; heartbeat_age_seconds: number | null
  worker_enabled: boolean; threads: Thread[]; database_bytes: number | null; disk: { total: number; free: number } | null
  backup: { known: boolean; at: string | null }
}
const sys = useLoad(() => get<SystemInfo>('system'), 15000)
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
        <Card title="Status">
          <dl class="sys">
            <dt>Overall</dt><dd><StatusBadge :s="sys.data.value.ready ? 'ok' : 'critical'" :text="sys.data.value.ready ? 'Ready' : 'Not ready'" /></dd>
            <template v-for="(ok, k) in sys.data.value.checks" :key="k"><dt>{{ CHECK[k] ?? k }}</dt><dd><StatusBadge :s="ok ? 'ok' : 'critical'" :text="ok ? 'Healthy' : 'Needs attention'" /></dd></template>
            <dt>Last heartbeat</dt><dd>{{ sys.data.value.heartbeat_age_seconds === null ? 'none yet' : sys.data.value.heartbeat_age_seconds + ' s ago' }}</dd>
          </dl>
        </Card>
        <Card title="Software">
          <dl class="sys">
            <dt>Console version</dt><dd>{{ sys.data.value.version }}</dd>
            <dt>Database schema</dt><dd class="mono">{{ sys.data.value.migration_head ?? 'not readable by the service account' }}</dd>
            <dt>Database size</dt><dd>{{ fmtBytes(sys.data.value.database_bytes) }}</dd>
            <dt>Disk free</dt><dd>{{ sys.data.value.disk ? fmtBytes(sys.data.value.disk.free) + ' of ' + fmtBytes(sys.data.value.disk.total) : 'unknown' }}</dd>
          </dl>
        </Card>
        <Card title="Background services" hint="Each service reports progress; a stalled one turns the readiness check red.">
          <p v-if="!sys.data.value.worker_enabled" class="muted">The worker is not running inside this server process.</p>
          <dl v-else class="sys">
            <template v-for="t in sys.data.value.threads" :key="t.name"><dt>{{ THREAD[t.name] ?? t.name }}</dt>
              <dd><StatusBadge :s="tone(t.state)" :text="t.state === 'ok' ? 'Running' : t.state === 'off' ? 'Off' : 'Stalled'" />
                <span v-if="t.last_progress_seconds !== null" class="muted small"> last progress {{ t.last_progress_seconds }} s ago</span></dd></template>
          </dl>
        </Card>
        <Card title="Backups">
          <p v-if="!sys.data.value.backup.known" class="muted">The backup folder cannot be read by the console service, so the last run is unknown. Run backups with the host script and check the folder on the server.</p>
          <p v-else-if="!sys.data.value.backup.at" class="muted">No backup has been found yet.</p>
          <dl v-else class="sys"><dt>Last backup</dt><dd><span :title="fmtTime(sys.data.value.backup.at)">{{ ago(sys.data.value.backup.at) }}</span></dd></dl>
        </Card>
      </div>
    </template>
  </div>
</template>
