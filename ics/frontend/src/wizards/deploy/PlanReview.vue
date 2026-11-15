<script setup lang="ts">
import type { DeploymentPlan } from '../api'
import { Banner, CapacityList, fmtGb, fmtMem } from '../kit'
defineProps<{ plan: DeploymentPlan }>()
</script>

<template>
  <div>
    <Banner v-for="(e, i) in plan.errors" :key="'e' + i" kind="bad" title="Blocking error">{{ e.message }}</Banner>
    <Banner v-for="(w, i) in plan.warnings" :key="'w' + i" kind="warn" title="Warning">{{ w.message }}</Banner>

    <div class="wz-card">
      <h2>Estimated consumption</h2>
      <dl class="wz-dl"><dt>CPU</dt><dd>{{ plan.consumption.cores }} vCPU</dd><dt>Memory</dt><dd>{{ fmtGb(plan.consumption.memory_gb) }}</dd><dt>Disk</dt><dd>{{ fmtGb(plan.consumption.disk_gb) }}</dd></dl>
      <h3>Capacity remaining after this plan</h3>
      <CapacityList :lines="plan.capacity" />
    </div>

    <div class="wz-card">
      <h2>Virtual machines ({{ plan.vms.length }})</h2>
      <div class="wz-table-wrap"><table>
        <thead><tr><th>Name</th><th>OS image</th><th class="num">CPU</th><th class="num">RAM</th><th>Disks</th><th>NICs</th></tr></thead>
        <tbody><tr v-for="v in plan.vms" :key="v.name">
          <td><b class="mono">{{ v.name }}</b><div v-if="v.role" class="muted small">{{ v.role }}</div></td><td>{{ v.os_image }}</td><td class="num">{{ v.cores }}</td><td class="num">{{ fmtMem(v.memory_mb) }}</td>
          <td><div v-for="d in v.disks" :key="d.name">{{ d.name }} {{ fmtGb(d.size_gb) }} <span class="muted">on {{ d.storage }}</span></div></td>
          <td><div v-for="(n, i) in v.nics" :key="i">{{ n.bridge }}<span v-if="n.vlan"> / VLAN {{ n.vlan }}</span><span v-if="n.ip" class="muted"> {{ n.ip }}</span></div></td>
        </tr></tbody>
      </table></div>
    </div>

    <div class="wz-grid two">
      <div class="wz-card">
        <h2>Containers ({{ plan.containers.length }})</h2>
        <p v-if="!plan.containers.length" class="muted">None.</p>
        <ul v-else class="wz-checks"><li v-for="c in plan.containers" :key="c.name"><span class="mono">{{ c.name }}</span><span>on {{ c.vm }}<div class="mono muted">{{ c.image }}<template v-if="c.digest">@{{ c.digest.slice(0, 19) }}…</template></div></span></li></ul>
      </div>
      <div class="wz-card">
        <h2>Services ({{ plan.services.length }})</h2>
        <ul class="wz-checks"><li v-for="s in plan.services" :key="s.name"><span class="mono">{{ s.name }}</span><span>on {{ s.vm }}<span v-if="s.ports?.length" class="muted"> &middot; ports {{ s.ports.join(', ') }}</span></span></li></ul>
      </div>
    </div>

    <div class="wz-card">
      <h2>Order of execution</h2>
      <p class="muted small">Steps run in this dependency order; each step is idempotent and resumes after a failure.</p>
      <ol class="wz-dag"><li v-for="s in plan.steps" :key="s.id">{{ s.label }}<span v-if="s.depends_on?.length" class="muted small"> (after {{ s.depends_on.join(', ') }})</span></li></ol>
    </div>

    <div class="wz-grid two">
      <div class="wz-card">
        <h2>Ports and exposure</h2>
        <div class="wz-table-wrap"><table>
          <thead><tr><th>Service</th><th class="num">Port</th><th>Proto</th><th>Exposure</th></tr></thead>
          <tbody><tr v-for="p in plan.ports" :key="p.service + p.port"><td>{{ p.service }}</td><td class="num">{{ p.port }}</td><td>{{ p.proto }}</td><td><span class="wz-chip" :class="p.exposure === 'external' ? 'warn' : 'info'">{{ p.exposure }}</span></td></tr></tbody>
        </table></div>
      </div>
      <div class="wz-card">
        <h2>Backups and monitoring</h2>
        <p v-if="!plan.backups.length" class="muted">No backups configured.</p>
        <p v-for="b in plan.backups" :key="b.target">Backup to <b>{{ b.target }}</b>, {{ b.schedule }}, keep {{ b.retention_days }} days.</p>
        <ul class="wz-checks"><li v-for="c in plan.monitoring" :key="c.check"><span class="wz-chip info">check</span><span>{{ c.check }}<span v-if="c.target" class="muted"> &middot; {{ c.target }}</span></span></li></ul>
      </div>
    </div>
  </div>
</template>
