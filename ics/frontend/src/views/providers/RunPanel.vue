<script setup lang="ts">
// Progress, approval waiting and failure help for one submitted plan.
import { computed } from 'vue'
import { Banner, HelpNote } from '../../wizards/kit'
import { troubleshoot } from './model'
import type { Run } from './run'
const props = defineProps<{ run: Run; what: string }>()
const v = computed(() => props.run.view.value)
const steps = ['Submitted', 'Approved', 'Running', 'Finished']
const at = computed(() => ({ awaiting_approval: 0, queued: 1, running: 2, succeeded: 4, failed: 4, rejected: 4 } as Record<string, number>)[v.value?.phase ?? 'queued'] ?? 0)
</script>
<template>
  <div class="pv-run" aria-live="polite">
    <Banner v-if="run.error.value && !run.created.value" kind="bad" title="Could not submit">{{ run.error.value }}</Banner>
    <template v-if="v">
      <ol class="pv-phases" aria-label="Progress">
        <li v-for="(s, i) in steps" :key="s" :data-s="i < at ? 'done' : i === at ? 'now' : 'todo'">{{ s }}</li>
      </ol>
      <div class="pv-bar" role="progressbar" :aria-valuenow="v.progress" aria-valuemin="0" aria-valuemax="100" :data-failed="v.phase === 'failed' || v.phase === 'rejected'"><i :ref="(el) => { if (el) (el as HTMLElement).style.width = props.run.view.value!.progress + '%' }"></i></div>
      <p class="pv-phase"><b>{{ v.text }}</b> <span class="muted">{{ props.what }}</span></p>
      <p v-if="!v.done" class="muted small">{{ v.detail }}</p>
      <p v-if="v.phase === 'awaiting_approval'" class="small">
        This change is high impact, so it needs sign-off. <a href="#/plans">Open Approvals</a> to review plan <span class="mono">{{ run.created.value?.plan_id.slice(0, 8) }}</span>. This page updates by itself.
      </p>
      <Banner v-if="run.created.value?.customer_approval_id" kind="info" title="Customer approval required">The customer who owns this cluster must also approve before anything runs.</Banner>
      <Banner v-if="v.phase === 'failed'" kind="bad" title="This did not work">{{ run.error.value }}
        <HelpNote title="Troubleshooting" open><ul class="pv-list"><li v-for="t in troubleshoot(run.error.value)" :key="t">{{ t }}</li></ul></HelpNote>
      </Banner>
      <Banner v-if="v.phase === 'rejected'" kind="warn" title="Rejected">{{ v.detail }}</Banner>
    </template>
  </div>
</template>
