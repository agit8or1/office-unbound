<script setup lang="ts">
import { get } from '../../../api'
import { useLoad } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import { duration, type Policy } from './users'

const policy = useLoad(() => get<Policy>('access-policy'))
</script>
<template>
  <section class="ux-stack">
    <ErrorBox :error="policy.error.value" />
    <template v-if="policy.data.value">
      <p class="muted">The policy this server is enforcing right now. It is set when ICS is deployed and cannot be edited from the console.</p>
      <div class="ux-cards-2">
        <div class="ux-card"><h2>Approvals by risk</h2>
          <dl class="kv"><template v-for="a in policy.data.value.approvals" :key="a.risk"><dt><span class="chip" :class="a.risk === 'high' ? 'warn' : 'info'">{{ a.risk }}</span></dt><dd>{{ a.text }}</dd></template></dl>
          <p class="muted small">Plans not decided within {{ duration(policy.data.value.plan_expiry_seconds) }} expire.</p></div>
        <div class="ux-card"><h2>Multi-factor authentication</h2>
          <p><span class="chip ok">mandatory</span> {{ policy.data.value.mfa.method }}</p>
          <p class="muted small">Every operator enrolls an authenticator before the account becomes active. A code can be used only once.</p></div>
        <div class="ux-card"><h2>Sessions</h2>
          <dl class="kv"><dt>Maximum lifetime</dt><dd>{{ duration(policy.data.value.sessions.absolute_seconds) }}</dd>
            <dt>Idle timeout</dt><dd>{{ duration(policy.data.value.sessions.idle_seconds) }}</dd>
            <dt>Concurrent sessions</dt><dd>{{ policy.data.value.sessions.max_per_user }} per user (oldest ends first)</dd></dl></div>
        <div class="ux-card"><h2>Lockout</h2>
          <dl class="kv"><dt>After</dt><dd>{{ policy.data.value.lockout.max_failures }} failed sign-ins in {{ duration(policy.data.value.lockout.window_seconds) }}</dd>
            <dt>Delay</dt><dd>starts at {{ duration(policy.data.value.lockout.backoff_base_seconds) }}, doubles, up to {{ duration(policy.data.value.lockout.backoff_cap_seconds) }}</dd>
            <dt>Per address</dt><dd>{{ policy.data.value.lockout.per_ip_max_failures }} failures across all names</dd></dl></div>
        <div class="ux-card"><h2>Enrollment</h2>
          <dl class="kv"><dt>Token validity</dt><dd>{{ duration(policy.data.value.enrollment.token_ttl_seconds) }}, single use</dd>
            <dt>Token channel</dt><dd>{{ policy.data.value.enrollment.token_channel }}</dd>
            <dt>Password</dt><dd>chosen by the person, at least {{ policy.data.value.enrollment.password_min_length }} characters</dd></dl></div>
      </div>
      <div class="ux-card"><h2>Rules that always apply</h2>
        <ul class="plain ux-rule-list"><li v-for="r in policy.data.value.rules" :key="r.id"><strong>{{ r.title }}.</strong> {{ r.text }}</li></ul></div>
    </template>
  </section>
</template>
