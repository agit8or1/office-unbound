<script setup lang="ts">
import { get, ROLES } from '../../../api'
import { useLoad } from '../../../store'
import ErrorBox from '../../../components/ErrorBox.vue'
import type { DirUser, Policy } from './users'

const props = defineProps<{ users: DirUser[] }>()
const policy = useLoad(() => get<Policy>('access-policy'))
const count = (r: string) => props.users.filter((u) => u.role === r && (u.status === 'active' || u.status === 'locked')).length
</script>
<template>
  <section class="ux-stack">
    <ErrorBox :error="policy.error.value" />
    <div v-if="policy.data.value" class="ux-cards-4">
      <div v-for="r in policy.data.value.roles" :key="r.role" class="ux-card ux-role">
        <h2>{{ r.role }} <span v-if="r.role === 'approver' || r.role === 'admin'" class="chip warn">privileged</span></h2>
        <p class="muted">{{ r.summary }}</p>
        <p class="small"><strong>{{ count(r.role) }}</strong> active {{ count(r.role) === 1 ? 'account' : 'accounts' }}</p>
      </div>
    </div>
    <div v-if="policy.data.value" class="ux-card">
      <h2 class="ux-pad">Permission matrix</h2>
      <div class="ux-scroll">
        <table class="ux-table ux-matrix">
          <caption class="sr">What each role can do</caption>
          <thead><tr><th scope="col">Capability</th><th v-for="r in ROLES" :key="r" scope="col" class="ux-c">{{ r }}</th></tr></thead>
          <tbody><tr v-for="c in policy.data.value.capabilities" :key="c.capability">
            <th scope="row" class="ux-plain">{{ c.capability }}</th>
            <td v-for="r in ROLES" :key="r" class="ux-c"><span v-if="c.roles[r]" class="ux-yes" aria-label="Allowed">&#10003;</span><span v-else class="ux-no" aria-label="Not allowed">&ndash;</span></td>
          </tr></tbody>
        </table>
      </div>
    </div>
    <p class="muted small">Roles are cumulative. Changing a role is a high-risk plan: see <a href="#/users/privileged">Privileged access</a>.</p>
  </section>
</template>
