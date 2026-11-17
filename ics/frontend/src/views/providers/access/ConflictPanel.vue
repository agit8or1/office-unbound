<script setup lang="ts">
// Asks the administrator what to do with each conflicting pre-existing Proxmox object and which Office Unbound leftovers to remove.
// Only options the server marked as available can be picked; the picks take effect after "Recalculate" (a new dry run).
import { computed } from 'vue'
import { ACTION_LABEL, KIND_NOUN, choiceKey, describeExisting, needsAck, type ChoiceState, type ConflictEntry, type Leftover } from './conflicts'
const props = defineProps<{ conflicts: ConflictEntry[]; leftovers: Leftover[]; state: ChoiceState; disabled?: boolean }>()
const removable = computed(() => props.leftovers.filter((l) => l.removable))
const kept = computed(() => props.leftovers.filter((l) => !l.removable))
const uid = (s: string) => 'cp-' + s.replace(/[^A-Za-z0-9_-]/g, '_')
function toggle(id: string, on: boolean) {
  const s = new Set(props.state.cleanup)
  if (on) s.add(id); else s.delete(id)
  props.state.cleanup = [...s].sort()     // eslint-disable-line vue/no-mutating-props -- the parent owns this reactive state on purpose
}
function selectAll(on: boolean) { props.state.cleanup = on ? removable.value.map((l) => l.id).sort() : [] }   // eslint-disable-line vue/no-mutating-props
</script>

<template>
  <div class="cp">
    <section v-if="conflicts.length" class="cp-sec" aria-labelledby="cp-conf-h">
      <h3 id="cp-conf-h">Objects that already exist in Proxmox</h3>
      <p class="muted small">Choose what happens to each one. Options Office Unbound cannot do safely are disabled, with the reason. Your choice becomes part of the plan only after you recalculate.</p>
      <fieldset v-for="c in conflicts" :key="choiceKey(c)" class="cp-card" :disabled="disabled">
        <legend>{{ KIND_NOUN[c.kind] ?? c.kind }} <span class="mono">{{ c.target }}</span></legend>
        <p class="small">{{ describeExisting(c) }}</p>
        <p v-if="c.kind === 'role' && ((c.existing.would_add as string[])?.length || (c.existing.would_remove as string[])?.length)" class="small">
          Overwriting would <span v-if="(c.existing.would_add as string[]).length" class="cp-add">add {{ (c.existing.would_add as string[]).join(', ') }}</span>
          <template v-if="(c.existing.would_add as string[]).length && (c.existing.would_remove as string[]).length"> and </template>
          <span v-if="(c.existing.would_remove as string[]).length" class="cp-rm">remove {{ (c.existing.would_remove as string[]).join(', ') }}</span>.
        </p>
        <p v-if="(c.existing.used_by_others as string[] | undefined)?.length" class="cp-warn small" role="note">
          Also used by permissions Office Unbound did not create: {{ (c.existing.used_by_others as string[]).join('; ') }}. Changing this role changes their rights too.
        </p>
        <div class="cp-opts" role="radiogroup" :aria-label="`What to do with ${c.target}`">
          <label v-for="o in c.options" :key="o.action" class="cp-opt" :class="{ off: !o.available }">
            <input type="radio" :name="uid(choiceKey(c))" :value="o.action" :disabled="!o.available" v-model="state.pick[choiceKey(c)]" />
            <span>{{ ACTION_LABEL[o.action] }}<template v-if="o.action === c.default"> <span class="wz-chip">default</span></template>
              <span v-if="!o.available && o.why_not" class="muted small cp-why">Not possible: {{ o.why_not }}</span></span>
          </label>
        </div>
        <p v-if="!state.pick[choiceKey(c)]" class="cp-bad small" role="alert">Choose an option: this object blocks the plan until you do.</p>
        <label v-if="needsAck(c, state)" class="cp-ack">
          <input type="checkbox" v-model="state.ack[choiceKey(c)]" />
          <span>I understand that the other users' rights listed above change too.</span>
        </label>
      </fieldset>
    </section>

    <section v-if="leftovers.length" class="cp-sec" aria-labelledby="cp-left-h">
      <h3 id="cp-left-h">Leftovers from earlier attempts</h3>
      <p class="muted small">These carry Office Unbound's name or marker, and no connected integration uses them. Select the ones to remove as part of this plan. Nothing is removed unless you select it.</p>
      <div v-if="removable.length > 1" class="row">
        <button type="button" class="wz-btn" :disabled="disabled" @click="selectAll(true)">Select all</button>
        <button type="button" class="wz-btn" :disabled="disabled" @click="selectAll(false)">Select none</button>
      </div>
      <ul class="cp-list">
        <li v-for="l in removable" :key="l.id">
          <label class="cp-opt">
            <input type="checkbox" :disabled="disabled" :checked="state.cleanup.includes(l.id)" @change="toggle(l.id, ($event.target as HTMLInputElement).checked)" :aria-describedby="uid(l.id) + '-d'" />
            <span>Remove {{ (KIND_NOUN[l.kind] ?? l.kind).toLowerCase() }} <span class="mono">{{ l.target }}</span>
              <span :id="uid(l.id) + '-d'" class="muted small cp-why">{{ l.why }}. Removes: {{ l.removes.join(', ') }}</span></span>
          </label>
        </li>
      </ul>
      <template v-if="kept.length">
        <p class="small"><b>Kept</b> (cannot be removed safely):</p>
        <ul class="cp-list"><li v-for="l in kept" :key="l.id" class="small">{{ KIND_NOUN[l.kind] ?? l.kind }} <span class="mono">{{ l.target }}</span>: {{ l.kept_because }}</li></ul>
      </template>
    </section>
  </div>
</template>

<style scoped>
.cp { display: grid; gap: 14px; }
.cp-sec { display: grid; gap: 8px; }
.cp-sec h3 { margin: 0; }
.cp-card { border: 1px solid var(--line); border-radius: var(--radius); padding: 10px 12px; margin: 0; display: grid; gap: 6px; background: var(--surface); }
.cp-card legend { padding: 0 4px; font-weight: 600; }
.cp-opts { display: grid; gap: 4px; }
.cp-opt { display: flex; gap: 8px; align-items: flex-start; cursor: pointer; }
.cp-opt.off { color: var(--faint); cursor: not-allowed; }
.cp-opt input { margin-top: 3px; }
.cp-why { display: block; }
.cp-add { color: var(--ok); }
.cp-rm, .cp-bad { color: var(--bad); }
.cp-warn { color: var(--warn); background: var(--warn-bg); border-radius: var(--radius-sm); padding: 4px 8px; margin: 0; }
.cp-ack { display: flex; gap: 8px; align-items: flex-start; color: var(--warn); }
.cp-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 6px; }
</style>
