<script setup lang="ts" generic="T extends Record<string, any>">
// Data table with sane density. Cells render `row[key]` unless a `cell-<key>` slot is given.
// `href(row)` makes the whole row clickable (hash route) while keeping a real link in the first cell for keyboard users.
export interface Col { key: string; label: string; num?: boolean; mono?: boolean }
const props = defineProps<{ cols: Col[]; rows: T[]; rowKey: (r: T) => string; href?: (r: T) => string | undefined; selected?: string; dense?: boolean }>()
function open(r: T) { const h = props.href?.(r); if (h) location.hash = '#' + h }
</script>
<template>
  <div class="tablewrap" tabindex="0" role="region" aria-label="Scrollable table">
    <table :class="{ dense }">
      <thead><tr><th v-for="c in cols" :key="c.key" :class="{ num: c.num }" scope="col">{{ c.label }}</th></tr></thead>
      <tbody>
        <tr v-for="r in rows" :key="rowKey(r)" :class="{ click: !!href, sel: selected === rowKey(r) }" @click="open(r)">
          <td v-for="(c, i) in cols" :key="c.key" :class="{ num: c.num, mono: c.mono }">
            <slot :name="'cell-' + c.key" :row="r">
              <a v-if="i === 0 && href?.(r)" :href="'#' + href(r)" @click.stop>{{ r[c.key] ?? '-' }}</a>
              <template v-else>{{ r[c.key] ?? '-' }}</template>
            </slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
