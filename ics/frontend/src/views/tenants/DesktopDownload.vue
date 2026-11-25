<script setup lang="ts">
// A small download card: Office Unbound Desktop for Windows from this ICS (GET /api/v1/downloads/desktop/windows, viewer and up).
import { useLoad } from '../../store'
import Card from '../../ui/Card.vue'
import { DESKTOP_WINDOWS_HREF, desktopApi, desktopWarning, humanSize } from './desktop'

const d = useLoad(() => desktopApi.info())
</script>
<template>
  <Card title="Office Unbound Desktop for Windows" hint="Downloaded from this server, the same installer the tenant's portal offers">
    <template v-if="d.data.value?.windows">
      <dl class="kv">
        <dt>Version</dt><dd>{{ d.data.value.windows.version }}</dd>
        <dt>Size</dt><dd>{{ humanSize(d.data.value.windows.size) }}</dd>
        <dt>SHA-256</dt><dd><code class="mono hash">{{ d.data.value.windows.sha256 }}</code></dd>
      </dl>
      <p v-if="desktopWarning(d.data.value.windows)" class="muted" data-test="desktop-warning">{{ desktopWarning(d.data.value.windows) }}</p>
      <p><a class="btn sm" :href="DESKTOP_WINDOWS_HREF" download data-test="desktop-download">Download for Windows</a></p>
    </template>
    <p v-else-if="d.data.value" class="muted" data-test="desktop-none">Not available yet.</p>
  </Card>
</template>
<style scoped>
.hash { word-break: break-all; }
</style>
