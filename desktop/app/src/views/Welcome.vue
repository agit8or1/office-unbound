<script setup lang="ts">
import { ref } from 'vue'
import type { Store } from '../store'
const props = defineProps<{ store: Store }>()
const input = ref('')
const s = props.store.s
const host = (u: string) => { try { return new URL(u).host } catch { return u } }
function submit() {
  if (input.value.trim()) props.store.discover(input.value.trim())
}
</script>
<template>
  <section class="welcome">
    <img src="../assets/ou-mark.svg" alt="" class="mark" width="40" height="40" />
    <template v-if="s.phase === 'welcome' || s.phase === 'loading'">
      <h1>Sign in to Office Unbound</h1>
      <p class="muted">Enter your work e-mail address. We find your organisation's server and open its sign-in page in your browser.</p>
      <form @submit.prevent="submit" class="row">
        <label class="sr" for="addr">Work e-mail or server address</label>
        <input id="addr" v-model="input" type="text" inputmode="email" autocomplete="email" spellcheck="false"
               placeholder="name@company.com or cloud.company.com" :disabled="s.busy" autofocus />
        <button class="primary" type="submit" :disabled="s.busy || !input.trim()">{{ s.busy ? 'Looking…' : 'Continue' }}</button>
      </form>
      <button v-if="s.accounts.length" class="link" type="button" @click="store.cancel()">Back</button>
    </template>
    <template v-else-if="s.phase === 'confirm' && s.pending">
      <h1>Sign in to {{ s.pending.deployment.name }}?</h1>
      <dl class="facts">
        <dt>Sign-in page</dt><dd class="mono">{{ host(s.pending.deployment.issuer) }}</dd>
        <dt>Files</dt><dd class="mono">{{ host(s.pending.deployment.files_url) }}</dd>
        <dt v-if="s.pending.deployment.matrix_url">Chat</dt><dd v-if="s.pending.deployment.matrix_url" class="mono">{{ host(s.pending.deployment.matrix_url) }}</dd>
      </dl>
      <p v-if="s.pending.deployment.foreign_hosts.length" class="warn" role="alert">
        Some services are outside {{ s.pending.deployment.domain }}: {{ s.pending.deployment.foreign_hosts.join(', ') }}.
        Continue only if your administrator told you to.
      </p>
      <p class="muted">Your password is entered only on your organisation's sign-in page, never in this app.</p>
      <div class="row">
        <button class="primary" type="button" @click="store.signIn()">Open sign-in page</button>
        <button type="button" @click="store.cancel()">Cancel</button>
      </div>
    </template>
    <template v-else-if="s.phase === 'waiting'">
      <h1>Finish signing in in your browser</h1>
      <p class="muted">Complete sign-in (and MFA, if asked) in the browser window that opened. This window updates by itself.</p>
    </template>
    <p v-if="s.error" class="bad" role="alert">{{ s.error }}</p>
  </section>
</template>
