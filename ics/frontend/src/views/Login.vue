<script setup lang="ts">
import { ref } from 'vue'
import { ApiError, post, type Role } from '../api'
import { go, session, setLoggedIn } from '../store'
import ErrorBox from '../components/ErrorBox.vue'
import BrandMark from '../ui/BrandMark.vue'
import Button from '../ui/Button.vue'

const username = ref(''), password = ref(''), totp = ref('')
const err = ref<ApiError | null>(null), busy = ref(false)
async function submit() {
  busy.value = true; err.value = null
  try {
    const r = await post<{ csrf_token: string; user: { username: string; role: Role } }>('auth/login',
      { username: username.value.trim(), password: password.value, totp_code: totp.value.trim() })
    setLoggedIn(r.user, r.csrf_token)
    password.value = ''; totp.value = ''
    go('overview')
  } catch (e) { err.value = e as ApiError; totp.value = '' } finally { busy.value = false }
}
</script>
<template>
  <div class="authpage">
    <aside class="authside" aria-label="About Office Unbound">
      <div class="row"><BrandMark /><strong>Office Unbound</strong></div>
      <div><p class="eyebrow">Infrastructure Control</p><h2>Run your infrastructure with confidence.</h2><p>Plan, approve and observe every change across your Proxmox clusters and customer deployments, with a complete audit trail.</p></div>
      <p class="small">Self-hosted. Your data stays yours.</p>
    </aside>
    <main id="main" tabindex="-1" class="authform">
      <div class="authbox">
        <div><h1>Sign in</h1><p class="muted">Use your console account and authenticator code.</p></div>
        <div v-if="session.expired" class="alert warn" role="status">Your session ended. Sign in again.</div>
        <ErrorBox :error="err" />
        <form @submit.prevent="submit">
          <label>Username<input v-model="username" autocomplete="username" required maxlength="64" autofocus></label>
          <label>Password<input v-model="password" type="password" autocomplete="current-password" required maxlength="1024"></label>
          <label>Authenticator code<input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8" placeholder="123456"></label>
          <Button variant="primary" type="submit" :loading="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</Button>
        </form>
        <p class="muted small">Have an invite? <a href="#/enroll">Set up your account</a>.</p>
      </div>
    </main>
  </div>
</template>
