<script setup lang="ts">
import { ref } from 'vue'
import { ApiError, post, type Role } from '../api'
import { go, session, setLoggedIn } from '../store'
import ErrorBox from '../components/ErrorBox.vue'

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
  <div class="center">
    <form class="panel auth" @submit.prevent="submit" aria-labelledby="t">
      <h1 id="t">Sign in</h1>
      <p class="muted">Office Unbound ICS operator console</p>
      <div v-if="session.expired" class="alert warn" role="status">Your session ended. Sign in again.</div>
      <ErrorBox :error="err" />
      <label>Username<input v-model="username" autocomplete="username" required maxlength="64" autofocus></label>
      <label>Password<input v-model="password" type="password" autocomplete="current-password" required maxlength="1024"></label>
      <label>Authenticator code
        <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8">
      </label>
      <button class="primary" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
      <p class="muted small">First login with an invite? <a href="#/enroll">Enroll your account</a>.</p>
    </form>
  </div>
</template>
