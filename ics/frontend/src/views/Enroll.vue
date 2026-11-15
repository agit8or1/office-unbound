<script setup lang="ts">
import { ref } from 'vue'
import QRCode from 'qrcode'
import { ApiError, post } from '../api'
import { go } from '../store'
import ErrorBox from '../components/ErrorBox.vue'

const step = ref<1 | 2 | 3>(1)
const username = ref(''), token = ref(''), password = ref(''), password2 = ref(''), code = ref('')
const qr = ref(''), secret = ref('')
const err = ref<ApiError | string | null>(null), busy = ref(false)

async function begin() {
  err.value = null
  if (password.value !== password2.value) { err.value = 'Passwords do not match.'; return }
  if (password.value.length < 12) { err.value = 'Password must be at least 12 characters.'; return }
  busy.value = true
  try {
    const r = await post<{ totp_provisioning_uri: string }>('auth/enroll',
      { username: username.value.trim(), token: token.value.trim(), password: password.value })
    secret.value = new URL(r.totp_provisioning_uri).searchParams.get('secret') ?? ''
    qr.value = await QRCode.toDataURL(r.totp_provisioning_uri, { margin: 1, width: 192 })
    password.value = password2.value = ''
    step.value = 2
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
async function confirm() {
  busy.value = true; err.value = null
  try {
    await post('auth/enroll/confirm', { username: username.value.trim(), token: token.value.trim(), totp_code: code.value.trim() })
    secret.value = ''; qr.value = ''; token.value = ''
    step.value = 3
  } catch (e) { err.value = e as ApiError } finally { busy.value = false }
}
</script>
<template>
  <main id="main" tabindex="-1" class="center">
    <div class="panel auth">
      <h1>Enroll account</h1>
      <p class="muted">Step {{ step }} of 3. Use the one-time enrollment token an operator gave you.</p>
      <ErrorBox :error="err" />
      <form v-if="step === 1" @submit.prevent="begin">
        <label>Username<input v-model="username" autocomplete="username" required maxlength="64"></label>
        <label>Enrollment token<input v-model="token" autocomplete="off" spellcheck="false" required maxlength="200"></label>
        <label>New password <span class="muted">(12+ characters)</span>
          <input v-model="password" type="password" autocomplete="new-password" required minlength="12" maxlength="1024"></label>
        <label>Repeat password<input v-model="password2" type="password" autocomplete="new-password" required maxlength="1024"></label>
        <button class="primary" :disabled="busy">Set password</button>
        <a class="btn ghost sm" href="#/login">Back to sign in</a>
      </form>
      <form v-else-if="step === 2" @submit.prevent="confirm">
        <div class="alert warn">This authenticator secret is shown once. Add it to your authenticator app now.</div>
        <img :src="qr" width="192" height="192" alt="QR code for the authenticator app" class="qr">
        <label>Secret (manual entry)<input :value="secret" readonly class="mono" @focus="($event.target as HTMLInputElement).select()"></label>
        <label>Code from the app<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" required maxlength="8" autofocus></label>
        <button class="primary" :disabled="busy">Verify and finish</button>
      </form>
      <div v-else>
        <div class="alert ok" role="status">Account enrolled. You can sign in now.</div>
        <button class="primary" @click="go('login')">Go to sign in</button>
      </div>
    </div>
  </main>
</template>
