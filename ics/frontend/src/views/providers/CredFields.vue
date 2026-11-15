<script setup lang="ts">
// Temporary administrator credentials. Write-only: the secret lives in the SecretBag, is sent once and wiped by the caller.
import { Field } from '../../wizards/kit'
import type { Errors } from '../../wizards/kit'
import type { SecretBag, WizardModel } from './model'
defineProps<{ m: Pick<WizardModel, 'adminKind' | 'adminUser' | 'adminTokenId'>; s: SecretBag; errors: Errors }>()
</script>
<template>
  <div class="pv-cred">
    <div class="wz-row">
      <label class="wz-choice"><input v-model="m.adminKind" type="radio" value="password" /> Administrator user and password</label>
      <label class="wz-choice"><input v-model="m.adminKind" type="radio" value="token" /> Administrator API token</label>
    </div>
    <div v-if="m.adminKind === 'password'" class="wz-grid two">
      <Field label="Administrator" :error="errors.adminUser" hint="For example root@pam. Used once, then discarded." v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.adminUser" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
      <Field label="Password" :error="errors.adminPassword" hint="Held in memory for this one request only." v-slot="{ id, invalid }"><input :id="id" v-model="s.adminPassword" type="password" autocomplete="new-password" :aria-invalid="invalid" /></Field>
    </div>
    <div v-else class="wz-grid two">
      <Field label="Token ID" :error="errors.adminTokenId" hint="user@realm!tokenname" v-slot="{ id, invalid }"><input :id="id" v-model.trim="m.adminTokenId" type="text" autocomplete="off" :aria-invalid="invalid" /></Field>
      <Field label="Token secret" :error="errors.adminTokenSecret" hint="Write-only. Never shown again." v-slot="{ id, invalid }"><input :id="id" v-model="s.adminTokenSecret" type="password" autocomplete="new-password" :aria-invalid="invalid" /></Field>
    </div>
  </div>
</template>
