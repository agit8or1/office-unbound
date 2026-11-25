<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { Store } from '../store'
import type { Backend } from '../api'
import type { ChatMessage, RoomSummary } from '../chat/types'
import Icon from '../Icon.vue'

const props = defineProps<{ store: Store; api: Backend }>()
const s = props.store.s
const account = computed(() => s.accounts.find((a) => a.services.includes('chat')) ?? null)
const rooms = ref<RoomSummary[]>([])
const current = ref<string | null>(null)
const messages = ref<ChatMessage[]>([])
const draft = ref('')
const error = ref('')
let since = 0
let alive = true

async function loadRooms() {
  if (!account.value || account.value.chat !== 'signed_in') return
  const r = await props.api.agent({ type: 'chat_rooms', account_id: account.value.id })
  if (r.type === 'chat_rooms') rooms.value = r.rooms
  else if (r.type === 'error') error.value = r.message
}
async function open(room: string) {
  current.value = room
  if (!account.value) return
  const r = await props.api.agent({ type: 'chat_history', account_id: account.value.id, room_id: room, limit: 50 })
  if (r.type === 'chat_history') {
    messages.value = r.messages
    const last = r.messages[r.messages.length - 1]
    if (last) props.api.agent({ type: 'chat_mark_read', account_id: account.value.id, room_id: room, event_id: last.event_id })
  } else if (r.type === 'error') error.value = r.message
}
async function send() {
  const body = draft.value.trim()
  if (!body || !current.value || !account.value) return
  const r = await props.api.agent({ type: 'chat_send', account_id: account.value.id, room_id: current.value, body })
  if (r.type === 'chat_sent') { draft.value = ''; await open(current.value) } else if (r.type === 'error') error.value = r.message
}
async function signIn() {
  if (!account.value) return
  const r = await props.api.agent({ type: 'chat_sign_in', account_id: account.value.id })
  if (r.type === 'error') error.value = r.message
  else props.store.refresh()
}
function text(m: ChatMessage): string {
  switch (m.body.kind) {
    case 'text': case 'notice': case 'emote': return m.body.body
    case 'file': return `📎 ${m.body.attachment.name}`
    case 'undecryptable': return 'Message could not be decrypted on this device'
    case 'redacted': return 'Message deleted'
    default: return ''
  }
}
async function events() {
  while (alive) {
    try {
      const r = await props.api.agent({ type: 'poll_events', since, wait_ms: 20000 })
      if (r.type !== 'events') { await new Promise((ok) => setTimeout(ok, 2000)); continue }
      since = r.next
      if (r.events.some(([, e]) => e.event.startsWith('chat_'))) {
        await loadRooms()
        if (current.value && r.events.some(([, e]) => e.event === 'chat_notification')) await open(current.value)
      }
      if (r.events.some(([, e]) => e.event === 'chat_signed_in' || e.event === 'chat_signed_out')) props.store.refresh()
    } catch { await new Promise((ok) => setTimeout(ok, 2000)) }
  }
}
watch(() => account.value?.chat, () => loadRooms())
onMounted(() => { loadRooms(); events() })
onBeforeUnmount(() => { alive = false })
</script>

<template>
  <section class="chat">
    <header class="pagehead"><h1>Chat</h1></header>
    <p v-if="!account" class="muted">Chat is not available for your accounts.</p>
    <template v-else-if="account.chat !== 'signed_in'">
      <p class="muted">Chat uses the same sign-in. If your browser asks, confirm once for Office Unbound Desktop.</p>
      <div class="row">
        <button class="primary" type="button" :disabled="account.chat === 'signing_in'" @click="signIn">
          {{ account.chat === 'signing_in' ? 'Finish in your browser…' : 'Sign in to chat' }}</button>
        <button type="button" @click="store.simple({ type: 'open_service', account_id: account.id, service: 'chat' })">
          Open chat in the browser <Icon name="external" /></button>
      </div>
    </template>
    <div v-else class="chatgrid">
      <ul class="rooms" role="listbox" aria-label="Conversations">
        <li v-for="r in rooms" :key="r.room_id" role="option" :aria-selected="current === r.room_id">
          <button type="button" :class="{ on: current === r.room_id }" @click="open(r.room_id)">
            <span class="rname">{{ r.name }}</span>
            <span v-if="r.highlights" class="badge signed_out">@{{ r.highlights }}</span>
            <span v-else-if="r.unread_messages" class="badge signing_in">{{ r.unread_messages }}</span>
          </button>
        </li>
        <li v-if="!rooms.length" class="muted small">No conversations yet.</li>
      </ul>
      <div class="thread">
        <p v-if="!current" class="muted">Choose a conversation.</p>
        <template v-else>
          <ol class="msgs">
            <li v-for="m in messages" :key="m.event_id"><span class="who mono">{{ m.sender }}</span> <span>{{ text(m) }}</span></li>
          </ol>
          <form class="row" @submit.prevent="send">
            <label class="sr" for="msg">Message</label>
            <input id="msg" v-model="draft" type="text" placeholder="Write a message" autocomplete="off" />
            <button class="primary" type="submit" :disabled="!draft.trim()">Send</button>
          </form>
        </template>
      </div>
    </div>
    <p v-if="error" class="bad" role="alert">{{ error }}</p>
  </section>
</template>
