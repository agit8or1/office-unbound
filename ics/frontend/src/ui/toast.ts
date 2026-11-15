import { reactive } from 'vue'

export interface ToastItem { id: number; kind: 'ok' | 'bad' | 'info'; text: string }
export const toasts = reactive<ToastItem[]>([])
let seq = 0
export function toast(text: string, kind: ToastItem['kind'] = 'info', ms = 5000) {
  const id = ++seq
  toasts.push({ id, kind, text })
  setTimeout(() => dismiss(id), ms)
}
export function dismiss(id: number) {
  const i = toasts.findIndex((t) => t.id === id)
  if (i >= 0) toasts.splice(i, 1)
}
