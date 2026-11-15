import fs from 'node:fs'
import crypto from 'node:crypto'

export type Role = 'admin' | 'approver' | 'approver2' | 'operator' | 'viewer'
export interface UserState { role: string; password: string; totp_secret?: string; last_step?: number; enrollment_token?: string }
export interface State { base: string; users: Record<string, UserState>; tls_port: number; plain_port: number; pending_plan_ids: string[] }

export function state(): State {
  const p = process.env.E2E_STATE
  if (!p) throw new Error('E2E_STATE not set; run via ics/e2e/run.sh <checkout>')
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}
export const userName = (r: Role) => `e2e-${r}`
export const authFile = (r: Role) => `results/auth-${r}.json`

export function totp(secret: string, step: number): string {
  const b32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) bits += b32.indexOf(ch).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g)!.map((x) => parseInt(x, 2)))
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(step))
  const h = crypto.createHmac('sha1', key).update(msg).digest()
  const o = h[h.length - 1] & 15
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

/** Waits until a TOTP step newer than `after` is current (the server rejects replays); returns the code and its step. */
export async function nextTotp(secret: string, after: number) {
  let step = Math.floor(Date.now() / 30000)
  while (step <= after) {
    await new Promise((r) => setTimeout(r, 1000))
    step = Math.floor(Date.now() / 30000)
  }
  return { code: totp(secret, step), step }
}
