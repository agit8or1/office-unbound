import { test as setup, request } from '@playwright/test'
import fs from 'node:fs'
import { authFile, nextTotp, state, userName, type Role } from '../lib/state'

// One real API login per role (TOTP replays are refused, so UI logins happen only in specs/01-login).
for (const role of ['admin', 'approver', 'approver2', 'operator', 'viewer'] as Role[]) {
  setup(`login ${role}`, async ({ baseURL }) => {
    const st = state()
    const u = st.users[userName(role)]
    const { code, step } = await nextTotp(u.totp_secret!, u.last_step ?? 0)
    const ctx = await request.newContext({ baseURL })
    const r = await ctx.post('/api/v1/auth/login', { data: { username: userName(role), password: u.password, totp_code: code } })
    if (!r.ok()) throw new Error(`login ${role} failed: ${r.status()}`)
    fs.mkdirSync('results', { recursive: true })
    await ctx.storageState({ path: authFile(role) })
    await ctx.dispose()
    void step
  })
}
