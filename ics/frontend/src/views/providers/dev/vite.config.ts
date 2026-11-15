// DEV-ONLY: `npx vite --config src/views/providers/dev/vite.config.ts` serves the real console on 127.0.0.1:8107 against the design-review mock API.
// Not used by `npm run build` (that reads ../../../../vite.config.ts), so the mock can never reach the production bundle.
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'
import { mockApi } from './mock-plugin'

const frontend = fileURLToPath(new URL('../../../..', import.meta.url))
export default defineConfig({
  root: frontend,
  base: '/ui/',
  plugins: [vue(), mockApi()],
  server: { host: '127.0.0.1', port: 8107, strictPort: true, fs: { allow: [frontend] } },
  cacheDir: '/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/pui/vite-cache',
})
