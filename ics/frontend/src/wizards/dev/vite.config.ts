// DEV-ONLY: `npx vite --config src/wizards/dev/vite.config.ts` serves the wizards on 127.0.0.1:8106 against the mock API.
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'
import { mockApi } from './mock-plugin'

const frontend = fileURLToPath(new URL('../../..', import.meta.url))
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [vue(), mockApi()],
  server: { host: '127.0.0.1', port: 8106, strictPort: true, fs: { allow: [frontend] } },
  cacheDir: '/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/ui-f/vite-cache',
})
