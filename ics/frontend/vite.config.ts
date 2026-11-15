import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// Built files land in ../ics/static, which the FastAPI app serves at /ui/ (and deploy/install.sh copies with the code).
export default defineConfig({
  base: '/ui/',
  plugins: [vue()],
  build: { outDir: '../ics/static', emptyOutDir: true, assetsInlineLimit: 0, sourcemap: false },
  server: { proxy: { '/api': 'http://127.0.0.1:8088', '/readyz': 'http://127.0.0.1:8088' } },
  test: { environment: 'jsdom' },
})
