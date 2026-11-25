import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// Tauri serves dist/ from its own protocol; nothing is loaded from the network (CSP in src-tauri/tauri.conf.json).
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: { host: '127.0.0.1', port: 5174, strictPort: true },
  build: { target: 'es2022', assetsInlineLimit: 0, sourcemap: false },
  test: { environment: 'jsdom' },
})
