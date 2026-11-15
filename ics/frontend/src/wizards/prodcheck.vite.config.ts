import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

const out = process.env.WIZ_PRODCHECK_OUT ?? 'dist-prodcheck'
export default defineConfig({
  base: '/ui/',
  plugins: [vue()],
  build: { outDir: out, emptyOutDir: true, assetsInlineLimit: 0, sourcemap: false, lib: { entry: fileURLToPath(new URL('./prodcheck.entry.ts', import.meta.url)), formats: ['es'], fileName: 'wizards' } },
})
