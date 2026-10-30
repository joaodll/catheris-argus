import { fileURLToPath, URL } from 'node:url'
import vue from '@vitejs/plugin-vue'
// From vitest/config: only its defineConfig types the `test` key.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    // No inline scripts or styles: the CSP allows 'self' only.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    // Development only (the frontend-dev service). In production nginx proxies /api.
    proxy: { '/api': { target: process.env.ARGUS_API_URL ?? 'http://api:8000' } },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
  },
})
