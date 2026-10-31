import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: { sourcemap: false, assetsInlineLimit: 0 },
  server: { proxy: { '/api': { target: process.env.PANEL_API_ORIGIN ?? 'https://127.0.0.1:8443', secure: true } } },
  test: {
    environment: 'jsdom', include: ['src/**/*.test.{ts,tsx}'], setupFiles: ['./src/test-setup.ts'], restoreMocks: true,
    // Node 25 enables its own storage by default; jsdom must own browser storage.
    execArgv: Number(process.versions.node.split('.')[0]) >= 25 ? ['--no-experimental-webstorage'] : [],
  },
})
