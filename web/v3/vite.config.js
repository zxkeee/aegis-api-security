import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5300,
    host: true,
    // Forward the pilot form to the Go server (run it on :8090) so submissions save.
    proxy: { '/api': 'http://localhost:8090' },
  },
})
