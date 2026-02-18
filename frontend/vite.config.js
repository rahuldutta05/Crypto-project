import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/auth':   'http://localhost:5000',
      '/chat':   'http://localhost:5000',
      '/keys':   'http://localhost:5000',
      '/verify': 'http://localhost:5000',
      '/admin':  'http://localhost:5000',
    }
  }
})
