import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'

// Vite 8 / Rolldown. The router plugin must precede @vitejs/plugin-react.
// `tanstackRouter` generates src/routeTree.gen.ts on dev/build via the
// file-routing Vite plugin, not the sidecar CLI.
export default defineConfig({
  plugins: [
    tanstackRouter({ target: 'react', autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
})
