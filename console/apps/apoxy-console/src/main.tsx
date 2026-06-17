import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider } from '@tanstack/react-router'
import { ConsoleProvider } from '@apoxy/console-core'
import '@apoxy/console-core/tokens.css'
import './styles.css'
import { router } from './router'
import { consoleClient } from './console-client'

const rootEl = document.getElementById('root')
if (!rootEl) throw new Error('#root not found')

createRoot(rootEl).render(
  <StrictMode>
    <ConsoleProvider client={consoleClient}>
      <RouterProvider router={router} />
    </ConsoleProvider>
  </StrictMode>,
)
