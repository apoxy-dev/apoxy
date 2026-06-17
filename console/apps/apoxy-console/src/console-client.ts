// The app's single ConsoleClient: a GVR client + QueryClient + WatchManager
// scoped to one project. Origin and project come from build-time env
// (VITE_APOXY_API_URL / VITE_APOXY_PROJECT_ID), defaulting to the serving
// origin so a co-hosted console "just works".

import { createConsoleClient, ProjectRequestDecorator, type ConsoleClient } from '@apoxy/console-core'
import { baseUrl, projectId } from './project-context'

export const consoleClient: ConsoleClient = createConsoleClient({
  decorator: new ProjectRequestDecorator({ baseUrl, projectId }),
})
