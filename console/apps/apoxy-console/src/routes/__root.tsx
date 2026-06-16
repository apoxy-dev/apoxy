import { createRootRoute, Outlet } from '@tanstack/react-router'

export const Route = createRootRoute({
  component: () => (
    <div className="apx-body min-h-screen">
      <Outlet />
    </div>
  ),
})
