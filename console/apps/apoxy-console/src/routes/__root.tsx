import { createRootRoute, Outlet } from '@tanstack/react-router'

export const Route = createRootRoute({
  component: () => (
    <div className="apx-body h-full">
      <Outlet />
    </div>
  ),
})
