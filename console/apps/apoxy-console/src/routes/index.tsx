import { createFileRoute } from '@tanstack/react-router'
import { Button, Card, CardMeta, CardTitle } from '@apoxy/console-core'

export const Route = createFileRoute('/')({
  component: Home,
})

function Home() {
  return (
    <main className="mx-auto flex max-w-[var(--container)] flex-col gap-[var(--sp-6)] p-[var(--sp-10)]">
      <h1 className="text-[length:var(--t-h1)] font-medium text-[color:var(--text-primary)]">
        Apoxy Console
      </h1>
      <Card>
        <CardTitle>Foundation is wired</CardTitle>
        <CardMeta>@apoxy/console-core · design tokens · primitives</CardMeta>
        <div className="mt-[var(--sp-4)] flex gap-[var(--sp-3)]">
          <Button>Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
        </div>
      </Card>
    </main>
  )
}
