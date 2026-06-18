// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { createRegistry, defineResource } from '../registry/registry'
import { YamlMenu, kubectlApplyCommand } from './yaml-menu'
import type { K8sObject } from '../lib/k8s-types'

const entry = createRegistry([
  defineResource({ kind: 'Gateway', group: 'gateway.apoxy.dev', resource: 'gateways', servedVersion: 'v1', sidebarGroup: 'Gateway', columns: [] }),
]).all()[0]!

const obj: K8sObject = { apiVersion: 'gateway.apoxy.dev/v1', kind: 'Gateway', metadata: { name: 'edge', namespace: 'default' } }

afterEach(cleanup)

describe('YamlMenu', () => {
  it('opens the manifest viewer from View YAML', () => {
    render(<YamlMenu entry={entry} object={obj} />)
    fireEvent.click(screen.getByRole('button', { name: 'YAML actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: /View YAML/ }))
    const dialog = screen.getByRole('dialog', { name: 'Manifest for edge' })
    expect(dialog.textContent).toContain('gateway.apoxy.dev/v1')
  })

  it('hands off to the raw editor from the viewer only when onEditRaw is given', () => {
    const onEditRaw = vi.fn()
    render(<YamlMenu entry={entry} object={obj} onEditRaw={onEditRaw} />)
    fireEvent.click(screen.getByRole('button', { name: 'YAML actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: /View YAML/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    expect(onEditRaw).toHaveBeenCalledTimes(1)
  })

  it('copies a kubectl apply command for the object', () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    render(<YamlMenu entry={entry} object={obj} />)
    fireEvent.click(screen.getByRole('button', { name: 'YAML actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Copy kubectl command/ }))
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('kubectl apply -f -'))
  })
})

describe('kubectlApplyCommand', () => {
  it('wraps the manifest in a heredoc apply', () => {
    expect(kubectlApplyCommand('kind: Gateway\n')).toBe("cat <<'EOF' | kubectl apply -f -\nkind: Gateway\nEOF")
  })
})
