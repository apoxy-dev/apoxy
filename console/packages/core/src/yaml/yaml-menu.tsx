// The per-object "YAML" menu (the design's `YamlMenu` + manifest tray): a
// dropdown with View / Copy kubectl / Download, plus the read-only manifest
// viewer it opens. Replaces the bare "View YAML" button on detail views. When
// `onEditRaw` is given (the kind is yamlEditable), the viewer also offers an Edit
// hand-off to the editable YAML tray. `y` opens the viewer, matching the design's
// keyboard hint.

import { useMemo, useState, type ReactNode } from 'react'
import { DropdownMenu, type DropdownItem } from '../components/ui/dropdown-menu'
import { useKeyboardScope } from '../keyboard/scope-stack'
import type { ResourceEntry } from '../registry/types'
import type { K8sObject } from '../lib/k8s-types'
import { forEditing, toYaml } from './yaml-doc'
import { ManifestTray } from './manifest-tray'

export interface YamlMenuProps {
  entry: ResourceEntry
  object: K8sObject
  /** Wire the viewer's Edit affordance to the editable YAML tray (omit for read-only kinds). */
  onEditRaw?: () => void
}

/** `cat <<EOF | kubectl apply -f -` for the given manifest. */
export function kubectlApplyCommand(yaml: string): string {
  return `cat <<'EOF' | kubectl apply -f -\n${yaml}EOF`
}

export function YamlMenu({ entry, object, onEditRaw }: YamlMenuProps) {
  const [viewing, setViewing] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const name = object.metadata.name ?? entry.kind
  const apiVersion = entry.gvr.group ? `${entry.gvr.group}/${entry.gvr.version}` : entry.gvr.version
  const yaml = useMemo(() => toYaml(forEditing(object)), [object])

  // `y` opens the viewer — but stay out of the way while the manifest tray is
  // already open or the dropdown itself is open (so typing `y` in the menu doesn't
  // both navigate the list and fire the global hotkey).
  useKeyboardScope({
    level: 'view',
    enabled: !viewing && !menuOpen,
    bindings: [{ keys: 'y', run: () => setViewing(true) }],
  })

  const items: DropdownItem[] = [
    {
      id: 'view',
      label: 'View YAML',
      sub: onEditRaw ? 'Inspect & edit the manifest' : 'Inspect the rendered manifest',
      kbd: 'Y',
      icon: <EyeIcon />,
      onSelect: () => setViewing(true),
    },
    {
      id: 'copy',
      label: 'Copy kubectl command',
      sub: 'kubectl apply for this object',
      icon: <TerminalIcon />,
      onSelect: () => void navigator.clipboard?.writeText(kubectlApplyCommand(yaml)).catch(() => {}),
    },
    {
      id: 'download',
      label: 'Download manifest',
      sub: 'Save as .yaml',
      icon: <DownloadIcon />,
      separatorBefore: true,
      onSelect: () => downloadYaml(yaml, name),
    },
  ]

  return (
    <>
      <DropdownMenu label="YAML" ariaLabel="YAML actions" icon={<ManifestIcon />} items={items} onOpenChange={setMenuOpen} />
      <ManifestTray
        open={viewing}
        onClose={() => setViewing(false)}
        title={name}
        subtitle={`${apiVersion} · ${entry.kind}`}
        yaml={yaml}
        filename={name}
        onEdit={
          onEditRaw
            ? () => {
                setViewing(false)
                onEditRaw()
              }
            : undefined
        }
      />
    </>
  )
}

function downloadYaml(yaml: string, name: string): void {
  const blob = new Blob([yaml], { type: 'text/yaml' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${name}.yaml`
  // Some browsers (Firefox) require the anchor to be in the DOM, and revoking the
  // URL in the same tick can cancel the download — append, click, then revoke late.
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

function ManifestIcon(): ReactNode {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <path d="M2 2h9v9H2z" />
      <path d="M5 6h3M5 8h3" />
    </svg>
  )
}
function EyeIcon(): ReactNode {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <path d="M1 7s2-4 6-4 6 4 6 4-2 4-6 4-6-4-6-4z" />
      <circle cx="7" cy="7" r="2" />
    </svg>
  )
}
function TerminalIcon(): ReactNode {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <path d="M2 3h10v8H2z" />
      <path d="M4 6l2 1.5L4 9M7.5 9H10" />
    </svg>
  )
}
function DownloadIcon(): ReactNode {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <path d="M7 1v8M3 6l4 4 4-4M2 12h10" />
    </svg>
  )
}
