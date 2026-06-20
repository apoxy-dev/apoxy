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
      icon: <ViewIcon />,
      onSelect: () => setViewing(true),
    },
    {
      id: 'copy',
      label: 'Copy kubectl command',
      sub: 'kubectl apply for this object',
      icon: <CopyIcon />,
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
      <DropdownMenu label="YAML" ariaLabel="YAML actions" icon={<CodeIcon />} items={items} onOpenChange={setMenuOpen} />
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

// All four glyphs are IBM Carbon icons, inlined to match the design's YAML menu
// (yaml-menu.jsx) exactly and keep @apoxy/console-core dependency-free.
/** Carbon `Code` (`</>`) — the YAML menu's trigger glyph. */
function CodeIcon(): ReactNode {
  return (
    <svg width="15" height="15" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true">
      <path d="M31 16 24 23 22.59 21.59 28.17 16 22.59 10.41 24 9 31 16z" />
      <path d="M1 16 8 9 9.41 10.41 3.83 16 9.41 21.59 8 23 1 16z" />
      <path d="M5.91 15H26.08V17H5.91z" transform="rotate(-75 15.996 16)" />
    </svg>
  )
}
/** Carbon `View` (eye). */
function ViewIcon(): ReactNode {
  return (
    <svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true">
      <path d="M30.94,15.66A16.69,16.69,0,0,0,16,5,16.69,16.69,0,0,0,1.06,15.66a1,1,0,0,0,0,.68A16.69,16.69,0,0,0,16,27,16.69,16.69,0,0,0,30.94,16.34,1,1,0,0,0,30.94,15.66ZM16,25c-5.3,0-10.9-3.93-12.93-9C5.1,10.93,10.7,7,16,7s10.9,3.93,12.93,9C26.9,21.07,21.3,25,16,25Z" />
      <path d="M16,10a6,6,0,1,0,6,6A6,6,0,0,0,16,10Zm0,10a4,4,0,1,1,4-4A4,4,0,0,1,16,20Z" />
    </svg>
  )
}
/** Carbon `Copy`. */
function CopyIcon(): ReactNode {
  return (
    <svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true">
      <path d="M28,10V28H10V10H28m0-2H10a2,2,0,0,0-2,2V28a2,2,0,0,0,2,2H28a2,2,0,0,0,2-2V10a2,2,0,0,0-2-2Z" />
      <path d="M4,18H2V4A2,2,0,0,1,4,2H18V4H4Z" />
    </svg>
  )
}
/** Carbon `Download`. */
function DownloadIcon(): ReactNode {
  return (
    <svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true">
      <path d="M26,24v4H6V24H4v4H4a2,2,0,0,0,2,2H26a2,2,0,0,0,2-2h0V24Z" />
      <path d="M26 14 24.59 12.59 17 20.17 17 2 15 2 15 20.17 7.41 12.59 6 14 16 24 26 14z" />
    </svg>
  )
}
