// The Gateway create/edit wizard (APO-782 follow-up). A bespoke form over the
// reusable WizardShell: an Identity step (name / namespace / class) and a
// Listeners step — a master-detail *collection* where each listener is a full-pane
// editor surfaced one level down in the rail — plus the shell's built-in YAML step
// for raw authoring. Gateway-API Gateways do NOT embed routes (those are separate
// HTTPRoute/GRPCRoute/TLSRoute objects), so the wizard stops at listeners, which
// keeps it correct and bounded. clrk's EgressGateway reuses the same shell and the
// same collection pattern for its listeners / routes / rules.

import {
  WizardShell,
  FormSection,
  Field,
  TextField,
  SegField,
  FieldRow,
  type WizardProps,
  type WizardStep,
  type WizardCollection,
  type WizardFormProps,
} from '@apoxy/console-core'
import { useMemo, type ReactNode } from 'react'
import type { GatewayObject, GatewayListener } from './gateway-routes'

const PROTOCOLS = ['HTTP', 'HTTPS', 'TLS', 'TCP', 'UDP']
const DEFAULT_PORT: Record<string, number> = { HTTP: 80, HTTPS: 443, TLS: 443, TCP: 8080, UDP: 8080 }

function emptyGateway(): GatewayObject {
  return {
    apiVersion: 'gateway.apoxy.dev/v1',
    kind: 'Gateway',
    metadata: { name: '', namespace: 'default' },
    spec: { gatewayClassName: '', listeners: [] },
  }
}

export function GatewayWizard({ entry, object, open, onClose, onSaved }: WizardProps) {
  const editing = !!object
  // Memoized so a re-render (e.g. each keystroke in a field) doesn't hand WizardShell
  // a fresh steps identity and defeat its allSteps memo.
  const steps = useMemo<WizardStep<GatewayObject>[]>(
    () => [
      { id: 'identity', label: 'Identity', render: (p) => <IdentityStep {...p} editing={editing} /> },
      { id: 'listeners', label: 'Listeners', collection: listenersCollection },
    ],
    [editing],
  )
  return (
    <WizardShell<GatewayObject>
      entry={entry}
      object={object as GatewayObject | undefined}
      open={open}
      onClose={onClose}
      onSaved={onSaved}
      emptyDraft={emptyGateway}
      steps={steps}
    />
  )
}

function IdentityStep({ draft, setDraft, editing }: WizardFormProps<GatewayObject> & { editing: boolean }) {
  const setMeta = (patch: Partial<GatewayObject['metadata']>) => setDraft({ ...draft, metadata: { ...draft.metadata, ...patch } })
  const setSpec = (patch: Partial<NonNullable<GatewayObject['spec']>>) => setDraft({ ...draft, spec: { ...draft.spec, ...patch } })
  return (
    <FormSection step="01" title="Identity" sub="Name, namespace, and class for the Gateway.">
      <FieldRow>
        <Field
          label="Name"
          required
          htmlFor="gw-name"
          hint={editing ? 'metadata.name — immutable after create.' : 'metadata.name — a DNS-1123 label.'}
        >
          <TextField id="gw-name" mono value={draft.metadata.name ?? ''} disabled={editing} onChange={(v) => setMeta({ name: v })} placeholder="edge-gateway" />
        </Field>
        <Field label="Namespace" htmlFor="gw-ns" hint="Scopes the gateway and the routes that may bind to it.">
          <TextField id="gw-ns" mono value={draft.metadata.namespace ?? ''} onChange={(v) => setMeta({ namespace: v })} placeholder="default" />
        </Field>
      </FieldRow>
      <Field label="Gateway class" htmlFor="gw-class" wide hint="spec.gatewayClassName — the controller that programs this gateway.">
        <TextField id="gw-class" mono value={draft.spec?.gatewayClassName ?? ''} onChange={(v) => setSpec({ gatewayClassName: v })} placeholder="apoxy" />
      </Field>
    </FormSection>
  )
}

// The Listeners step as a collection: the shell renders the overview list, the
// nested rail entries, and the per-item header/remove; this just maps the draft's
// listener array to items and renders one listener's fields.
const listenersCollection: WizardCollection<GatewayObject> = {
  noun: 'listener',
  glyph: <ListenerGlyph />,
  items: (d) =>
    (d.spec?.listeners ?? []).map((l, i) => ({
      id: String(i),
      label: l.name || `listener-${i + 1}`,
      summary: `${l.protocol ?? 'HTTP'}${l.port != null ? `:${l.port}` : ''}${l.hostname ? ` · ${l.hostname}` : ''}`,
    })),
  onAdd: (d) => {
    const ls = d.spec?.listeners ?? []
    return {
      draft: { ...d, spec: { ...d.spec, listeners: [...ls, { name: `listener-${ls.length + 1}`, protocol: 'HTTP', port: 80 }] } },
      focusId: String(ls.length),
    }
  },
  onRemove: (d, id) => {
    const i = Number(id)
    const ls = d.spec?.listeners ?? []
    return { ...d, spec: { ...d.spec, listeners: ls.filter((_, j) => j !== i) } }
  },
  renderItem: ({ draft, setDraft, itemId }) => <ListenerFields draft={draft} setDraft={setDraft} index={Number(itemId)} />,
}

function ListenerFields({ draft, setDraft, index }: Pick<WizardFormProps<GatewayObject>, 'draft' | 'setDraft'> & { index: number }) {
  const listeners = draft.spec?.listeners ?? []
  const l = listeners[index]
  if (!l) return null
  const update = (patch: Partial<GatewayListener>) =>
    setDraft({ ...draft, spec: { ...draft.spec, listeners: listeners.map((x, j) => (j === index ? { ...x, ...patch } : x)) } })

  return (
    <>
      <FieldRow>
        <Field label="Name" htmlFor={`l-name-${index}`} hint="Unique within the gateway; referenced by routes via sectionName.">
          <TextField id={`l-name-${index}`} mono value={l.name} onChange={(v) => update({ name: v })} placeholder="https" />
        </Field>
        <Field label="Port" htmlFor={`l-port-${index}`} hint="The port this listener binds.">
          <TextField
            id={`l-port-${index}`}
            mono
            value={l.port != null ? String(l.port) : ''}
            onChange={(v) => {
              const n = Number(v)
              update({ port: v && Number.isFinite(n) ? n : undefined })
            }}
            placeholder="443"
          />
        </Field>
      </FieldRow>
      <Field label="Protocol" wide>
        <SegField
          value={l.protocol ?? 'HTTP'}
          options={PROTOCOLS}
          onChange={(proto) => {
            // Move the port to the new protocol's default only when it still holds the
            // *old* protocol's default — never clobber a port the user typed.
            const atOldDefault = l.port === DEFAULT_PORT[l.protocol ?? 'HTTP']
            update({ protocol: proto, ...(atOldDefault ? { port: DEFAULT_PORT[proto] } : {}) })
          }}
        />
      </Field>
      <Field label="Hostname" htmlFor={`l-host-${index}`} wide hint="Optional — narrows the listener to a single host or wildcard.">
        <TextField id={`l-host-${index}`} mono value={l.hostname ?? ''} onChange={(v) => update({ hostname: v || undefined })} placeholder="*.example.com" />
      </Field>
    </>
  )
}

function ListenerGlyph(): ReactNode {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true">
      <path d="M3 8a5 5 0 0110 0" />
      <path d="M5 8a3 3 0 016 0" />
      <circle cx="8" cy="8" r="1" fill="currentColor" />
    </svg>
  )
}
