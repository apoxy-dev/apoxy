// Shared icon glyphs for the console design system. The whole console (apoxy /
// clrk / cloud) standardizes on IBM Carbon icons + the bundled design fonts, so
// the icon set — like the fonts in tokens.css — is owned here in core rather than
// re-picked per app. Apps import these semantic glyphs (or Carbon directly) so a
// concept like "a listener" renders the same everywhere.
//
// App-agnostic: these name console concepts (a listener, a port), never a specific
// app's resource kinds.

import { PortInput } from '@carbon/icons-react'
import type { ReactNode } from 'react'

export interface GlyphProps {
  /** Square px size; defaults to the 15px the wizard rails use. */
  size?: number
}

/** The listener / ingress-port glyph (Carbon `PortInput`) — the canonical icon for
 *  a gateway listener, used by the create/edit wizards' Listeners collection. */
export function ListenerGlyph({ size = 15 }: GlyphProps): ReactNode {
  return <PortInput size={size} />
}
