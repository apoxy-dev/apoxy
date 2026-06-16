// @apoxy/console-core — public surface.
// Design tokens are shipped as a plain CSS file and imported by consumers via
// `@apoxy/console-core/tokens.css` (ADR-0003); they are intentionally not re-exported here.

export * from './components/ui'
export * from './lib'
export type { paths, components, operations } from './schema/schema'
