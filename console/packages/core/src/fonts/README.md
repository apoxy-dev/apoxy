# Fonts

`colors_and_type.css` declares `@font-face` rules that load **Inter** (three optical sizes:
`18pt`, `24pt`, `28pt`) from this directory, and `tokens.css` loads **TWK Everett** from
`../assets/fonts/`. The binary font files are intentionally **not** committed in this
scaffold — until they are dropped in, the token font stacks fall back to
`ui-sans-serif`/`system-ui`, so the build and layout are correct, just not on-brand.

To activate the real faces, copy the files from the **Apoxy Design System** project
(claude.ai/design, project `019df41b-2666-72f6-881c-d558b01ca8c8`) into:

- `packages/core/src/fonts/` — `Inter_18pt-*.ttf`, `Inter_24pt-*.ttf`, `Inter_28pt-*.ttf`
- `packages/core/src/assets/fonts/` — `TWKEverett-Regular.woff2`, `TWKEverett-Medium.woff2`
  (+ `.woff`)

Tracked under the design-tokens part of APO-763 / primitives APO-766.
