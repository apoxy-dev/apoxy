# Fonts

All `@font-face` rules live in `../tokens.css` (a single file, so a consumer that
`@import '@apoxy/console-core/tokens.css'` gets every face — a nested `@import`
does not survive Tailwind/Vite hoisting once tokens.css is itself imported).

Bundled faces:

- `fonts/Inter-roman.var.woff2` — **Inter**, the UI body face. One variable woff2
  (weights 100–900 + optical-size axis); the `Inter`, `Inter Small`, and
  `Inter Display` families all resolve to it.
- `fonts/JetBrainsMono-roman.var.woff2` — **JetBrains Mono**, the code/mono face
  (variable, weights 100–800).
- `../assets/fonts/TWKEverett-{Regular,Medium}.woff2` — **TWK Everett**, the
  licensed display face (static woff2).

Inter and JetBrains Mono are OFL; their variable woff2 come from the
`@fontsource-variable/*` packages. TWK Everett is licensed — its woff2 are the
files from the Apoxy Design System project (claude.ai/design).

Tracked under the design-tokens part of APO-763 / primitives APO-766.
