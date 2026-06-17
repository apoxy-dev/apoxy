// Light/dark theme state. The whole console is token-driven, so a theme is just
// `data-theme="dark"` on <html> (see tokens.css). We default to light and only
// persist an explicit choice. The matching inline boot script in index.html
// applies a stored dark choice before first paint to avoid a flash.

export type Theme = 'light' | 'dark'

export const THEME_KEY = 'apoxy.console.theme'

export function readTheme(): Theme {
  try {
    return globalThis.localStorage?.getItem(THEME_KEY) === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export function applyTheme(theme: Theme): void {
  const root = globalThis.document?.documentElement
  if (!root) return
  if (theme === 'dark') root.dataset.theme = 'dark'
  else delete root.dataset.theme
}

export function storeTheme(theme: Theme): void {
  try {
    globalThis.localStorage?.setItem(THEME_KEY, theme)
  } catch {
    /* storage unavailable — the choice just won't persist */
  }
}
