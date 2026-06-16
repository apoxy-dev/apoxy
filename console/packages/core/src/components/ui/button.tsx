import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/cn'

type Variant = 'primary' | 'secondary' | 'ghost'
type Size = 'sm' | 'md'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
}

// Square corners everywhere (0px radius is a brand rule — tokens.css), Inter medium,
// off-black ink on bone for primary. Colors are token CSS vars; the consumer's Tailwind
// compiles the arbitrary utilities.
const base =
  'inline-flex items-center justify-center whitespace-nowrap rounded-none font-medium ' +
  'transition-colors duration-150 focus-visible:outline-none ' +
  'focus-visible:shadow-[var(--sh-focus)] disabled:pointer-events-none disabled:opacity-50'

const variants: Record<Variant, string> = {
  primary: 'bg-[var(--apx-ink)] text-[color:var(--apx-bone)] hover:bg-[var(--apx-graphite)]',
  secondary:
    'border border-[color:var(--apx-ink)] bg-transparent text-[color:var(--apx-ink)] hover:bg-[var(--apx-mist)]',
  ghost: 'bg-transparent text-[color:var(--apx-ink)] hover:bg-[var(--apx-mist)]',
}

const sizes: Record<Size, string> = {
  sm: 'h-8 px-3 text-[length:var(--t-body-sm)]',
  md: 'h-10 px-4 text-[length:var(--t-body)]',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = 'primary', size = 'md', type = 'button', ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(base, variants[variant], sizes[size], className)}
      {...props}
    />
  )
})
