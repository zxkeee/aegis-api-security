import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { ArrowRight } from '@phosphor-icons/react'

export const EASE = [0.16, 1, 0.3, 1]

export function Reveal({ children, delay = 0, className = '', y = 18 }) {
  const reduce = useReducedMotion()
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: reduce ? 0 : y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.25 }}
      transition={{ duration: reduce ? 0.01 : 0.6, delay: reduce ? 0 : delay, ease: EASE }}
    >
      {children}
    </motion.div>
  )
}

/* No separate icon. The wordmark itself is the mark: the capital A stands
   alone at rest, and the rest of the word grows out of that same letter in
   the same font on arrival, so it reads as one name revealing itself, not a
   logo glued to a label. Same reveal on every device, not gated on hover. */
export function Wordmark({ className = '' }) {
  const [open, setOpen] = useState(false)
  const reduce = useReducedMotion()

  useEffect(() => {
    const t = setTimeout(() => setOpen(true), 450)
    return () => clearTimeout(t)
  }, [])

  return (
    <span className={`inline-flex items-baseline font-serif text-[21px] tracking-[0.01em] text-ink ${className}`}>
      <span>A</span>
      <motion.span
        className="overflow-hidden whitespace-nowrap"
        initial={false}
        animate={{ width: open ? 68 : 0, opacity: open ? 1 : 0 }}
        transition={reduce ? { duration: 0.01 } : { type: 'spring', stiffness: 260, damping: 24 }}
      >
        EGIS
      </motion.span>
    </span>
  )
}

export function GhostButton({ href, children, className = '', ...props }) {
  const cls = `group inline-flex items-center gap-2 rounded-[4px] border border-ink px-4 py-2 text-[14px] font-medium text-ink transition-all duration-300 hover:gap-3 hover:bg-ink hover:text-obsidian ${className}`
  const content = (
    <>
      {children}
      <ArrowRight size={14} weight="bold" className="transition-transform duration-300 group-hover:translate-x-0.5" />
    </>
  )
  return href
    ? <a href={href} className={cls} {...props}>{content}</a>
    : <button className={cls} {...props}>{content}</button>
}

export const TextLink = ({ href, children }) => (
  <a href={href} className="inline-flex items-center gap-1.5 text-[14px] font-medium text-accent transition-opacity hover:opacity-80">
    {children} <ArrowRight size={14} weight="bold" />
  </a>
)

export const Badge = ({ children, tone = 'default' }) => (
  <span
    className={`inline-block rounded-[4px] px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.05em] ${
      tone === 'accent' ? 'bg-navy text-ink' : 'bg-elevated text-muted'
    }`}
  >
    {children}
  </span>
)

/* Section opener: serif does the work, no eyebrow/kicker per the reference register. */
export function SectionHeader({ title, sub, align = 'left' }) {
  return (
    <div className={align === 'center' ? 'mx-auto max-w-2xl text-center' : 'max-w-2xl'}>
      <h2 className="text-balance font-serif text-[clamp(28px,3.6vw,44px)] font-normal leading-[1.15] tracking-[-0.02em] text-ink">
        {title}
      </h2>
      {sub && <p className="mt-4 text-[16px] leading-relaxed text-muted">{sub}</p>}
    </div>
  )
}

export function Section({ id, className = '', children }) {
  return (
    <section id={id} className={`border-t border-line py-16 md:py-20 scroll-mt-16 ${className}`}>
      {children}
    </section>
  )
}
