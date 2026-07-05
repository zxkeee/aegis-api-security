import { cva, type VariantProps } from "class-variance-authority";
import { motion } from "framer-motion";
import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Button ───────────────────────────────────────────────────────────────────
const buttonV = cva(
  "inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-colors focus-visible:outline-none disabled:opacity-50 disabled:pointer-events-none select-none",
  {
    variants: {
      variant: {
        primary: "bg-accent text-accent-fg hover:brightness-110",
        ghost: "text-muted hover:text-fg hover:bg-elevated",
        outline: "border border-border text-fg hover:bg-elevated",
        danger: "bg-danger/10 text-danger hover:bg-danger/20 border border-danger/30",
      },
      size: {
        sm: "h-8 px-3",
        md: "h-10 px-4",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonV>
>(({ className, variant, size, ...props }, ref) => (
  <motion.button
    ref={ref}
    whileTap={{ scale: 0.97 }}
    transition={{ type: "spring", stiffness: 500, damping: 30 }}
    className={cn(buttonV({ variant, size }), className)}
    {...(props as any)}
  />
));
Button.displayName = "Button";

// ── Card ─────────────────────────────────────────────────────────────────────
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-border bg-surface", className)} {...props} />;
}

// ── Badge ────────────────────────────────────────────────────────────────────
const badgeV = cva("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium", {
  variants: {
    tone: {
      neutral: "bg-elevated text-muted",
      ok: "bg-ok/12 text-ok",
      warn: "bg-warn/12 text-warn",
      danger: "bg-danger/12 text-danger",
      accent: "bg-accent/12 text-accent",
    },
  },
  defaultVariants: { tone: "neutral" },
});

export function Badge({
  tone,
  className,
  children,
}: VariantProps<typeof badgeV> & { className?: string; children: ReactNode }) {
  return <span className={cn(badgeV({ tone }), className)}>{children}</span>;
}

// ── Input ────────────────────────────────────────────────────────────────────
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-10 w-full rounded-lg border border-border bg-bg px-3 text-sm text-fg placeholder:text-muted/70",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 transition-shadow",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

// ── Skeleton ─────────────────────────────────────────────────────────────────
export function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn("relative overflow-hidden rounded-md bg-elevated", className)}>
      <div className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-fg/5 to-transparent animate-shimmer" />
    </div>
  );
}

// ── Spinner ──────────────────────────────────────────────────────────────────
export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("h-4 w-4 animate-spin", className)} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-90" d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

// ── Empty / error states ─────────────────────────────────────────────────────
export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      {icon && <div className="text-muted/60">{icon}</div>}
      <p className="text-sm font-medium text-fg">{title}</p>
      {hint && <p className="max-w-sm text-xs text-muted">{hint}</p>}
    </div>
  );
}
