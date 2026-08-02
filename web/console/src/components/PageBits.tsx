import { motion } from "framer-motion";
import { type ReactNode } from "react";
import { Card, Skeleton } from "./ui";
import { cn } from "@/lib/utils";

export const stagger = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.04 } },
};
export const item = {
  hidden: { opacity: 0, y: 10 },
  show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 26 } as const },
};

export function StatCard({
  label,
  value,
  tone = "fg",
  hint,
  loading,
  delta,
}: {
  label: string;
  value: ReactNode;
  /** @deprecated kept for call-site compatibility; no longer rendered — the
   * card reads as number-led (Vercel/Linear register), not icon-led. */
  icon?: ReactNode;
  tone?: "fg" | "accent" | "danger" | "warn";
  hint?: string;
  loading?: boolean;
  /** Small "+N since last poll" style indicator, shown beside the value. */
  delta?: ReactNode;
}) {
  const toneCls = { fg: "text-fg", accent: "text-fg", danger: "text-fg", warn: "text-fg" }[tone];
  return (
    <motion.div variants={item}>
      <Card className="p-5">
        <span className="text-[13px] text-muted">{label}</span>
        {loading ? (
          <Skeleton className="mt-3.5 h-8 w-24" />
        ) : (
          <div className="mt-3.5 text-[28px] font-bold tnum leading-none tracking-tight">
            <span className={toneCls}>{value}</span>
          </div>
        )}
        <div className="mt-3.5 flex items-center gap-1.5 text-[12px] text-muted">{delta ?? (hint && <span>{hint}</span>)}</div>
      </Card>
    </motion.div>
  );
}

/** Monochrome delta: small colored arrow+value, then muted context text —
 * no filled badge/pill. Color is used only as a one-word signal, never as a
 * background fill, per the product's "no rainbow" visual rule. */
export function Delta({ dir, children, context }: { dir: "up" | "down" | "flat"; children: ReactNode; context?: ReactNode }) {
  const cls = dir === "down" ? "text-danger" : "text-muted";
  const arrow = dir === "up" ? "↑" : dir === "down" ? "↓" : "";
  return (
    <>
      <span className={cn("inline-flex items-center gap-0.5 font-medium tnum", cls)}>
        {arrow} {children}
      </span>
      {context && <span>{context}</span>}
    </>
  );
}

export function PageHeader({ title, desc, action }: { title: string; desc?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h2 className="font-serif text-2xl tracking-tight">{title}</h2>
        {desc && <p className="mt-0.5 text-sm text-muted">{desc}</p>}
      </div>
      {action}
    </div>
  );
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <Card className="border-danger/30 bg-danger/5 p-4 text-sm text-danger">Failed to load: {error}</Card>
  );
}

// Minimal responsive table.
export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted">{head}</tr>
          </thead>
          <tbody>{children}</tbody>
        </table>
      </div>
    </Card>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cn("px-4 py-3 font-medium", className)}>{children}</th>;
}

export function Row({ children, i = 0 }: { children: ReactNode; i?: number }) {
  return (
    <motion.tr
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: Math.min(i * 0.02, 0.3) }}
      className="border-b border-border/60 last:border-0 transition-colors hover:bg-elevated/40"
    >
      {children}
    </motion.tr>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn("px-4 py-3", className)}>{children}</td>;
}
