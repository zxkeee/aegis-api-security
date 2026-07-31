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
  icon,
  tone = "fg",
  hint,
  loading,
  delta,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: "fg" | "accent" | "danger" | "warn";
  hint?: string;
  loading?: boolean;
  /** Small "+N since last poll" style indicator, shown beside the value. */
  delta?: ReactNode;
}) {
  const toneCls = { fg: "text-fg", accent: "text-accent", danger: "text-danger", warn: "text-warn" }[tone];
  return (
    <motion.div variants={item}>
      <Card className="group relative overflow-hidden p-5 transition-colors hover:border-accent/40">
        <div className="flex items-start justify-between">
          <span className="text-xs font-medium uppercase tracking-wide text-muted">{label}</span>
          {icon && <span className="text-muted/50 transition-colors group-hover:text-accent">{icon}</span>}
        </div>
        {loading ? (
          <Skeleton className="mt-3 h-8 w-20" />
        ) : (
          <div className="mt-2 flex items-baseline gap-2">
            <span className={cn("text-3xl font-semibold tnum tracking-tight", toneCls)}>{value}</span>
            {delta}
          </div>
        )}
        {hint && <p className="mt-1 text-xs text-muted">{hint}</p>}
      </Card>
    </motion.div>
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
