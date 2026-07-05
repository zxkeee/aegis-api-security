import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { ErrorNote, PageHeader } from "@/components/PageBits";
import { Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type Finding } from "@/lib/api";
import { useData } from "@/lib/hooks";

interface FindingsResp {
  findings: Finding[];
  count: number;
  by_severity: { critical: number; warning: number; info: number };
}

export function Findings() {
  const { data, loading, error } = useData<FindingsResp>(() => api.get("/api/findings"), []);

  return (
    <div>
      <PageHeader
        title="Findings"
        desc="Actionable security exposures derived from the catalog — critical first."
        action={
          data ? (
            <div className="flex gap-2">
              <Pill n={data.by_severity.critical} tone="danger" label="critical" />
              <Pill n={data.by_severity.warning} tone="warn" label="warning" />
            </div>
          ) : null
        }
      />

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : !data?.findings.length ? (
        <EmptyState
          icon={<ShieldCheck size={40} />}
          title="No findings"
          hint="No exposed PII, shadow endpoints or auth gaps detected in the current catalog."
        />
      ) : (
        <div className="space-y-2">
          {data.findings.map((f, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: Math.min(i * 0.03, 0.4) }}
            >
              <Card className="flex items-center justify-between gap-4 p-4 transition-colors hover:border-accent/40">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.finding.severity} />
                    <span className="truncate text-sm font-medium">{f.finding.kind}</span>
                  </div>
                  <p className="mt-1 truncate text-xs text-muted">{f.finding.detail}</p>
                  <p className="mt-1 flex items-center gap-1.5 font-mono text-xs text-muted/80">
                    <MethodBadge method={f.method} /> {f.path_template}
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <div className="text-2xl font-semibold tnum text-danger">{f.risk_score}</div>
                  <div className="text-xs text-muted">risk</div>
                </div>
              </Card>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}

function Pill({ n, tone, label }: { n: number; tone: "danger" | "warn"; label: string }) {
  const cls = tone === "danger" ? "text-danger bg-danger/10" : "text-warn bg-warn/10";
  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${cls}`}>
      {n} {label}
    </span>
  );
}
