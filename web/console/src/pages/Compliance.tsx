import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";
import { SeverityBadge } from "@/components/badges";
import { ErrorNote, PageHeader } from "@/components/PageBits";
import { Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type ComplianceReport } from "@/lib/api";
import { useData } from "@/lib/hooks";

export function Compliance() {
  const { data, loading, error } = useData<ComplianceReport>(() => api.get("/api/compliance"), []);
  const hasAny = data && data.frameworks.length > 0;

  return (
    <div>
      <PageHeader
        title="Compliance"
        desc="Your API-security findings mapped to NIS2 and ISO 27001 controls — the auditor's language."
        action={
          data ? (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Pill n={data.summary.critical} tone="danger" label="critical" />
              <Pill n={data.summary.warning} tone="warn" label="warning" />
              <span className="text-muted">{data.summary.controls_affected} controls affected</span>
            </div>
          ) : null
        }
      />

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full" />
          ))}
        </div>
      ) : !hasAny ? (
        <EmptyState
          icon={<ShieldCheck size={40} />}
          title="No mapped findings"
          hint="No exposures or access-control abuse detected to map onto compliance controls. Drive traffic to build the picture."
        />
      ) : (
        <div className="space-y-6">
          {data!.frameworks.map((fw) => (
            <section key={fw.framework}>
              <h2 className="mb-2 text-sm font-semibold tracking-tight">{fw.framework}</h2>
              <div className="space-y-2">
                {fw.controls.map((c, i) => (
                  <motion.div
                    key={c.control}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: Math.min(i * 0.03, 0.3) }}
                  >
                    <Card className="p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={c.severity} />
                            <span className="font-mono text-xs text-muted">{c.control}</span>
                            <span className="truncate text-sm font-medium">{c.title}</span>
                          </div>
                          <ul className="mt-2 space-y-1">
                            {c.issues.map((iss, j) => (
                              <li key={j} className="truncate text-xs text-muted" title={iss}>
                                • {iss}
                              </li>
                            ))}
                          </ul>
                        </div>
                        <div className="shrink-0 text-right">
                          <div className="text-2xl font-semibold tnum">{c.count}</div>
                          <div className="text-xs text-muted">issues</div>
                        </div>
                      </div>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </section>
          ))}
          <p className="pt-1 text-xs text-muted/70">
            Mapping aid across OWASP API Top 10, NIS2 (Art. 21(2)) and ISO/IEC 27001:2022 Annex A — not a legal
            certification.
          </p>
        </div>
      )}
    </div>
  );
}

function Pill({ n, tone, label }: { n: number; tone: "danger" | "warn"; label: string }) {
  const cls = tone === "danger" ? "text-danger bg-danger/10" : "text-warn bg-warn/10";
  return <span className={`rounded-full px-2.5 py-1 font-medium ${cls}`}>{n} {label}</span>;
}
