import { motion } from "framer-motion";
import { useMemo } from "react";
import { DownloadSimple, ShieldCheck } from "@phosphor-icons/react";
import { ErrorNote, PageHeader, StatCard } from "@/components/PageBits";
import { Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type Finding } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt } from "@/lib/utils";

interface FindingsResp {
  findings: Finding[];
  count: number;
  by_severity: { critical: number; warning: number; info: number };
}

export function Findings() {
  const { data, loading, error } = useData<FindingsResp>(() => api.get("/api/findings"), []);

  // Real, computed from the findings actually returned — not fabricated.
  const avgRisk = useMemo(() => {
    if (!data?.findings.length) return undefined;
    return Math.round(data.findings.reduce((sum, f) => sum + f.risk_score, 0) / data.findings.length);
  }, [data]);

  return (
    <div>
      <PageHeader
        title="Findings"
        desc="Actionable security exposures derived from the catalog — critical first, mapped to OWASP API Top-10."
        action={
          data?.findings.length ? (
            <a
              href="/api/findings?format=csv"
              className="flex items-center gap-1.5 text-xs font-medium text-muted transition-colors hover:text-fg"
              download
            >
              <DownloadSimple size={14} /> Export CSV
            </a>
          ) : null
        }
      />

      {error ? (
        <ErrorNote error={error} />
      ) : (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Critical" value={data ? fmt(data.by_severity.critical) : undefined} tone="danger" loading={loading} />
          <StatCard label="Warning" value={data ? fmt(data.by_severity.warning) : undefined} loading={loading} />
          <StatCard label="Total findings" value={data ? fmt(data.count) : undefined} loading={loading} />
          <StatCard label="Avg. risk score" value={fmt(avgRisk)} loading={loading} hint={avgRisk == null ? undefined : "of the endpoints with findings"} />
        </div>
      )}

      <div className="mt-4">
        {loading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        ) : !data?.findings.length ? (
          !error && (
            <Card>
              <EmptyState
                icon={<ShieldCheck size={40} />}
                title="No findings"
                hint="No exposed PII, shadow endpoints or auth gaps detected in the current catalog."
              />
            </Card>
          )
        ) : (
          <Card className="divide-y divide-border/60">
            {data.findings.map((f, i) => (
              <FindingRow key={`${f.method} ${f.path_template} ${f.finding.code}`} f={f} i={i} />
            ))}
          </Card>
        )}
      </div>
    </div>
  );
}

function FindingRow({ f, i }: { f: Finding; i: number }) {
  const critical = f.finding.severity === "critical";
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(i * 0.03, 0.4) }}
      className="flex items-start gap-4 px-4 py-4 transition-colors hover:bg-elevated/40 sm:gap-5"
    >
      <span className="w-16 shrink-0 pt-0.5 sm:w-20">
        <span className={`inline-flex items-center gap-1.5 text-[11.5px] font-medium ${critical ? "text-danger" : "text-muted"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${critical ? "bg-danger" : "bg-muted"}`} />
          <span className="hidden sm:inline">{critical ? "Critical" : "Warning"}</span>
        </span>
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span className="rounded bg-elevated px-1.5 py-0.5 font-bold text-fg">{f.method}</span>
          <span className="text-fg">{f.path_template}</span>
          {f.finding.owasp && (
            <span className="rounded border border-border px-1.5 py-0.5 text-[10px] font-semibold text-muted">{f.finding.owasp}</span>
          )}
        </div>
        <p className="mt-1.5 text-[13.5px] font-medium text-fg">{f.finding.title}</p>
        {f.finding.why && <p className="mt-0.5 text-xs leading-relaxed text-muted">{f.finding.why}</p>}
      </div>
      <div className="shrink-0 text-center">
        <div className="text-[17px] font-bold tnum text-fg">{f.risk_score}</div>
        <div className="text-[9.5px] uppercase tracking-wide text-muted">risk</div>
      </div>
    </motion.div>
  );
}
