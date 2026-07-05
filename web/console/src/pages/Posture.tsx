import { motion } from "framer-motion";
import { PageHeader, StatCard, stagger } from "@/components/PageBits";
import { Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type PostureSummary } from "@/lib/api";
import { useData } from "@/lib/hooks";

export function Posture() {
  const { data, loading, error } = useData<PostureSummary>(() => api.get("/api/posture/summary"), []);

  return (
    <div>
      <PageHeader title="Posture" desc="How well the discovered API surface is protected." />

      {error ? (
        <EmptyState title="Posture unavailable" hint={error} />
      ) : (
        <>
          <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
            <CoverageRing pct={data?.coverage_pct ?? 0} loading={loading} />
            <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-2 gap-4">
              <StatCard label="Protected" value={data?.protected ?? 0} tone="accent" loading={loading} />
              <StatCard label="Partial" value={data?.partial ?? 0} tone="warn" loading={loading} />
              <StatCard label="Unprotected" value={data?.unprotected ?? 0} tone="danger" loading={loading} />
              <StatCard label="Shadow" value={data?.shadow ?? 0} tone="danger" loading={loading} />
            </motion.div>
          </div>
        </>
      )}
    </div>
  );
}

function CoverageRing({ pct, loading }: { pct: number; loading: boolean }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const tone = pct >= 70 ? "hsl(var(--ok))" : pct >= 40 ? "hsl(var(--warn))" : "hsl(var(--danger))";
  return (
    <Card className="flex flex-col items-center justify-center p-8">
      {loading ? (
        <Skeleton className="h-36 w-36 rounded-full" />
      ) : (
        <div className="relative h-36 w-36">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 128 128">
            <circle cx="64" cy="64" r={r} fill="none" stroke="hsl(var(--elevated))" strokeWidth="10" />
            <motion.circle
              cx="64"
              cy="64"
              r={r}
              fill="none"
              stroke={tone}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={c}
              initial={{ strokeDashoffset: c }}
              animate={{ strokeDashoffset: c - (c * pct) / 100 }}
              transition={{ duration: 0.9, ease: "easeOut" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-semibold tnum">{Math.round(pct)}%</span>
            <span className="text-xs text-muted">coverage</span>
          </div>
        </div>
      )}
      <p className="mt-4 text-center text-xs text-muted">Protected endpoints as a share of the total surface.</p>
    </Card>
  );
}
