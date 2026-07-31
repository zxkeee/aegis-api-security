import { motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { Prohibit, CheckCircle, Gauge, ShieldWarning, Package, ChartDonut, Pulse } from "@phosphor-icons/react";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { PageHeader, StatCard, stagger, Table, Th, Row, Td } from "@/components/PageBits";
import { Badge, Card, EmptyState } from "@/components/ui";
import { api, type BlockEntry, type Effectiveness, type PostureSummary } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, pct, timeAgo } from "@/lib/utils";

const CONTROL_LABEL: Record<string, string> = {
  waf: "WAF",
  rate_limit: "Rate limit",
  ip_guard: "IP guard",
  behavior: "Behaviour",
  threatfeed: "Threat feed",
  bot: "Bot",
  dlp: "DLP",
};

/** Tracks the increase in a counter between polls, for a small "+N" delta chip. */
function useDelta(value: number | undefined) {
  const prev = useRef<number | undefined>(undefined);
  const [delta, setDelta] = useState<number | null>(null);
  useEffect(() => {
    if (value == null) return;
    if (prev.current != null && value > prev.current) setDelta(value - prev.current);
    prev.current = value;
  }, [value]);
  return delta;
}

function DeltaChip({ n }: { n: number | null }) {
  if (!n) return null;
  return (
    <motion.span
      key={n}
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-full bg-ok/12 px-1.5 py-0.5 text-[11px] font-medium tnum text-ok"
    >
      +{fmt(n)}
    </motion.span>
  );
}

export function Overview() {
  const eff = useData<Effectiveness>(() => api.get("/api/effectiveness"), [], 10000);
  const posture = useData<PostureSummary>(() => api.get("/api/posture/summary"), [], 20000);
  const log = useData<BlockEntry[]>(() => api.get("/api/block-log"), [], 10000);

  const blocks = eff.data?.blocks_by_control ?? {};
  const totalBlocks = eff.data?.total_blocks ?? 0;
  const passed = eff.data?.passed_waf ?? 0;
  const coverage = posture.data?.coverage_pct;

  const passedDelta = useDelta(eff.data ? passed : undefined);
  const blocksDelta = useDelta(eff.data ? totalBlocks : undefined);

  const live = !eff.error;

  return (
    <div>
      <PageHeader
        title="Overview"
        desc="Live protection posture and control effectiveness."
        action={
          <span className="flex items-center gap-2 text-xs text-muted">
            <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-ok" : "bg-danger"}`} />
            {live ? "Live" : "Unreachable"}
          </span>
        }
      />

      <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Requests passed"
          value={fmt(passed)}
          icon={<CheckCircle size={18} />}
          tone="accent"
          loading={eff.loading}
          hint="Clean through the WAF"
          delta={<DeltaChip n={passedDelta} />}
        />
        <StatCard
          label="Total blocks"
          value={fmt(totalBlocks)}
          icon={<Prohibit size={18} />}
          tone="danger"
          loading={eff.loading}
          hint="Across all controls"
          delta={<DeltaChip n={blocksDelta} />}
        />
        <StatCard
          label="Coverage"
          value={pct(coverage)}
          icon={<Gauge size={18} />}
          tone="warn"
          loading={posture.loading}
          hint="Protected endpoints"
        />
        <StatCard
          label="Endpoints"
          value={fmt(posture.data?.total)}
          icon={<Package size={18} />}
          loading={posture.loading}
          hint="Discovered surface"
        />
      </motion.div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {/* Blocks by control */}
        <div>
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
            <ShieldWarning size={15} /> Blocks by control
          </h3>
          <Card className="p-5">
            <BarList data={blocks} labels={CONTROL_LABEL} />
          </Card>
        </div>

        {/* Posture split */}
        <div>
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
            <ChartDonut size={15} /> Posture distribution
          </h3>
          <Card className="p-5">
            {posture.data ? (
              <div className="space-y-3">
                <PostureBar label="Protected" n={posture.data.protected} total={posture.data.total} tone="bg-ok" />
                <PostureBar label="Partial" n={posture.data.partial} total={posture.data.total} tone="bg-warn" />
                <PostureBar label="Unprotected" n={posture.data.unprotected} total={posture.data.total} tone="bg-danger" />
                <PostureBar label="Shadow" n={posture.data.shadow} total={posture.data.total} tone="bg-danger/60" />
              </div>
            ) : (
              <div className="h-32" />
            )}
          </Card>
        </div>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {/* Recent activity */}
        <div>
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
            <Pulse size={15} /> Recent activity
          </h3>
          <Card className="divide-y divide-border/60">
            {!log.data?.length ? (
              <EmptyState title="No events yet" hint="Blocks and abuse detections will stream in here." />
            ) : (
              log.data.slice(0, 6).map((e, i) => {
                const severity = typeof e.extra?.severity === "string" ? e.extra.severity : undefined;
                return (
                  <div key={i} className="flex items-center justify-between gap-3 px-4 py-2.5 text-xs">
                    <div className="flex min-w-0 items-center gap-2">
                      {severity && <SeverityBadge severity={severity} />}
                      <span className="truncate text-muted">{e.reason.replace(/_/g, " ")}</span>
                      <MethodBadge method={e.method} />
                      <span className="truncate font-mono text-muted/80">{e.path}</span>
                    </div>
                    <span className="shrink-0 text-muted/70">{timeAgo(e.timestamp)}</span>
                  </div>
                );
              })
            )}
          </Card>
        </div>

        {/* Top risky endpoints */}
        <div>
          <h3 className="mb-3 text-sm font-medium text-muted">Top risk endpoints</h3>
          {posture.data?.top_risky?.length ? (
            <Table
              head={
                <>
                  <Th>Endpoint</Th>
                  <Th className="text-right">Risk</Th>
                  <Th className="hidden text-right sm:table-cell">Requests</Th>
                </>
              }
            >
              {posture.data.top_risky.slice(0, 6).map((e, i) => (
                <Row key={e.id} i={i}>
                  <Td className="font-mono text-xs">
                    <span className="text-accent">{e.method}</span> {e.path_template}
                  </Td>
                  <Td className="text-right">
                    <Badge tone={e.risk_score >= 70 ? "danger" : e.risk_score >= 40 ? "warn" : "neutral"}>
                      {e.risk_score}
                    </Badge>
                  </Td>
                  <Td className="hidden text-right tnum sm:table-cell">{fmt(e.request_count)}</Td>
                </Row>
              ))}
            </Table>
          ) : (
            <Card>
              <EmptyState title="No risk data yet" hint="Populates once the catalog scores discovered endpoints." />
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function BarList({ data, labels }: { data: Record<string, number>; labels: Record<string, string> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (entries.every(([, v]) => v === 0)) {
    return <p className="py-8 text-center text-sm text-muted">No blocks recorded yet.</p>;
  }
  return (
    <div className="space-y-3">
      {entries.map(([k, v], i) => (
        <div key={k} className="flex items-center gap-3">
          <span className="w-24 shrink-0 text-xs text-muted">{labels[k] ?? k}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-elevated">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(v / max) * 100}%` }}
              transition={{ delay: i * 0.05, type: "spring", stiffness: 120, damping: 20 }}
              className="h-full rounded-full bg-accent"
            />
          </div>
          <span className="w-10 shrink-0 text-right text-xs tnum text-fg">{fmt(v)}</span>
        </div>
      ))}
    </div>
  );
}

function PostureBar({ label, n, total, tone }: { label: string; n: number; total: number; tone: string }) {
  const w = total > 0 ? (n / total) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <span className="w-24 shrink-0 text-xs text-muted">{label}</span>
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-elevated">
        <motion.div initial={{ width: 0 }} animate={{ width: `${w}%` }} transition={{ type: "spring", stiffness: 120, damping: 20 }} className={`h-full rounded-full ${tone}`} />
      </div>
      <span className="w-8 shrink-0 text-right text-xs tnum">{n}</span>
    </div>
  );
}
