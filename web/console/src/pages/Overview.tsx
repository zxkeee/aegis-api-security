import { motion } from "framer-motion";
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, ClipboardText, Key, ListMagnifyingGlass, Warning } from "@phosphor-icons/react";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { Delta, PageHeader, StatCard, stagger } from "@/components/PageBits";
import { Card, EmptyState } from "@/components/ui";
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

/** Tracks the increase in a counter between polls, for a delta indicator. */
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

/** Accumulates real polled values into a short in-memory series. This is a
 * genuinely live chart, not a fabricated history: the backend has no
 * time-series store today (only cumulative counters), so there is no honest
 * way to show "last 24h" here. What's shown is real data observed since this
 * page was opened — labelled that way, not dressed up as more than it is. */
function useLiveSeries(value: number | undefined, maxPoints = 60) {
  const [series, setSeries] = useState<number[]>([]);
  const prev = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (value == null) return;
    if (prev.current != null) {
      const d = Math.max(0, value - prev.current);
      setSeries((s) => [...s.slice(-(maxPoints - 1)), d]);
    }
    prev.current = value;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return series;
}

export function Overview({ onNavigate }: { onNavigate?: (key: string) => void }) {
  const eff = useData<Effectiveness>(() => api.get("/api/effectiveness"), [], 10000);
  const posture = useData<PostureSummary>(() => api.get("/api/posture/summary"), [], 20000);
  const log = useData<BlockEntry[]>(() => api.get("/api/block-log"), [], 10000);

  const blocks = eff.data?.blocks_by_control ?? {};
  const totalBlocks = eff.data?.total_blocks ?? 0;
  const passed = eff.data?.passed_waf ?? 0;
  const coverage = posture.data?.coverage_pct;

  const passedDelta = useDelta(eff.data ? passed : undefined);
  const blocksDelta = useDelta(eff.data ? totalBlocks : undefined);
  const passedSeries = useLiveSeries(eff.data ? passed : undefined);

  const live = !eff.error;

  const criticalCount = useMemo(
    () => log.data?.filter((e) => e.extra?.severity === "critical").length ?? 0,
    [log.data],
  );

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
          loading={eff.loading}
          delta={passedDelta ? <Delta dir="up" context=" since last poll">+{fmt(passedDelta)}</Delta> : <span>clean through the WAF</span>}
        />
        <StatCard
          label="Total blocks"
          value={fmt(totalBlocks)}
          loading={eff.loading}
          delta={blocksDelta ? <Delta dir="down" context=" since last poll">+{fmt(blocksDelta)}</Delta> : <span>across all controls</span>}
        />
        <StatCard label="Coverage" value={pct(coverage)} loading={posture.loading} hint="protected endpoints" />
        <StatCard label="Active findings" value={fmt(criticalCount || undefined)} loading={log.loading} hint="critical, last 300 events" />
      </motion.div>

      <Card className="mt-4 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-[15px] font-semibold">Requests passed</h3>
            <p className="mt-0.5 text-xs text-faint text-muted">live — accumulated since this page opened, not a stored history</p>
          </div>
        </div>
        <LiveChart series={passedSeries} />
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.1fr_1fr_1fr]">
        <Card className="p-6">
          <h3 className="text-[15px] font-semibold">Blocks by control</h3>
          <p className="mt-0.5 text-xs text-muted">since process start</p>
          <BarList data={blocks} labels={CONTROL_LABEL} />
        </Card>

        <Card className="p-6">
          <h3 className="text-[15px] font-semibold">Posture</h3>
          <p className="mt-0.5 text-xs text-muted">{posture.data ? `${fmt(posture.data.total)} endpoints` : " "}</p>
          <PostureDonut data={posture.data} onNavigate={onNavigate} />
        </Card>

        <Card className="p-6">
          <h3 className="text-[15px] font-semibold">Quick actions</h3>
          <p className="mt-0.5 text-xs text-muted">Jump to what needs attention.</p>
          <div className="mt-3 flex flex-col">
            <QuickAction
              icon={<Warning size={16} />}
              title={criticalCount ? `Review ${criticalCount} critical event${criticalCount === 1 ? "" : "s"}` : "Review findings"}
              hint="Confirmed IDOR, PII exposure"
              onClick={() => onNavigate?.("findings")}
            />
            <QuickAction
              icon={<ClipboardText size={16} />}
              title="Export compliance report"
              hint="NIS2 / ISO 27001 mapping"
              onClick={() => onNavigate?.("compliance")}
            />
            <QuickAction
              icon={<ListMagnifyingGlass size={16} />}
              title="Browse the catalog"
              hint={posture.data ? `${fmt(posture.data.unprotected + posture.data.shadow)} unprotected or shadow` : undefined}
              onClick={() => onNavigate?.("catalog")}
            />
            <QuickAction icon={<Key size={16} />} title="Manage access" hint="Tenants, users, roles" onClick={() => onNavigate?.("access")} />
          </div>
        </Card>
      </div>

      <div className="mt-4">
        <h3 className="mb-2 text-[15px] font-semibold">Recent activity</h3>
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
    </div>
  );
}

function QuickAction({ icon, title, hint, onClick }: { icon: React.ReactNode; title: string; hint?: string; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className="group flex items-center gap-3 rounded-lg px-2 py-2.5 text-left transition-colors hover:bg-elevated"
    >
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-elevated text-muted">{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-medium text-fg">{title}</span>
        {hint && <span className="block truncate text-[11.5px] text-muted">{hint}</span>}
      </span>
      <ArrowRight size={13} className="shrink-0 text-muted opacity-0 transition-opacity group-hover:opacity-100" />
    </button>
  );
}

function BarList({ data, labels }: { data: Record<string, number>; labels: Record<string, string> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (entries.every(([, v]) => v === 0)) {
    return <p className="py-8 text-center text-sm text-muted">No blocks recorded yet.</p>;
  }
  return (
    <div className="mt-4 space-y-3">
      {entries.map(([k, v], i) => (
        <div key={k} className="flex items-center gap-3">
          <span className="w-20 shrink-0 text-xs text-muted">{labels[k] ?? k}</span>
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-elevated">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(v / max) * 100}%` }}
              transition={{ delay: i * 0.05, type: "spring", stiffness: 120, damping: 20 }}
              className="h-full rounded-full bg-fg/70"
            />
          </div>
          <span className="w-10 shrink-0 text-right text-xs tnum text-fg">{fmt(v)}</span>
        </div>
      ))}
    </div>
  );
}

/** Real posture split as a donut (protected/partial/unprotected/shadow),
 * grayscale-graded so severity reads as darkness, not a rainbow — only
 * "shadow" (the worst state) pops in the danger color. */
function PostureDonut({ data, onNavigate }: { data?: PostureSummary | null; onNavigate?: (key: string) => void }) {
  if (!data || data.total === 0) return <div className="flex h-40 items-center justify-center text-xs text-muted">No catalog data yet.</div>;
  const segs = [
    { label: "Protected", n: data.protected, cls: "stroke-fg" },
    { label: "Partial", n: data.partial, cls: "stroke-muted" },
    { label: "Unprotected", n: data.unprotected, cls: "stroke-muted/50" },
    { label: "Shadow", n: data.shadow, cls: "stroke-danger" },
  ];
  const R = 52;
  const C = 2 * Math.PI * R;
  let acc = 0;
  return (
    <div className="mt-2 flex flex-col items-center">
      <svg width="140" height="140" viewBox="0 0 140 140" className="-rotate-90">
        <circle cx="70" cy="70" r={R} className="stroke-border" strokeWidth="14" fill="none" />
        {segs.map((s) => {
          const frac = s.n / data.total;
          const dash = C * frac;
          const offset = -C * acc;
          acc += frac;
          if (frac === 0) return null;
          return (
            <motion.circle
              key={s.label}
              cx="70"
              cy="70"
              r={R}
              className={s.cls}
              strokeWidth="14"
              fill="none"
              strokeDasharray={`${dash} ${C - dash}`}
              initial={{ strokeDashoffset: offset, opacity: 0 }}
              animate={{ strokeDashoffset: offset, opacity: 1 }}
              transition={{ duration: 0.8, ease: [0.16, 0.8, 0.3, 1] }}
            />
          );
        })}
      </svg>
      <div className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1.5 text-[11.5px] text-muted">
        {segs.map((s) => (
          <button
            key={s.label}
            onClick={() => onNavigate?.("catalog")}
            className="flex items-center gap-1.5 hover:text-fg"
          >
            <span className={`h-2 w-2 rounded-sm ${s.cls.replace("stroke-", "bg-")}`} />
            {s.label} {data.total > 0 ? Math.round((s.n / data.total) * 100) : 0}%
          </button>
        ))}
      </div>
    </div>
  );
}

/** Thin single-stroke area chart of a live-accumulated series. No gridlines
 * with fabricated date labels — there's no historical backend to back them. */
function LiveChart({ series }: { series: number[] }) {
  if (series.length < 2) {
    return <div className="mt-4 flex h-[160px] items-center justify-center text-xs text-muted">Collecting live data…</div>;
  }
  const W = 1000, H = 160, PAD = 8;
  const max = Math.max(1, ...series);
  const step = (W - PAD * 2) / (series.length - 1);
  const pts = series.map((v, i) => [PAD + i * step, H - PAD - (v / max) * (H - PAD * 2)] as const);
  const line = "M" + pts.map((p) => p.join(",")).join(" L");
  const area = line + ` L${pts[pts.length - 1][0]},${H} L${pts[0][0]},${H} Z`;
  return (
    <svg className="mt-4 w-full" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ height: 160 }}>
      <path d={area} className="fill-fg/[0.06]" />
      <path d={line} className="stroke-fg" strokeWidth="1.75" fill="none" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
