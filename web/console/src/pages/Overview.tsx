import { motion } from "framer-motion";
import { Ban, CheckCircle2, Gauge, ShieldAlert, Boxes, Radar } from "lucide-react";
import { PageHeader, StatCard, stagger, Table, Th, Row, Td } from "@/components/PageBits";
import { Badge, Card } from "@/components/ui";
import { api, type Effectiveness, type PostureSummary } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, pct } from "@/lib/utils";

const CONTROL_LABEL: Record<string, string> = {
  waf: "WAF",
  rate_limit: "Rate limit",
  ip_guard: "IP guard",
  behavior: "Behaviour",
  threatfeed: "Threat feed",
  bot: "Bot",
  dlp: "DLP",
};

export function Overview() {
  const eff = useData<Effectiveness>(() => api.get("/api/effectiveness"), [], 10000);
  const posture = useData<PostureSummary>(() => api.get("/api/posture/summary"), []);

  const blocks = eff.data?.blocks_by_control ?? {};
  const totalBlocks = eff.data?.total_blocks ?? 0;
  const passed = eff.data?.passed_waf ?? 0;
  const coverage = posture.data?.coverage_pct;

  return (
    <div>
      <PageHeader title="Overview" desc="Live protection posture and control effectiveness." />

      <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Requests passed"
          value={fmt(passed)}
          icon={<CheckCircle2 size={18} />}
          tone="accent"
          loading={eff.loading}
          hint="Clean through the WAF"
        />
        <StatCard
          label="Total blocks"
          value={fmt(totalBlocks)}
          icon={<Ban size={18} />}
          tone="danger"
          loading={eff.loading}
          hint="Across all controls"
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
          icon={<Boxes size={18} />}
          loading={posture.loading}
          hint="Discovered surface"
        />
      </motion.div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {/* Blocks by control */}
        <div>
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
            <ShieldAlert size={15} /> Blocks by control
          </h3>
          <Card className="p-5">
            <BarList data={blocks} labels={CONTROL_LABEL} />
          </Card>
        </div>

        {/* Posture split */}
        <div>
          <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
            <Radar size={15} /> Posture distribution
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

      {/* Top risky endpoints */}
      {posture.data?.top_risky?.length ? (
        <div className="mt-6">
          <h3 className="mb-3 text-sm font-medium text-muted">Top risk endpoints</h3>
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
        </div>
      ) : null}
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
