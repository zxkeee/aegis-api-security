import { MagnifyingGlass } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { MethodBadge, PostureBadge, RiskDot } from "@/components/badges";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, EmptyState, Input, Skeleton } from "@/components/ui";
import { api, type Endpoint } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, timeAgo } from "@/lib/utils";

const FILTERS = ["all", "protected", "partial", "unprotected", "shadow"] as const;

export function Catalog() {
  const { data, loading, error } = useData<{ endpoints: Endpoint[]; count: number }>(
    () => api.get("/api/catalog?limit=500"),
    [],
  );
  const [q, setQ] = useState("");
  const [posture, setPosture] = useState<(typeof FILTERS)[number]>("all");

  const rows = useMemo(() => {
    let eps = data?.endpoints ?? [];
    if (posture !== "all") eps = eps.filter((e) => e.posture === posture);
    if (q.trim()) {
      const s = q.toLowerCase();
      eps = eps.filter((e) => e.path_template.toLowerCase().includes(s) || e.method.toLowerCase().includes(s));
    }
    return [...eps].sort((a, b) => b.risk_score - a.risk_score);
  }, [data, q, posture]);

  return (
    <div>
      <PageHeader title="API Catalog" desc="Every endpoint discovered from live traffic." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[16rem] flex-1">
          <MagnifyingGlass size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search endpoints…" className="pl-9" />
        </div>
        <div className="flex gap-1 rounded-lg border border-border bg-surface p-1">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setPosture(f)}
              className={`rounded-md px-2.5 py-1 text-xs capitalize transition-colors ${
                posture === f ? "bg-accent text-accent-fg" : "text-muted hover:text-fg"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No endpoints" hint="Traffic through the gateway populates the catalog automatically." />
      ) : (
        <Table
          head={
            <>
              <Th>Endpoint</Th>
              <Th>Posture</Th>
              <Th className="text-right">Risk</Th>
              <Th className="hidden text-right md:table-cell">Requests</Th>
              <Th className="hidden text-right md:table-cell">PII</Th>
              <Th className="hidden text-right lg:table-cell">Last seen</Th>
            </>
          }
        >
          {rows.map((e, i) => (
            <Row key={e.id} i={i}>
              <Td>
                <span className="flex items-center gap-2 font-mono text-xs">
                  <MethodBadge method={e.method} />
                  <span className="truncate">{e.path_template}</span>
                </span>
              </Td>
              <Td>
                <PostureBadge posture={e.posture} />
              </Td>
              <Td className="text-right">
                <RiskDot score={e.risk_score} />
              </Td>
              <Td className="hidden text-right tnum md:table-cell">{fmt(e.request_count)}</Td>
              <Td className="hidden text-right md:table-cell">
                {e.pii_count > 0 ? <Badge tone="danger">{fmt(e.pii_count)}</Badge> : <span className="text-muted">—</span>}
              </Td>
              <Td className="hidden text-right text-xs text-muted lg:table-cell">{timeAgo(e.last_seen)}</Td>
            </Row>
          ))}
        </Table>
      )}
    </div>
  );
}
