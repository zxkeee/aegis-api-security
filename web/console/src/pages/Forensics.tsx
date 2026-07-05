import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { MethodBadge } from "@/components/badges";
import { Badge, EmptyState, Skeleton } from "@/components/ui";
import { api, type BlockEntry } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { timeAgo } from "@/lib/utils";

function reasonTone(reason: string): "danger" | "warn" | "neutral" {
  if (reason.includes("waf") || reason.includes("sqli") || reason.includes("traversal")) return "danger";
  if (reason.includes("rate") || reason.includes("behavior") || reason.includes("bot")) return "warn";
  return "neutral";
}

export function Forensics() {
  const { data, loading, error } = useData<BlockEntry[]>(() => api.get("/api/block-log"), [], 8000);
  const rows = data ?? [];

  return (
    <div>
      <PageHeader title="Forensics" desc="Recent security block events, newest first." />

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-11 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No block events" hint="Blocked requests appear here as controls trigger." />
      ) : (
        <Table
          head={
            <>
              <Th>Reason</Th>
              <Th>Source IP</Th>
              <Th className="hidden md:table-cell">Request</Th>
              <Th className="text-right">Code</Th>
              <Th className="hidden text-right sm:table-cell">When</Th>
            </>
          }
        >
          {rows.map((e, i) => (
            <Row key={i} i={i}>
              <Td>
                <Badge tone={reasonTone(e.reason)}>{e.reason.replace(/_/g, " ")}</Badge>
              </Td>
              <Td className="font-mono text-xs">{e.ip}</Td>
              <Td className="hidden max-w-[20rem] truncate font-mono text-xs md:table-cell">
                <MethodBadge method={e.method} /> {e.path}
              </Td>
              <Td className="text-right tnum">
                <span className={e.code >= 500 ? "text-danger" : "text-muted"}>{e.code}</span>
              </Td>
              <Td className="hidden text-right text-xs text-muted sm:table-cell">{timeAgo(e.timestamp)}</Td>
            </Row>
          ))}
        </Table>
      )}
    </div>
  );
}
