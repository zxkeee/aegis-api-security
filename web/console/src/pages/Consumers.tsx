import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, EmptyState, Skeleton } from "@/components/ui";
import { api, type Consumer } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, timeAgo } from "@/lib/utils";

const KIND_TONE: Record<string, "accent" | "warn" | "neutral"> = {
  jwt: "accent",
  key: "warn",
  ip: "neutral",
};

export function Consumers() {
  const { data, loading, error } = useData<{ consumers: Consumer[]; count: number }>(
    () => api.get("/api/consumers?limit=200"),
    [],
  );
  const rows = (data?.consumers ?? []).slice().sort((a, b) => b.request_count - a.request_count);

  return (
    <div>
      <PageHeader title="Consumers" desc="Who calls the APIs — the identity graph behind the traffic." />

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No consumers yet" hint="Consumers appear as identified traffic flows through the gateway." />
      ) : (
        <Table
          head={
            <>
              <Th>Consumer</Th>
              <Th>Kind</Th>
              <Th className="text-right">Requests</Th>
              <Th className="hidden text-right sm:table-cell">Errors</Th>
              <Th className="hidden text-right md:table-cell">Endpoints</Th>
              <Th className="hidden text-right lg:table-cell">Last seen</Th>
            </>
          }
        >
          {rows.map((c, i) => (
            <Row key={c.id} i={i}>
              <Td className="max-w-[16rem] truncate font-mono text-xs">{c.label || c.id}</Td>
              <Td>
                <Badge tone={KIND_TONE[c.kind] ?? "neutral"}>{c.kind}</Badge>
              </Td>
              <Td className="text-right tnum">{fmt(c.request_count)}</Td>
              <Td className="hidden text-right tnum sm:table-cell">
                {c.error_count > 0 ? <span className="text-danger">{fmt(c.error_count)}</span> : "0"}
              </Td>
              <Td className="hidden text-right tnum md:table-cell">{c.endpoints_touched}</Td>
              <Td className="hidden text-right text-xs text-muted lg:table-cell">{timeAgo(c.last_seen)}</Td>
            </Row>
          ))}
        </Table>
      )}
    </div>
  );
}
