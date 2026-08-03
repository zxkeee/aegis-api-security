import { motion } from "framer-motion";
import { Prohibit, Key, ShieldSlash, Trash } from "@phosphor-icons/react";
import { useState } from "react";
import { ErrorNote, PageHeader } from "@/components/PageBits";
import { Button, Card, EmptyState, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { useToast } from "@/lib/toast";

interface BlockedIP {
  ip: string;
  // "manual" (deliberate, permanent) | "auto" (behaviour auto-ban, self-expires)
  // | "manual+auto" (both at once — unblocking "everything" here would also
  // silently lift the deliberate block, which is why unblock is source-aware).
  source: "manual" | "auto" | "manual+auto";
  ttl_seconds?: number;
}

function fmtTTL(secs?: number): string {
  if (!secs || secs <= 0) return "";
  const m = Math.ceil(secs / 60);
  return m < 60 ? `${m}m` : `${Math.ceil(m / 60)}h`;
}

export function Access() {
  const toast = useToast();
  const ips = useData<{ ips: BlockedIP[]; count: number }>(() => api.get("/api/blocked-ips"), []);
  const [newIP, setNewIP] = useState("");
  const [jti, setJti] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function block() {
    if (!newIP.trim()) return;
    setBusy("block");
    try {
      await api.post("/api/blocked-ips", { ip: newIP.trim(), reason: "manual" });
      toast("ok", `Blocked ${newIP.trim()}`);
      setNewIP("");
      ips.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to block");
    } finally {
      setBusy(null);
    }
  }

  // source omitted clears everything (both, if both apply) — same as before.
  // Passed explicitly for a "manual+auto" row so an operator can lift just
  // the auto-ban without discarding the deliberate manual block underneath.
  async function unblock(ip: string, source?: "manual" | "auto") {
    setBusy(ip + (source ?? ""));
    try {
      const qs = source ? `?source=${source}` : "";
      await api.del(`/api/blocked-ips/${encodeURIComponent(ip)}${qs}`);
      toast("ok", source ? `Lifted ${source} block on ${ip}` : `Unblocked ${ip}`);
      ips.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to unblock");
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    if (!jti.trim()) return;
    setBusy("revoke");
    try {
      await api.post("/api/jwt/revoke", { jti: jti.trim() });
      toast("ok", "Token revoked");
      setJti("");
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to revoke");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader title="Access Control" desc="Manually block IPs and revoke JSON Web Tokens." />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* IP blocklist */}
        <Card className="p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-medium">
            <ShieldSlash size={16} className="text-danger" /> IP blocklist
          </h3>
          <div className="flex gap-2">
            <Input
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && block()}
              placeholder="203.0.113.7"
              className="font-mono"
            />
            <Button onClick={block} disabled={busy === "block"}>
              {busy === "block" ? <Spinner /> : <Prohibit size={16} />}
              Block
            </Button>
          </div>

          <div className="mt-4 space-y-1.5">
            {ips.error ? (
              <ErrorNote error={ips.error} />
            ) : ips.data?.ips.length ? (
              ips.data.ips.map((row) => (
                <motion.div
                  key={row.ip}
                  layout
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center justify-between gap-2 rounded-lg border border-border bg-bg px-3 py-2"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="font-mono text-xs">{row.ip}</span>
                    <span
                      className="shrink-0 rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted"
                      title={row.source === "manual+auto" ? "manually blocked AND under a live auto-ban" : row.source === "auto" ? "self-expiring behaviour auto-ban" : "deliberate, permanent admin block"}
                    >
                      {row.source}
                      {row.source !== "manual" && row.ttl_seconds ? ` · ${fmtTTL(row.ttl_seconds)}` : ""}
                    </span>
                  </div>
                  {row.source === "manual+auto" ? (
                    <div className="flex shrink-0 gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => unblock(row.ip, "auto")}
                        disabled={busy === row.ip + "auto"}
                        aria-label={`Lift auto-ban on ${row.ip}, keep manual block`}
                        title="Lift only the auto-ban, keep the manual block"
                      >
                        {busy === row.ip + "auto" ? <Spinner /> : <ShieldSlash size={15} className="text-muted hover:text-fg" />}
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => unblock(row.ip, "manual")}
                        disabled={busy === row.ip + "manual"}
                        aria-label={`Lift manual block on ${row.ip}, keep auto-ban`}
                        title="Lift only the manual block, keep the auto-ban"
                      >
                        {busy === row.ip + "manual" ? <Spinner /> : <Trash size={15} className="text-muted hover:text-danger" />}
                      </Button>
                    </div>
                  ) : (
                    <Button variant="ghost" size="icon" onClick={() => unblock(row.ip)} disabled={busy === row.ip} aria-label={`Unblock ${row.ip}`}>
                      {busy === row.ip ? <Spinner /> : <Trash size={15} className="text-muted hover:text-danger" />}
                    </Button>
                  )}
                </motion.div>
              ))
            ) : (
              <EmptyState title="No IPs blocked" />
            )}
          </div>
        </Card>

        {/* JWT revocation */}
        <Card className="h-fit p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-medium">
            <Key size={16} className="text-warn" /> Revoke a token
          </h3>
          <p className="mb-3 text-xs text-muted">
            Enter a token's <code className="text-fg">jti</code> claim. It is rejected until the TTL (default 24h) expires.
          </p>
          <div className="flex gap-2">
            <Input
              value={jti}
              onChange={(e) => setJti(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && revoke()}
              placeholder="jti-value"
              className="font-mono"
            />
            <Button variant="danger" onClick={revoke} disabled={busy === "revoke"}>
              {busy === "revoke" ? <Spinner /> : "Revoke"}
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
