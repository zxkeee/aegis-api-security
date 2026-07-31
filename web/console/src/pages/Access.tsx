import { motion } from "framer-motion";
import { Prohibit, Key, ShieldSlash, Trash } from "@phosphor-icons/react";
import { useState } from "react";
import { ErrorNote, PageHeader } from "@/components/PageBits";
import { Button, Card, EmptyState, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { useToast } from "@/lib/toast";

export function Access() {
  const toast = useToast();
  const ips = useData<{ ips: string[]; count: number }>(() => api.get("/api/blocked-ips"), []);
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

  async function unblock(ip: string) {
    setBusy(ip);
    try {
      await api.del(`/api/blocked-ips/${encodeURIComponent(ip)}`);
      toast("ok", `Unblocked ${ip}`);
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
              ips.data.ips.map((ip) => (
                <motion.div
                  key={ip}
                  layout
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center justify-between rounded-lg border border-border bg-bg px-3 py-2"
                >
                  <span className="font-mono text-xs">{ip}</span>
                  <Button variant="ghost" size="icon" onClick={() => unblock(ip)} disabled={busy === ip} aria-label={`Unblock ${ip}`}>
                    {busy === ip ? <Spinner /> : <Trash size={15} className="text-muted hover:text-danger" />}
                  </Button>
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
