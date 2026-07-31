import { motion } from "framer-motion";
import { Buildings, Scroll, SealQuestion, Trash, UserPlus, UsersThree } from "@phosphor-icons/react";
import { useState } from "react";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, Button, Card, EmptyState, Input, Spinner } from "@/components/ui";
import { api, type AuditEntry, type IamUser, type Session, type Tenant } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { useToast } from "@/lib/toast";
import { timeAgo } from "@/lib/utils";

export function Settings({ session }: { session: Session }) {
  return (
    <div className="space-y-8">
      <PageHeader title="Settings" desc="Tenants, operators and the admin action trail." />
      <TenantsSection session={session} />
      <UsersSection session={session} />
      <AuditSection session={session} />
    </div>
  );
}

// ── Tenants ──────────────────────────────────────────────────────────────────
function TenantsSection({ session }: { session: Session }) {
  const toast = useToast();
  const tenants = useData<{ tenants: Tenant[]; count: number }>(() => api.listTenants(), []);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function create() {
    if (!id.trim()) return;
    setBusy("create");
    try {
      await api.createTenant(id.trim(), name.trim() || id.trim());
      toast("ok", `Tenant "${id.trim()}" created`);
      setId("");
      setName("");
      tenants.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to create tenant");
    } finally {
      setBusy(null);
    }
  }

  async function remove(tid: string) {
    setBusy(tid);
    try {
      await api.deleteTenant(tid);
      toast("ok", `Tenant "${tid}" deleted`);
      tenants.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to delete tenant");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
        <Buildings size={15} /> Tenants
      </h3>
      <Card className="p-5">
        {session.superAdmin && (
          <div className="mb-4 flex flex-wrap gap-2">
            <Input value={id} onChange={(e) => setId(e.target.value)} placeholder="tenant-id" className="max-w-[10rem] font-mono" />
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Display name (optional)" className="max-w-xs" />
            <Button onClick={create} disabled={busy === "create"}>
              {busy === "create" ? <Spinner /> : <Buildings size={16} />}
              Create tenant
            </Button>
          </div>
        )}
        {tenants.error ? (
          <ErrorNote error={tenants.error} />
        ) : !tenants.data?.tenants.length ? (
          <EmptyState title="No tenants" />
        ) : (
          <div className="space-y-1.5">
            {tenants.data.tenants.map((t) => (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-center justify-between rounded-lg border border-border bg-bg px-3 py-2"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs">{t.id}</span>
                  {t.name && t.name !== t.id && <span className="text-xs text-muted">{t.name}</span>}
                  {t.id === session.tenant && <Badge tone="accent">you</Badge>}
                </div>
                {session.superAdmin && t.id !== "default" && (
                  <Button variant="ghost" size="icon" onClick={() => remove(t.id)} disabled={busy === t.id} aria-label={`Delete ${t.id}`}>
                    {busy === t.id ? <Spinner /> : <Trash size={15} className="text-muted hover:text-danger" />}
                  </Button>
                )}
              </motion.div>
            ))}
          </div>
        )}
        {!session.superAdmin && (
          <p className="mt-3 text-xs text-muted/70">Only your own tenant is visible. Super-admin required to manage others.</p>
        )}
      </Card>
    </section>
  );
}

// ── Users ────────────────────────────────────────────────────────────────────
function UsersSection({ session }: { session: Session }) {
  const toast = useToast();
  const users = useData<{ users: IamUser[]; count: number }>(() => api.listUsers(), []);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("admin");
  const [superAdmin, setSuperAdmin] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  async function create() {
    if (!email.trim() || password.length < 12) {
      toast("err", "Email and a 12+ character password are required");
      return;
    }
    setBusy("create");
    try {
      await api.createUser({ email: email.trim(), password, role, super_admin: session.superAdmin ? superAdmin : undefined });
      toast("ok", `User ${email.trim()} created`);
      setEmail("");
      setPassword("");
      users.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to create user");
    } finally {
      setBusy(null);
    }
  }

  async function remove(u: IamUser) {
    setBusy(u.id);
    try {
      await api.deleteUser(u.id);
      toast("ok", `${u.email} removed`);
      users.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to delete user");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <h3 className="mb-3 flex items-center gap-2 text-sm font-medium text-muted">
        <UsersThree size={15} /> Operators
      </h3>
      <Card className="p-5">
        <div className="mb-4 flex flex-wrap gap-2">
          <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.com" className="max-w-[14rem]" />
          <Input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password (12+ chars)"
            type="password"
            className="max-w-[12rem]"
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="h-10 rounded-lg border border-border bg-bg px-3 text-sm text-fg"
          >
            <option value="admin">admin</option>
            <option value="viewer">viewer</option>
          </select>
          {session.superAdmin && (
            <label className="flex items-center gap-2 rounded-lg border border-border px-3 text-xs text-muted">
              <input type="checkbox" checked={superAdmin} onChange={(e) => setSuperAdmin(e.target.checked)} className="accent-accent" />
              Super-admin
            </label>
          )}
          <Button onClick={create} disabled={busy === "create"}>
            {busy === "create" ? <Spinner /> : <UserPlus size={16} />}
            Add operator
          </Button>
        </div>

        {users.error ? (
          <ErrorNote error={users.error} />
        ) : !users.data?.users.length ? (
          <EmptyState title="No operators yet" hint="Add teammates so they don't have to share the bootstrap secret." />
        ) : (
          <Table
            head={
              <>
                <Th>Email</Th>
                <Th>Role</Th>
                <Th className="hidden md:table-cell">Tenant</Th>
                <Th className="hidden text-right sm:table-cell">Created</Th>
                <Th className="text-right">·</Th>
              </>
            }
          >
            {users.data.users.map((u, i) => (
              <Row key={u.id} i={i}>
                <Td className="text-xs">{u.email}</Td>
                <Td>
                  <div className="flex items-center gap-1.5">
                    <Badge tone={u.role === "admin" ? "accent" : "neutral"}>{u.role}</Badge>
                    {u.super_admin && <Badge tone="warn">super</Badge>}
                  </div>
                </Td>
                <Td className="hidden font-mono text-xs text-muted md:table-cell">{u.tenant_id}</Td>
                <Td className="hidden text-right text-xs text-muted sm:table-cell">{timeAgo(u.created_at)}</Td>
                <Td className="text-right">
                  <Button variant="ghost" size="icon" onClick={() => remove(u)} disabled={busy === u.id} aria-label={`Remove ${u.email}`}>
                    {busy === u.id ? <Spinner /> : <Trash size={15} className="text-muted hover:text-danger" />}
                  </Button>
                </Td>
              </Row>
            ))}
          </Table>
        )}
      </Card>
    </section>
  );
}

// ── Audit log ────────────────────────────────────────────────────────────────
function AuditSection({ session }: { session: Session }) {
  const [all, setAll] = useState(false);
  const audit = useData<{ entries: AuditEntry[]; count: number }>(() => api.audit({ limit: 100, all }), [all]);
  const disabled = audit.error?.includes("audit log is disabled");

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-medium text-muted">
          <Scroll size={15} /> Audit trail
        </h3>
        {session.superAdmin && (
          <label className="flex items-center gap-2 text-xs text-muted">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} className="accent-accent" />
            All tenants
          </label>
        )}
      </div>
      {audit.error && !disabled ? (
        <ErrorNote error={audit.error} />
      ) : disabled || !audit.data?.entries.length ? (
        <Card className="p-5">
          <EmptyState
            icon={<SealQuestion size={36} />}
            title={disabled ? "Audit log disabled" : "No admin activity yet"}
            hint={disabled ? "Set forensic_dsn to enable the audit trail." : "Logins, blocks and token revocations will appear here."}
          />
        </Card>
      ) : (
        <Table
          head={
            <>
              <Th>Action</Th>
              <Th>Actor</Th>
              <Th className="hidden md:table-cell">Tenant</Th>
              <Th className="hidden text-right sm:table-cell">Status</Th>
              <Th className="text-right">When</Th>
            </>
          }
        >
          {(audit.data?.entries ?? []).map((e, i) => (
            <Row key={i} i={i}>
              <Td>
                <Badge tone={e.action.includes("fail") ? "danger" : e.action === "login" ? "accent" : "neutral"}>
                  {e.action.replace(/_/g, " ")}
                </Badge>
              </Td>
              <Td className="text-xs">{e.actor_email || e.actor_id || "bootstrap secret"}</Td>
              <Td className="hidden font-mono text-xs text-muted md:table-cell">{e.tenant_id}</Td>
              <Td className="hidden text-right tnum sm:table-cell">
                {e.status ? <span className={e.status >= 400 ? "text-danger" : "text-muted"}>{e.status}</span> : "—"}
              </Td>
              <Td className="text-right text-xs text-muted">{timeAgo(e.time)}</Td>
            </Row>
          ))}
        </Table>
      )}
    </section>
  );
}
