import { useCallback, useEffect, useState } from "react";
import { Shell } from "@/components/Shell";
import { Spinner } from "@/components/ui";
import { api, type Session } from "@/lib/api";
import { Access } from "@/pages/Access";
import { Catalog } from "@/pages/Catalog";
import { Compliance } from "@/pages/Compliance";
import { Consumers } from "@/pages/Consumers";
import { Findings } from "@/pages/Findings";
import { Forensics } from "@/pages/Forensics";
import { Graph } from "@/pages/Graph";
import { Login } from "@/pages/Login";
import { Overview } from "@/pages/Overview";
import { Posture } from "@/pages/Posture";
import { Settings } from "@/pages/Settings";

const PAGES: Record<string, React.ComponentType<{ session: Session }>> = {
  overview: Overview,
  catalog: Catalog,
  posture: Posture,
  findings: Findings,
  compliance: Compliance,
  consumers: Consumers,
  map: Graph,
  forensics: Forensics,
  access: Access,
  settings: Settings,
};

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [session, setSession] = useState<Session>({});
  const [active, setActive] = useState("overview");
  const [refreshKey, setRefreshKey] = useState(0);

  // Probe the session cookie on load; skip the login screen if it's still
  // valid, and rehydrate who's signed in (the login response only fires once,
  // at login time, and doesn't survive a page refresh).
  const probe = useCallback(async () => {
    try {
      const s = await api.session();
      setSession({ tenant: s.tenant, role: s.role, superAdmin: s.super_admin });
      setAuthed(true);
    } catch {
      setAuthed(false);
    }
  }, []);

  useEffect(() => {
    probe();
    const onUnauth = () => setAuthed(false);
    window.addEventListener("aegis:unauthorized", onUnauth);
    return () => window.removeEventListener("aegis:unauthorized", onUnauth);
  }, [probe]);

  async function onLogout() {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    setAuthed(false);
  }

  if (authed === null) {
    return (
      <div className="flex min-h-dvh items-center justify-center text-muted">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (!authed) {
    return (
      <Login
        onAuthed={(s) => {
          history.replaceState(null, "", location.pathname); // drop ?sso_error
          setSession(s);
          setAuthed(true);
          setActive("overview");
        }}
      />
    );
  }

  const Page = PAGES[active] ?? Overview;
  return (
    <Shell
      active={active}
      onNavigate={setActive}
      onRefresh={() => setRefreshKey((k) => k + 1)}
      onLogout={onLogout}
      session={session}
    >
      <div key={`${active}-${refreshKey}`}>
        <Page session={session} />
      </div>
    </Shell>
  );
}
