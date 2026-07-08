import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Boxes,
  LayoutGrid,
  LogOut,
  Moon,
  RefreshCw,
  Share2,
  ShieldCheck,
  Sun,
  Users,
  Waypoints,
} from "lucide-react";
import { type ReactNode } from "react";
import { Button } from "./ui";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

export interface NavItem {
  key: string;
  label: string;
  icon: ReactNode;
}

export const NAV: NavItem[] = [
  { key: "overview", label: "Overview", icon: <LayoutGrid size={18} /> },
  { key: "catalog", label: "Catalog", icon: <Boxes size={18} /> },
  { key: "posture", label: "Posture", icon: <ShieldCheck size={18} /> },
  { key: "findings", label: "Findings", icon: <AlertTriangle size={18} /> },
  { key: "consumers", label: "Consumers", icon: <Users size={18} /> },
  { key: "map", label: "Map", icon: <Share2 size={18} /> },
  { key: "forensics", label: "Forensics", icon: <Activity size={18} /> },
  { key: "access", label: "Access", icon: <Waypoints size={18} /> },
];

export function Shell({
  active,
  onNavigate,
  onRefresh,
  onLogout,
  session,
  children,
}: {
  active: string;
  onNavigate: (k: string) => void;
  onRefresh: () => void;
  onLogout: () => void;
  session: { tenant?: string; role?: string };
  children: ReactNode;
}) {
  const { theme, toggle } = useTheme();
  const title = NAV.find((n) => n.key === active)?.label ?? "";

  return (
    <div className="flex min-h-dvh">
      {/* Sidebar */}
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col border-r border-border bg-surface/60 px-3 py-5 backdrop-blur md:flex">
        <div className="mb-8 flex items-center gap-2.5 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/12 text-accent">
            <ShieldCheck size={18} />
          </div>
          <span className="text-sm font-semibold tracking-tight">AEGIS</span>
        </div>

        <nav className="flex flex-col gap-1">
          {NAV.map((item) => {
            const on = item.key === active;
            return (
              <button
                key={item.key}
                onClick={() => onNavigate(item.key)}
                className={cn(
                  "relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  on ? "text-fg" : "text-muted hover:text-fg hover:bg-elevated/60",
                )}
              >
                {on && (
                  <motion.span
                    layoutId="nav-active"
                    className="absolute inset-0 rounded-lg bg-elevated"
                    transition={{ type: "spring", stiffness: 400, damping: 32 }}
                  />
                )}
                <span className="relative z-10">{item.icon}</span>
                <span className="relative z-10">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="mt-auto px-2 text-xs text-muted">
          <div className="truncate">{session.tenant ?? "default"}</div>
          <div className="capitalize text-muted/70">{session.role ?? "admin"}</div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-bg/70 px-4 backdrop-blur md:px-6">
          <div className="flex items-center gap-2">
            {/* Mobile nav */}
            <div className="flex gap-1 md:hidden">
              {NAV.map((n) => (
                <button
                  key={n.key}
                  onClick={() => onNavigate(n.key)}
                  className={cn("rounded-md p-2", n.key === active ? "text-accent" : "text-muted")}
                  aria-label={n.label}
                >
                  {n.icon}
                </button>
              ))}
            </div>
            <h1 className="hidden text-sm font-semibold md:block">{title}</h1>
          </div>

          <div className="flex items-center gap-1">
            <Button variant="ghost" size="icon" onClick={onRefresh} aria-label="Refresh">
              <RefreshCw size={17} />
            </Button>
            <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={theme}
                  initial={{ rotate: -90, opacity: 0 }}
                  animate={{ rotate: 0, opacity: 1 }}
                  exit={{ rotate: 90, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="block"
                >
                  {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
                </motion.span>
              </AnimatePresence>
            </Button>
            <Button variant="ghost" size="icon" onClick={onLogout} aria-label="Sign out">
              <LogOut size={17} />
            </Button>
          </div>
        </header>

        <main className="flex-1 px-4 py-6 md:px-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="mx-auto max-w-6xl"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
