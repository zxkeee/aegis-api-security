import { Badge } from "./ui";

export function PostureBadge({ posture }: { posture: string }) {
  const tone =
    posture === "protected" ? "ok" : posture === "partial" ? "warn" : posture === "shadow" ? "danger" : "danger";
  return <Badge tone={tone as any}>{posture}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = severity === "critical" ? "danger" : severity === "warning" ? "warn" : "neutral";
  return <Badge tone={tone as any}>{severity}</Badge>;
}

export function RiskDot({ score }: { score: number }) {
  const color = score >= 70 ? "bg-danger" : score >= 40 ? "bg-warn" : "bg-ok";
  return (
    <span className="inline-flex items-center gap-2 tnum">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      {score}
    </span>
  );
}

export function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    GET: "text-ok",
    POST: "text-accent",
    PUT: "text-warn",
    DELETE: "text-danger",
    PATCH: "text-warn",
  };
  return <span className={`font-mono text-xs font-semibold ${map[method] ?? "text-muted"}`}>{method}</span>;
}
