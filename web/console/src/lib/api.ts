// Thin admin-API client. Auth is cookie-based (HttpOnly session set by the
// gateway); mutations carry the CSRF token from the readable aegis_csrf cookie
// (double-submit). All requests are same-origin with credentials.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)aegis_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const opts: RequestInit = { method, credentials: "same-origin", headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrfToken();
  }
  const res = await fetch(path, opts);
  if (res.status === 401 || res.status === 403) {
    // Session gone / not authorized — signal the app to show the login screen.
    if (path !== "/api/login") window.dispatchEvent(new CustomEvent("aegis:unauthorized"));
  }
  const text = await res.text();
  const data = text ? safeJSON(text) : null;
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || res.statusText;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

function safeJSON(t: string): any {
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  del: <T>(p: string, b?: unknown) => request<T>("DELETE", p, b),

  // ── Auth ──
  loginSecret: (secret: string) => request<LoginResp>("POST", "/api/login", { secret }),
  loginPassword: (email: string, password: string, tenant?: string) =>
    request<LoginResp>("POST", "/api/login", { email, password, tenant }),
  logout: () => request<unknown>("POST", "/api/logout"),
};

// ── Response types ──
export interface LoginResp {
  auth: boolean;
  csrf: string;
  tenant?: string;
  role?: string;
}

export type Metrics = Record<string, number>;

export interface PostureSummary {
  total: number;
  protected: number;
  partial: number;
  unprotected: number;
  shadow: number;
  coverage_pct: number;
  top_risky?: Endpoint[];
}

export interface Endpoint {
  id: string;
  method: string;
  path_template: string;
  posture: string;
  risk_score: number;
  request_count: number;
  error_count: number;
  auth_present_count: number;
  anon_count: number;
  pii_count: number;
  avg_latency_ms: number;
  last_seen: string;
}

export interface Consumer {
  id: string;
  kind: string;
  label: string;
  request_count: number;
  error_count: number;
  endpoints_touched: number;
  last_seen: string;
}

export interface Finding {
  method: string;
  path_template: string;
  risk_score: number;
  finding: { severity: string; kind: string; detail: string };
}

export interface BlockEntry {
  tenant?: string;
  timestamp: string;
  ip: string;
  path: string;
  method: string;
  reason: string;
  code: number;
  // extra carries per-event detail (severity, why, owner, …) for abuse
  // detections like BOLA/BFLA. Present on security-relevant events.
  extra?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  type: "consumer" | "endpoint";
  label: string;
  requests: number;
  kind?: string;
  method?: string;
  posture?: string;
  risk?: number;
  pii?: boolean;
}
export interface GraphEdge {
  source: string;
  target: string;
  requests: number;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Effectiveness {
  blocks_by_control: Record<string, number>;
  total_blocks: number;
  passed_waf: number;
  coverage_pct?: number;
}
