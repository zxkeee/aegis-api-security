# Reliability under load — PostgreSQL outage + graceful drain (2026-07-08)

Closes two of the three items left open by the Redis-outage run
(`redis-outage-results-2026-06-26.md`, "Still open"):

1. **PostgreSQL outage under load** — catalog/forensic backing store killed mid-run.
2. **Rolling-update drain** — zero-5xx during `Shutdown` under sustained traffic,
   plus a new lame-duck grace so rollouts cause zero connection errors.

> **Environment honesty.** This run is on **macOS + Docker Desktop** (backing
> services in containers, gateway as a host binary on ports 18080/18081). It
> validates *behaviour* (does the data plane survive a PG outage; does the drain
> shed 5xx). It is **not** a published-capacity benchmark — the Docker Desktop VM
> adds latency/scheduling overhead, so absolute RPS/latency numbers here are
> indicative only. Capacity numbers still need the dedicated-hardware run.

## Setup

- **Gateway:** current `cmd/gateway` build, config `tests/load/loadtest.yaml`
  (rate_limit + ip_guard → Redis in the hot path, both fail-open; discovery +
  forensic → PostgreSQL; WAF on; rate-limit cap set high so load is not throttled).
- **Backing services:** throwaway `redis:7-alpine` (password), `postgres:16-alpine`,
  echo upstream (`mendhak/http-https-echo`), each on its own alt port.
- **Drivers:** `pg_outage_loadgen.go` and `drain_loadgen.go` (this directory).

## 1. PostgreSQL outage under load

100 rps to the data plane for 90s; `docker stop` PostgreSQL at t=45s, `docker
start` at t=65s. A 1/s admin probe hits `GET /api/catalog` (served from PG).

| Phase | Requests | Success | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| PRE (0–45s, pg up) | 4498 | 100.0% | 7 ms | 10 ms | 11 ms | 24 ms |
| **OUTAGE (45–65s, pg DOWN)** | 2000 | **100.0%** | 7 ms | 10 ms | 11 ms | 15 ms |
| RECOV (65–90s, pg up) | 2500 | 100.0% | 7 ms | 10 ms | 11 ms | 19 ms |

**Reading**

1. **The data plane does not notice PostgreSQL dying.** Success stayed 100% and
   latency was *flat* (p99 11 ms) straight through the outage. Discovery/forensic
   writes are off the request path (async catalog worker + batched forensic sink
   with a Redis ring-buffer fallback), so a catalog DB outage cannot degrade
   proxied traffic. This is the decoupling the architecture promised, now shown
   under sustained load.
2. **Admin catalog read degrades and self-recovers.** `GET /api/catalog` returned
   errors for the full outage window and flipped back to `200` the second PG
   returned — no operator action.

**Finding (now fixed):** during the outage the admin catalog read returned
**HTTP 500** instead of **503**. 503 is the correct signal for "a required
dependency is down, retry later" (a load balancer / client backs off; 500 reads
as a bug). Fixed: `storeUnavailable` classifies connection-level errors and the
admin read handlers (catalog/consumers/posture/report/findings/effectiveness/
audit/spec/drift) now return **503** when the backing store is unreachable, 500
only for genuine query/logic errors. Regression: `internal/api`
`TestStoreUnavailable_Classifies`. Never affected the data plane.

## 2. Graceful drain (rolling-update) — before/after lame-duck

100 rps to the data plane; SIGTERM to the gateway at t=8s; keep driving to t=20s.
Each response classed ok / server_error (5xx) / conn_error (refused/reset).

### Before (immediate `Shutdown` on SIGTERM)

| Phase | n | ok | 5xx | conn_err |
|---|---|---|---|---|
| PRE (before SIGTERM) | 799 | 799 | **0** | 0 |
| DRAIN (after SIGTERM) | 1200 | 0 | **0** | **1200** |

Zero 5xx (the server never errors a request due to teardown) — but **every**
post-SIGTERM request was refused *immediately*: Go's `Shutdown` closes the
listener and idle keep-alives at once, and `/readyz` was still `200` up to that
instant. In a k8s rolling update the load balancer has not yet observed the pod
as unready, so it keeps routing — and those requests hit a closed listener.
**Every rollout sheds a burst of connection errors.**

### Fix — lame-duck grace (`shutdown_drain`)

On SIGTERM the gateway now (1) flips `/readyz` to `503`, (2) keeps serving
established connections for `shutdown_drain`, then (3) drains in-flight and stops.
`shutdown_drain: 6s` for this run (`5s` shipped in `gateway.yaml` /
`gateway.docker.yaml`).

| Phase | n | ok | 5xx | conn_err |
|---|---|---|---|---|
| PRE (before SIGTERM) | 798 | 798 | **0** | 0 |
| DRAIN (after SIGTERM) | 1200 | **601** | **0** | 599 |

`/readyz` timeline (SIGTERM at t=8s, grace 6s):

```
t=4..8s -> 200      (healthy)
t=9..14s -> 503     (draining — LB removes the instance from rotation)
t=15s+   -> conn err (grace elapsed; listener closed; process exited)
```

**Reading:** the 601 requests that succeeded during the grace window are exactly
the traffic a load balancer would still be sending before it notices `/readyz`
went unhealthy. With a readiness-gated LB (k8s Service/Ingress, ALB target group)
those now complete instead of erroring — **zero-downtime rollout**. Still zero
5xx. The grace must exceed the LB's readiness-probe period (default `5s` assumes
a probe period ≤ a few seconds).

Regression tests: `internal/api` `TestReadyz_DrainingWinsOverHealthyRedis` and
`TestServer_SetDrainingWiresToReadyz`.

## Still open

- **Published capacity numbers** (VU sweep, WAF on/off split, max-RPS) on
  dedicated hardware — Docker Desktop is not a valid capacity substrate.
- PG-outage while *also* under a catalog-write-heavy discovery load (this run had
  discovery on but the finding is unaffected — writes are async either way).

## Reproduce

```bash
# backing services (alt ports; own password), then build+launch the gateway:
AEGIS_REDIS_PASSWORD=… AEGIS_ADMIN_SECRET=… \
  AEGIS_FORENSIC_DSN='postgres://aegis:aegis@127.0.0.1:15432/aegis?sslmode=disable' \
  go run ./cmd/gateway --config tests/load/loadtest.yaml &

# PostgreSQL outage under load:
AEGIS_ADMIN_SECRET=… go run tests/load/pg_outage_loadgen.go \
  -pg <pg-container> -rate 100 -dur 90 -outage_start 45 -outage_end 65

# Graceful drain (writes the gateway pid to a file it can SIGTERM):
go run tests/load/drain_loadgen.go -pidfile /path/to/gateway.pid \
  -rate 100 -signal_at 8 -until 20
```
