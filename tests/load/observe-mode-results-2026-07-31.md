# AEGIS load benchmark — observe/pilot mode overhead — 2026-07-31

Answers the first question a pilot partner asks about an inline security
product: does the "record everything, block nothing" pilot posture
(`observe: true`, merged in #20) cost anything over normal enforcement? Compares
enforce mode (`block_mode: true`, the 2026-06-21 baseline config) against
observe mode with an **identical security config otherwise** — same controls
enabled (WAF, DLP, bot, behavior, ip_guard, abuse/object-ownership), same
backend, same Redis, same host — differing only in the top-level `observe: true`
flag and the ports.

## Environment

| | |
|---|---|
| Date | 2026-07-31 |
| Gateway binary | built from `main` @ `c7883ca` (merge of #20, observe mode) |
| Backend | `aegis-demo-backend` (httpbin), `aegis-demo-net` bridge |
| Redis | dedicated `aegis-bench-redis` (fresh container, own password, not the shared demo one) |
| Host | Debian NUC, LAN gigabit; client runs on macOS over Wi-Fi (same setup as 2026-06-21) |
| Load tool | k6 v2.0.0 |
| Load shape | 20 VUs, 15s steady state, `tests/load/gateway_load.js` against `/get`; `rate_limit.requests: 1000000` so the limiter is out of the picture |

`forensic_dsn` is unset in both configs (catalog disabled) so the comparison
isolates the per-request middleware chain cost, not PostgreSQL write latency —
the discovery/findings write path is already async and off the request's
critical path (see `tests/load/reliability-results-2026-07-08.md`).

## Results (2 runs each, 20 VUs / 15s)

| | Enforce (`block_mode: true`) | Observe (`observe: true`) |
|---|---|---|
| Throughput | 349.0 / 338.0 req/s | 381.7 / 378.6 req/s |
| p50 | 36.98 / 38.23 ms | 31.47 / 32.32 ms |
| p95 | 107.38 / 108.55 ms | 104.66 / 102.96 ms |
| Errors | 0.00 % | 0.00 % |

## Reading

**Observe mode is not slower than enforce mode — if anything, marginally
faster, within run-to-run noise.** Both configs run the full middleware chain
and the full Coraza rule evaluation (observe only switches the WAF's engine
mode to `DetectionOnly`, which still parses and matches every rule — it skips
the `deny` interrupt path, not the inspection). The ~30–38 ms p50 in both runs
matches the 2026-06-21 baseline (33.46 ms) — consistent with Wi-Fi RTT to the
NUC dominating the number, not AEGIS's added cost. **A pilot partner asking
"what does observe mode cost me" gets a clean answer: nothing measurable beyond
what enforcement already costs.**

This also serves as a regression check on the #20 merge: no throughput/latency
regression from the observe-mode middleware changes (DLP body pass-through,
JWT soft-auth branch, WAF directive rewrite) at this VU count.

## Caveats

- Same Wi-Fi-to-LAN noise floor as prior runs — absolute p95 should be read
  loosely; the enforce-vs-observe *delta* is the meaningful number here, same
  caveat as the 2026-06-21 multi-tenant comparison.
- No auth/BOLA-triggering traffic in this run (plain `GET /get`, no JWTs) — the
  abuse/object-ownership code path is enabled but not exercised, so this
  measures the always-on middleware cost, not the BOLA-detection cost
  specifically.
- Single VU-count sample (20). The existing "next bench iterations" TODO (VU
  sweep 10/50/100/200, raw-backend baseline bypassing the gateway) still
  applies and would sharpen the absolute numbers; not done here since the
  question this run answers (observe vs enforce delta) doesn't need it.

## Reproducing

```bash
# Fresh, isolated Redis (do not reuse the shared aegis-demo-redis's secret)
docker run -d --name aegis-bench-redis --network aegis-demo-net redis:7-alpine \
  redis-server --requirepass "$BENCH_REDIS_PW" --save '' --appendonly no

# Enforce and observe configs are identical except `observe: true` + ports —
# see the two configs' security: block for the exact shape used here (WAF,
# DLP, bot, behavior, ip_guard, abuse/object_ownership all enabled).
docker run -d --name aegis-bench-enforce --network aegis-demo-net \
  -e AEGIS_ADMIN_SECRET=... -e AEGIS_REDIS_PASSWORD="$BENCH_REDIS_PW" \
  -p 192.168.31.116:8090:8090 -p 192.168.31.116:8091:8091 \
  -v /path/to/bench-enforce.yaml:/app/config.yaml:ro \
  -v /path/to/gateway-linux-amd64:/app/gateway:ro \
  -w /app debian:bookworm-slim /app/gateway --config /app/config.yaml

docker run -d --name aegis-bench-observe --network aegis-demo-net \
  -e AEGIS_ADMIN_SECRET=... -e AEGIS_REDIS_PASSWORD="$BENCH_REDIS_PW" \
  -p 192.168.31.116:8092:8092 -p 192.168.31.116:8093:8093 \
  -v /path/to/bench-observe.yaml:/app/config.yaml:ro \
  -v /path/to/gateway-linux-amd64:/app/gateway:ro \
  -w /app debian:bookworm-slim /app/gateway --config /app/config.yaml

k6 run -e TARGET=http://192.168.31.116:8090 -e PATH=/get -e VUS=20 -e DURATION=15s tests/load/gateway_load.js
k6 run -e TARGET=http://192.168.31.116:8092 -e PATH=/get -e VUS=20 -e DURATION=15s tests/load/gateway_load.js
```
