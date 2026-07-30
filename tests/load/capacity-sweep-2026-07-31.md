# AEGIS capacity sweep (VU 10/50/100/200) — WAF on vs off — 2026-07-31

Closes the last open item under Pillar 3 ("Load and latency benchmarks") in
`RELEASE-CHECKLIST.md`: a VU sweep and a WAF on/off split, on dedicated
hardware (the NUC, not Docker Desktop).

## Environment

Same setup as `tests/load/results-2026-06-21.md` and
`tests/load/observe-mode-results-2026-07-31.md`: gateway built from current
`main`, `aegis-demo-backend` (httpbin) over the `aegis-demo-net` bridge, a
fresh isolated Redis, LAN gigabit NUC host, k6 client over Wi-Fi from macOS.
Two configs identical except `security.waf.enabled` / `block_mode` and ports;
`rate_limit.requests` lifted to 10,000,000 so it's out of the picture; DLP,
bot, behavior, ip_guard, abuse all disabled in both (isolating WAF cost
specifically, not the whole chain — see `observe-mode-results-2026-07-31.md`
for the whole-chain enforce-vs-observe comparison).

## Results

| Config | VUs | Throughput | p50 | p95 | Errors |
|---|---:|---:|---:|---:|---:|
| WAF on | 10 | 399.6 req/s | 17.55 ms | 32.98 ms | 0.00 % |
| WAF on | 50 | 436.0 req/s | 85.93 ms | 163.85 ms | 0.00 % |
| WAF on | 100 | 429.9 req/s | 175.86 ms | 341.19 ms | 0.00 % |
| WAF on | 200 | 431.5 req/s | 361.89 ms | 702.05 ms | 0.00 % |
| WAF off | 10 | 429.0 req/s | 15.74 ms | 31.61 ms | 0.00 % |
| WAF off | 50 | 451.5 req/s | 80.89 ms | 156.78 ms | 0.00 % |
| WAF off | 100 | 451.2 req/s | 166.96 ms | 318.05 ms | 0.00 % |
| WAF off | 200 | 4413.9 req/s | 18.70 ms | 62.09 ms | **96.36 %** |

## Reading

**This sweep did not find AEGIS's own throughput ceiling — it found the
shared demo backend's.** From 10 to 100 VUs, throughput is flat at ~400–450
req/s regardless of VU count while p50/p95 scale up roughly linearly with VUs
— the textbook signature of a fixed-capacity server (here, the single
`kennethreitz/httpbin` container `aegis-demo-backend`, not built for this) with
requests queueing behind it, not of AEGIS adding per-request cost that grows
with concurrency.

**WAF cost is small and consistent at moderate load**: 400→436 req/s (WAF on)
vs 429→452 req/s (WAF off) at 10–100 VUs — roughly a 5–7% throughput cost and
a few ms of added latency for Coraza's rule evaluation. Consistent with the
"WAF blocks are cheap" finding in `results-2026-06-21.md`.

**The 200-VU WAF-off row is not a real throughput number — it's a saturation
failure.** `docker logs` for that run show the proxy's circuit breaker
repeatedly opening against `aegis-demo-backend` (`"circuit_breaker: open,
trying next upstream"`) because the single-threaded-ish demo backend couldn't
keep up once WAF-off let requests reach it faster; with only one upstream
configured there is nowhere to fail over to, so those attempts surface as
errors instead of degrading gracefully. The reported "4413.9 req/s" is mostly
k6 counting failed/short-circuited requests, not successful ones (96.36%
`http_req_failed`). WAF-on's extra per-request latency at the same VU count
incidentally throttled the effective request rate reaching the backend enough
to avoid tripping the same collapse (0% errors) — a side effect of the WAF's
cost, not a designed backpressure mechanism; do not read this as "the WAF
protects the backend from overload" without a dedicated test for that claim.

## What this does and doesn't tell you

- **Does**: WAF overhead at realistic concurrency (10–100 VUs, where this demo
  backend holds up) is small and doesn't grow disproportionately with load.
- **Does**: confirms the proxy's circuit breaker does engage under backend
  saturation (working as designed) rather than queueing forever.
- **Doesn't**: give AEGIS's own max-RPS ceiling — that number is currently the
  demo backend's ceiling, not the gateway's. A real capacity number needs a
  backend that can absorb far more load than AEGIS itself can push (e.g. a
  Go `net/http` no-op handler, not a single Python/Flask-style httpbin
  container), so the gateway's own per-request cost becomes the bottleneck
  being measured instead of the backend's.

## Next iteration

- Swap `aegis-demo-backend` for a purpose-built high-throughput no-op backend
  (a trivial Go handler) to actually find AEGIS's own ceiling, not the demo
  backend's.
- Add a second upstream (or lower `retry_attempts` deliberately) to see
  graceful-degradation behavior under backend saturation instead of the
  circuit breaker's fail path with nowhere to go.
- A raw-backend-only k6 run (bypassing AEGIS entirely) would separate "backend
  ceiling" from "AEGIS overhead" cleanly — still on the existing TODO list in
  `tests/load/README.md`/`results-2026-06-21.md`.
