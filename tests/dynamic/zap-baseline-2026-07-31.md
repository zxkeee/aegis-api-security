# OWASP ZAP baseline scan — admin plane — 2026-07-31

Supplements the nuclei admin-plane scan already gated in CI
(`.github/workflows/security-scan.yml`) with a second, differently-sourced
automated scanner. Not a substitute for the external independent pentest that
`RELEASE-CHECKLIST.md` still lists as open — no budget for that right now — but
a free, self-run way to widen coverage in the meantime beyond a single tool's
template set.

## Setup

Built the gateway from current `main` (post `#20`, observe mode merged), ran it
with the same config CI uses for the nuclei scan (`tests/dynamic/gateway.ci.yaml`,
admin plane authenticated, data plane WAF on, no external state — Redis only,
`forensic_dsn` unset). Fresh, isolated Redis + echo backend on the NUC, torn
down after the run.

```bash
docker run --rm --network aegis-zap-net -v "$PWD/zap-out:/zap/wrk:rw" \
  zaproxy/zap-stable zap-baseline.py \
  -t http://aegis-zap-gw:28091 \
  -r zap-report.html -J zap-report.json -w zap-report.md -m 5 -T 10
```

`zap-baseline.py` runs ZAP's passive scan (spider + passive rules; no active
attack payloads) against the admin plane — the same surface nuclei targets, for
the same reason: the data plane proxies to a disposable/reflecting backend that
makes exposure-style findings false-positive there, and the data plane's WAF is
already exercised deterministically by `tests/pentest.sh`.

## Result

**`FAIL-NEW: 0` · `WARN-NEW: 4` · `PASS: 63`** — no high/critical findings.

All 4 warnings are pre-existing, deliberate, and already documented in code —
not new gaps this scan surfaced:

| Warning | Verdict |
|---|---|
| Non-Storable Content [10049] | Expected — admin API/console responses are correctly marked `no-store` |
| CSP: `style-src unsafe-inline` [10055] | Deliberate tradeoff, documented in `internal/api/dashboard.go` (script-src is strict nonce-based CSP; style-src is relaxed for the animation layer) and enforced by `dashboard_test.go` (fails if `script-src` ever allows unsafe-inline/eval) |
| Modern Web Application [10109] | Informational only (ZAP noting the app is a JS SPA) |
| Cross-Origin-Embedder-Policy Header Missing [90004] | Deliberately omitted per the comment in `internal/middleware/helpers.go` (COEP can break legitimate cross-origin subresource loads; COOP + CORP already cover the same-origin isolation this console needs) |

## Reading

A second, independently-sourced automated scanner corroborates the nuclei
result: no new exposure. This raises confidence incrementally but does **not**
close the "independent manual pentest" line in `RELEASE-CHECKLIST.md` — an
automated baseline scan (passive rules, no active attack payloads) is a much
lower bar than a human tester probing business logic, auth flows, and
multi-step attack chains. Treat this as cheap interim coverage, not a
replacement.

## Reproducing / next steps

- Re-run after any admin-plane change of note (auth, session, CSRF, console).
- Consider `zap-full-scan.py` (active scan) instead of baseline once there's a
  disposable, non-shared target to point it at — active payloads are noisier
  and shouldn't run against anything else on the same host/network.
- Wiring this into CI (like nuclei) is a reasonable follow-up but adds another
  Docker image + runtime to the pipeline — a call for whoever owns CI budget,
  not made here.
