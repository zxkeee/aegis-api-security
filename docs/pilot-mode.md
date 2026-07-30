# Observe / Pilot mode

`observe: true` puts AEGIS into a **guaranteed non-disruptive** posture for a
first pilot on a partner's live traffic. Every control still inspects and
records — but nothing is blocked, no response body is modified, and no control
fails closed. It is the deployment that lets you produce a findings report with
**zero risk to the partner's production**.

```yaml
observe: true            # top-level; overrides the security controls below
security:
  waf:   { enabled: true }        # detects attacks (DetectionOnly), never blocks
  dlp:   { enabled: true }        # classifies PII, never redacts the body
  auth:  { enabled: true, secret: ... }   # extracts identity, never returns 401
  abuse: { enabled: true, object_ownership: true }  # flags BOLA/BFLA, never blocks
```

## What observe mode guarantees

Coercion is applied by `GatewayConfig.ApplyObserveMode()` after config validation,
on **startup and every hot-reload**, so it cannot be bypassed by a per-route
override or a later edit:

| Control | Enforce mode | Observe mode |
|---------|--------------|--------------|
| WAF | blocks (403) | **DetectionOnly** — matches + logs, forwards the request |
| DLP | redacts PII in the response | **classifies + flags the endpoint, body passes through unmodified** |
| JWT auth | 401 on missing/invalid token | **extracts identity from a valid token, otherwise passes through** |
| Abuse (BOLA/BFLA) | can block / proactively deny | **detect-only** |
| Schema | rejects (422) | monitor |
| Rate limit, IP guard, threat feed, bot, challenge, behavior | block / throttle / ban | **disabled** (no discovery value, only risk) |
| `fail_closed` (rate-limit, IP-guard, JWT revocation) | may deny on Redis outage | **forced off — never fail closed** |
| per-route `rate_limit` override | throttles | **cleared** |

What still runs and produces the pilot's value: **passive discovery** (catalog,
posture, shadow-API detection), **DLP classification** (which endpoints leak
which PII classes), **BOLA/BFLA detection** (identity-attributed when a valid
token is present), **WAF detection**, and **schema drift**.

A loud `OBSERVE MODE ACTIVE` warning is logged at startup and on every reload.

## Why "observe" and not the customer's own auth off?

JWT auth in observe mode is *soft*: a valid token is still parsed, its identity
propagated and signed, so BOLA/BFLA attribution and consumer analytics work — but
a missing, expired, malformed or revoked token is passed **through** rather than
rejected. AEGIS must never block traffic the customer's own backend would have
accepted; the backend remains the source of truth for enforcement during a pilot.

## Deploying a pilot

1. Copy `config/gateway.pilot.yaml` and fill in its two `TODO`s: the partner's
   real backend(s) under `routes`, and `trusted_proxies` if there's an LB/CDN in
   front of AEGIS. It already ships with `observe: true` and every detection
   control enabled — nothing to hand-tune before going live.
2. Run it via `docker-compose.yml` (`command: ["--config", "config/gateway.pilot.yaml"]`)
   with `AEGIS_ADMIN_SECRET`, `AEGIS_REDIS_PASSWORD` set — the bundled Redis and
   PostgreSQL cover the catalog/findings/consumer graph out of the box.
3. Let it run for a week.
4. Read the findings: `GET /api/findings` (critical-first; add `?format=csv` for
   a downloadable report you can hand to the partner without console access),
   the catalog (`GET /api/catalog`, also `?format=csv`), posture
   (`GET /api/posture/summary`), and compliance mapping (`GET /api/compliance`).

> Note: observe mode is still **inline** — AEGIS sits in the request path, so it
> adds the (sub-millisecond, fail-fast) proxy hop even though it blocks nothing.
> True out-of-band ingestion (traffic mirroring / eBPF, ROADMAP B1) removes the
> path entirely and is the next step for partners who cannot add any inline hop.
