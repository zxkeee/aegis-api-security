# AEGIS — Release Readiness Checklist (v1.0 Gate)

This document defines the gate that must be cleared before AEGIS is released as a
commercial product. The goal is a release that is (1) free of known security
holes, (2) competitive in the API-security market, and (3) demonstrably reliable.

Do not ship v1.0 until every **P0** item is checked. **P1** items are required to
be competitive; **P2** items are post-launch improvements.

Legend: `[ ]` open · `[x]` done · `[~]` partially done

---

## Pillar 1 — No security holes

### Already addressed
- [x] Constant-time challenge-token compare in `store.IsValidChallengeToken`
      (was `stored == token` — replaced with `subtle.ConstantTimeCompare`).
- [x] Backend identity propagation works in JWKS mode: separate
      `auth.propagation_secret` (env `AEGIS_PROPAGATION_SECRET`) signs the
      `X-Gateway-Signature` header even when JWT verification is JWKS-based;
      startup-warning fires when JWKS is on without a propagation secret so the
      operator knows the gatewayverify SDK will reject every request.
- [x] `gosec_results.json` removed from repo + `.gitignore` (build artifact).
- [x] Stored XSS in the admin console (output escaping across all tables;
      data-attribute event delegation instead of inline JS)
- [x] CSV/formula injection in the report export (`csvSafe`)
- [x] JWT algorithm-confusion and fail-closed when JWKS is unavailable
- [x] Rate-limiter window-reset defect; opt-in `fail_closed`
- [x] DLP streaming / WebSocket safety (Flusher/Hijacker, bounded buffer)
- [x] Proxy retry only for idempotent requests; buffered attempt
- [x] Signed identity propagation with timestamp + nonce
- [x] `gosec` and `golangci-lint` run in CI on every commit
- [x] Hot-reload runs the full startup safety gate: `config.Validate` +
      `InitTrustedProxies` now apply on every reload (previously an unsafe edit
      went live unvalidated, and `trusted_proxies` changes were silently
      ignored — breaking every per-IP control). Trusted-proxy set is swapped
      atomically (race-free with in-flight requests).
- [x] Proxy no longer wraps upstreams in `http.TimeoutHandler` (which buffered
      whole responses in memory — an OOM vector — and broke SSE/WebSocket).
      The per-route timeout is now a response-header bound on the transport;
      SSE flushes and WebSocket upgrades pass through end-to-end (covered by
      `TestProxy_SSEStreamsThroughRetryPath` / `TestProxy_WebSocketUpgradePassesThrough`).
- [x] JWKS initial fetch retries forever with capped backoff (a transient IdP
      outage at boot used to leave the gateway permanently fail-closed after
      5 attempts, 401-ing all traffic until restart).
- [x] Challenge no longer embeds the expected token in the page: the server
      stores an FNV-1a transform of the embedded seed, so scraping the HTML and
      echoing the seed back does not pass (documented honestly as a
      trivial-bot filter, not bot-proof).
- [x] Unknown `load_balance` strategies and malformed route timeouts are
      rejected by `config.Validate` instead of silently degrading to defaults.
- [x] Optional `admin_cors` block: the admin plane no longer has to share the
      data-plane CORS origin list; wildcard rejected when `admin_auth` is on.
- [x] Client-supplied `X-Request-ID` is sanitised (charset + 64-char cap)
      before being logged/echoed/forwarded; deprecated `X-XSS-Protection`
      header dropped (CSP is the control).
- [x] **No false-positive auto-bans on normal traffic.** The behavioural error
      signal now counts only genuinely abusive statuses (`400`/`429`), not the
      normal `401`/`403`/`404` or backend `5xx`, so an active client behind a
      shared IP/NAT is not banned for hitting missing/protected endpoints. The
      WAF no longer mis-attributes an upstream `403`/`400`/`405` as its own block
      (a "reached backend" sentinel distinguishes a Coraza interruption from a
      passed-through downstream status), so those responses no longer inflate
      `waf_blocked` or add a behaviour penalty.
- [x] **Catalog cardinality cap.** The PostgreSQL catalog bounds the total number
      of distinct endpoints (mirroring the Redis inventory cap), so a path-flood
      through a catch-all route cannot grow `api_endpoints` without limit.
- [x] **Threat-feed redirect safety.** Feed fetches follow only HTTPS redirects to
      non-private hosts, closing a blind-SSRF path (redirect to `http://` or an
      internal address such as cloud metadata).

### P0 — release blockers
- [x] **Real console authentication.** Static bearer in `sessionStorage` replaced
      with server-side sessions in Redis: HttpOnly session cookie (unreadable by
      JS/XSS) + CSRF double-submit token on mutations, with TTL. Bearer kept for
      API/CLI. `admin`/`viewer` roles enforced. **OIDC single sign-on** now
      implemented (`internal/sso`): Authorization Code flow with PKCE against the
      provider discovery document, ID-token verification (signature via the
      provider JWKS, issuer/audience/expiry, nonce), claim→tenant/role mapping,
      and just-in-time user provisioning. `GET /api/auth/oidc/login` +
      `/callback`; validated end-to-end against a local IdP with real RS256
      crypto (`internal/sso` integration tests) and a live-PG callback test.
      (SAML + SCIM + MFA remain P1 — most enterprises front OIDC with their own
      MFA, so this unblocks the majority of SSO deals.)
- [x] **Dependency CVE scanning.** `govulncheck` runs in CI; x/net bumped and
      toolchain pinned (go1.26.4) so the module and stdlib are CVE-clean.
- [~] **Independent security testing.** Automated dynamic scan in place
      (`.github/workflows/security-scan.yml`): boots a self-contained instance and
      runs `tests/pentest.sh` (WAF efficacy + admin-auth) plus **nuclei** against
      the admin plane (high/critical gate, allowlist in `tests/dynamic/`).
      Validated end-to-end on a Linux Docker host: pentest 18/18, nuclei admin
      plane 0 high/critical. This scan also surfaced and fixed a real WAF gap
      (JSON request bodies were not inspected — see `waf.go` JSON body processor).
      Note: nuclei against the data plane false-positives on the reflecting test
      backend, so the gate scans the admin plane and pentest.sh covers the WAF.
      Still open (external, cannot be self-certified): an **independent manual
      pentest** by a third party.
- [x] **TLS mandatory in production.** `require_tls` makes startup fail without
      gateway TLS; the gateway now actually terminates TLS
      (`ListenAndServeTLS`) when `tls.enabled`, not just plaintext; a loud
      startup warning fires when TLS is off; documented that production must
      terminate TLS at the gateway or a trusted upstream.
- [x] **Backend signature verification reference.** `sdk/gatewayverify` Go
      package + README verifies `X-Gateway-Signature`, timestamp freshness and
      nonce uniqueness (HMAC over `sub:roles:scopes:ts:nonce`), with an
      `http.Handler` wrapper, a pluggable `NonceStore`, and a non-Go recipe.
- [x] **Secret rotation procedure** documented (`docs/runbooks/secret-rotation.md`)
      with rolling/dual-accept steps and verification for admin, JWT, Redis and
      forensic-DSN secrets.

### P1 — strongly recommended before launch
- [x] Real TLS JA3/JA4 fingerprinting. Spoofable `X-JA3-Fingerprint` header is
      now stripped; a real fingerprint is computed from the TLS ClientHello at
      the gateway (`internal/tlsfp`, JA3-style over stdlib-exposed fields, GREASE
      filtered). Canonical JA3 extension-list parsing remains a future refinement.
- [~] Extend `fail_closed` semantics to IP guard and behavioural scoring.
      IP-guard `fail_closed` done (denies on Redis outage); behavioural scoring
      intentionally stays fail-open (a scoring gap is safer than blocking all
      traffic) — documented in `store`.
- [x] Security headers / CSP tightened: nonce-based `script-src`/`style-src`,
      no more `unsafe-inline`; nonce rotates per response; added `base-uri`,
      `form-action`, kept `frame-ancestors 'none'`. Validated live on stand.
- [x] Per-IP brute-force rate limit on `/api/login`: 8 failures / 5 min →
      `429 Retry-After`. Counter only consumes budget on failure (successful
      operators never throttle). Validated live: 8× 401 → 9th request 429.

---

## Pillar 2 — Competitive

### Differentiators already in place
- [x] Passive API discovery with path normalization
- [x] Posture classification (protected / partial / unprotected / shadow)
- [x] Risk scoring
- [x] Consumer graph (who calls what)
- [x] Coverage, effectiveness and reporting (JSON/CSV)

### P1 — table stakes / flagship
- [x] **OWASP API Top-10 detection**, starting with **BOLA/BFLA** built on the
      existing consumer graph. This is the primary reason customers buy API
      security; without it the product reads as "another WAF". Implemented in
      `middleware.AbuseDetection` (wired after JWT so it sees verified roles):
      **BFLA** flags a consumer hitting a privileged path prefix without any
      required role; **BOLA/IDOR** is caught two ways: (1) **enumeration** via
      per-consumer/endpoint distinct-ID counts (`store.TrackObjectAccess`) against
      both a hard `enum_threshold` ceiling and an adaptive per-consumer EWMA
      baseline (`store.TrackBaseline`, A2); (2) **single-object IDOR**
      (`object_ownership`) — learns which consumers own which objects
      (`store.TrackObjectOwner`) and flags a consumer that **successfully (2xx)**
      reads an object owned by a different, small set of consumers and never
      accessed by it. Evaluated after the response so a backend 4xx (authorization
      enforced) is correctly NOT flagged — the one-object leak that enumeration and
      signature WAFs miss. **Confirmed ownership**: with `owner_fields` set, the
      object's true owner is read from the response body and compared to the
      authenticated subject (heuristic warning → confirmed critical), and that
      binding (`store.SetObjectOwner`/`GetObjectOwner`) lets `object_ownership_block`
      **deny a known cross-owner access before forwarding** — preventing the leak,
      not just recording it; `ownership_bypass_roles` exempt support/admin. With an
      allowlist for known high-cardinality callers and explainable `why` on every event.
- [~] **SIEM integration** (Splunk / Elastic) and **alerting** (Slack / PagerDuty)
      with configurable webhooks. Done: `alerting` config block (webhook URL,
      `generic`/`slack` payload format, `min_severity` gate); `AEGIS_ALERT_WEBHOOK_URL`
      env override. Remaining: per-rule routing, ticketing (Jira/ServiceNow).
- [x] **Native Prometheus exposition** of the AEGIS counters (`GET /metrics`,
      text format 0.0.4, behind the admin bearer; scrape config in `prometheus.yml`).
- [x] **OpenAPI / spec drift**: import an OpenAPI 3.x / Swagger 2.0 spec (config
      `discovery.spec_path` fallback or per-tenant `PUT /api/discovery/spec`) and
      compare documented vs observed. `GET /api/discovery/drift` reports
      **undocumented** endpoints (observed, not in spec — OWASP API9) and
      **zombie** operations (documented, never observed); undocumented endpoints
      also surface as `undocumented_endpoint`/`undocumented_method` findings on
      the catalog. Spec paths are canonicalised to the catalog's `{id}` template
      so documented and observed surfaces compare exactly. Parser is dependency
      -free (yaml.v3, which also reads JSON). Per-tenant spec stored in PG with
      RLS; validated on the home-server containers.
- [~] **Schema enforcement (positive security)**: beyond reporting drift, actively
      validate requests against the documented contract (`security.schema`,
      `middleware.SchemaValidation`). The parser captures each operation's request
      schema (params + JSON body, `$ref`-resolved); the validator flags missing/
      mistyped/out-of-enum query params and JSON body fields, and — the
      anti mass-assignment lever — rejects undocumented body fields when the schema
      sets `additionalProperties:false` (OWASP API6). Monitor mode records, block
      mode returns a machine-readable 422. Contract source in v1 is the config-level
      spec (`discovery.spec_path`); remaining: enforce per-tenant uploaded specs,
      path/header params, formats/bounds.

### P2
- [~] **Admin audit log** (enterprise/compliance table-stake). Done: `internal/audit`
      persists every control-plane action (login/login_failed/logout/mutation/
      `denied:<reason>`) to PostgreSQL via an async best-effort writer that never
      blocks the admin request path; entries carry actor/role/super-admin/tenant/
      method/path/status/ip. `AdminAuth` records; `GET /api/audit` reads,
      tenant-scoped (super-admin spans all with `?all=true`). Remaining:
      retention/rollup, data-residency, export, and an RLS policy on
      `admin_audit_log` (today it is application-scoped only).
- [x] **Multi-tenancy** (organisations, per-tenant data isolation). Closed
      end-to-end across all 6 phases of ADR-001 (`docs/design/multitenancy.md`):
      `TenantResolve` ingress (route+host, strips `X-Tenant-*`); PostgreSQL
      isolation (`tenant_id` + composite PKs on all catalog/forensic tables,
      `WHERE tenant_id` everywhere, RLS `FORCE`+policy via `set_config` GUC as a
      fail-closed backstop); Redis isolation (`tkey(ctx)` → `gw:t:<tenant>:*` on
      every key family); console sessions pinned to a tenant + RBAC (admin/viewer)
      in `internal/iam`; tenant + user CRUD (`/api/tenants`, `/api/users`) with
      super-admin scoping; cross-tenant deny tests against live PG/Redis, plus a
      multi-tenant k6 load run (overhead in the noise) and `docs/runbooks/ha.md`.
- [~] Anomaly detection / behavioural baselines per consumer. Done: per-consumer
      EWMA baseline for BOLA enumeration (`store.TrackBaseline`, A2). Remaining:
      volume/time/geo/error-rate profiles, sequence anomaly, peer-group.
- [~] **Data retention.** Background sweep (`internal/retention`) deletes rows
      older than a configured per-table window from the tables that grow
      unbounded with traffic — `forensic_logs`, `admin_audit_log`, and the
      consumer graph (`api_consumers` / `api_endpoint_consumers` + orphan
      cleanup). The endpoint catalog is left intact (bounded by normalisation).
      One maintenance transaction spans all tenants via the RLS `app.tenant_id='*'`
      escape hatch. Config: `retention` (interval + `forensic_days` / `audit_days`
      / `consumer_idle_days`; 0 keeps a table forever). Remaining: rollup of aged
      rows into summaries, backups/PITR (ops), batching for very large deletes.
- [ ] Out-of-band deployment (traffic mirroring) in addition to inline.
- [ ] Compliance report templates (PCI-DSS, HIPAA, GDPR).
- [ ] Licensing / metering.

---

## Pillar 3 — Works excellently

### P0 — release blockers
- [x] **Test coverage.** Regression tests for every recent security fix
      (JA3 spoof, IP-guard/rate-limit fail-closed, identity signature/replay).
      A CI coverage gate (`scripts/coverage-gate.sh`, wired into `test.yml`)
      enforces per-package floors that ratchet toward the >= 70% target — now met
      on **every critical package**. Current (against the live Redis+PostgreSQL
      stand): tenant/tlsfp 100%, classify 93%, gatewayverify 93%, proxy 92%,
      config 90%, gateway 87%, sso 88%, store 85%, discovery 84%, iam 82%,
      middleware 82%, retention 81%, audit 80%, **api 76%** (the catalog/posture
      handlers are now exercised through a seeded live catalog, plus requireAuth
      and the store error paths). The `api` floor was ratcheted 60→70.
- [~] **Load and latency benchmarks.** k6 scripts + guide under `tests/load/`
      (single-tenant + multi-tenant + attack-mix scenarios, CI-able
      thresholds). First on-hardware run in `tests/load/results-2026-06-21.md`:
      single-tenant 373.6 RPS / p50 33.5 ms, multi-tenant 375.7 RPS / p50
      34 ms (MT overhead in the noise), attack-mix p50 7.9 ms (WAF rejects
      early). Still to do: wired-LAN run, VU sweep, WAF on/off split for
      published capacity numbers.
- [~] **Graceful failure under load.** Redis-outage behaviour verified two ways:
      (1) end-to-end unit matrix in `internal/middleware/degradation_test.go`
      (fail_closed → 503, default → 200, static blacklist still enforced, no
      panics) against a killed Redis; (2) **on-hardware sustained-traffic run**
      with Redis killed mid-test (`tests/load/redis-outage-results-2026-06-26.md`):
      at 50 rps, during a full Redis outage the gateway kept **100% success**
      (fail-open) with **p99 864 ms / max 1.30 s** — bounded by the fail-fast
      Redis timeouts (dial 1s / read-write 500ms / 1 retry), vs the 3–9 s hangs
      the go-redis defaults would cause; latency snapped back to p99 42 ms on
      recovery. **PostgreSQL-outage under load** now covered on a live stand
      (`tests/load/reliability-results-2026-07-08.md`): at 100 rps with PG killed
      mid-run the data plane held **100% success with flat latency** (p99 11 ms
      through the outage) — the async catalog/forensic path is decoupled from
      proxied traffic; the admin catalog read degrades and self-recovers. **Rolling
      -update drain** covered in the same run: **zero 5xx** during `Shutdown`, and
      a new lame-duck grace (`shutdown_drain`: `/readyz` → 503 → serve → drain →
      stop) turns a post-SIGTERM burst of connection errors into zero-downtime
      rollouts behind a readiness-gated LB (601/1200 drain-window requests now
      succeed vs 0 before). Regression: `internal/api` readyz-draining tests.
      Admin read handlers now return **503** (not 500) when the backing store is
      unreachable, so clients/LBs back off correctly (`storeUnavailable`
      classifier, `TestStoreUnavailable_Classifies`). Still to do: capacity sweep
      for published max-RPS (needs dedicated hardware, not Docker Desktop).

### P1
- [x] High-availability guide (`docs/runbooks/ha.md`): topology (Sentinel + PG
      streaming replication), per-failure-mode matrix (fail-open vs
      fail-closed per control), RLS rolling-deploy notes, bring-up checklist.
      Sentinel client implemented: `redis.UniversalOptions{MasterName, Addrs}`
      via `store.NewWithConfig` + `config.RedisConfig.Sentinel`; AEGIS code
      is mode-agnostic (the client handles failover).
- [~] Capacity-planning guidance with **rule-of-thumb** sizing (in `ha.md`);
      concrete numbers pending the benchmark run on reference hardware.
- [x] End-to-end smoke test in CI (start gateway + Redis + PG, drive traffic,
      assert catalog and posture populate). `.github/workflows/e2e-smoke.yml`
      boots the gateway against real Redis + PostgreSQL + an echo upstream, drives
      traffic, and asserts the discovery catalog (`/api/catalog`) and posture
      summary (`/api/posture/summary`) populate with normalised `{id}` templates.
      Validated end-to-end on a Linux Docker host.

---

## Suggested sequence

1. **Tests (P3-P0)** — establish reliability and lock in the security fixes with
   regression tests. *In progress.*
2. **Console authentication (P1-P0)** — close the last release-blocking hole.
3. **BOLA/BFLA detection (P2-P1)** — the competitive flagship.
4. **SIEM/alerting + Prometheus (P2-P1)** — fit into customer stacks.
5. **Benchmarks + HA hardening (P3-P0/P1)** — prove "works excellently".

Realistic effort: roughly 2–4 focused iterations. The foundation is solid; this
checklist is the disciplined path from a strong implementation to a shippable
product.
