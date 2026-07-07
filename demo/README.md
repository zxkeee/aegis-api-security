# AEGIS — IDOR / BOLA live demo

A 90-second, self-contained walkthrough that shows the one thing a signature WAF
cannot do: catch a **Broken Object Level Authorization (BOLA / IDOR)** leak — a
logged-in user reading another user's object — and then **prevent** it.

## Run it

```bash
./demo/idor-demo.sh        # interactive: press Enter between steps (for a live audience)
./demo/idor-demo.sh -y     # run straight through
```

Requires `docker` (a throwaway Redis), `go`, and `curl`. `jq` is used for pretty
output if present. Everything is built to a temp dir and torn down on exit; it
touches nothing in your environment except a short-lived Redis container.

## What the audience sees

The stand is a deliberately **vulnerable orders API** (order `1001` belongs to
`alice`) behind AEGIS. `alice` and `bob` are authenticated with real HS256 JWTs.

| Step | What happens | The point |
|---|---|---|
| ① Attack | `bob` requests `GET /api/orders/1001` (alice's) → backend returns **200** and the body `user_id: alice` | The app has an IDOR: it hands any order to any logged-in user. |
| ② Detect | AEGIS read the response and recorded a **confirmed, critical** `bola_object_ownership` finding | The owner is taken from the **response body** (`user_id`), compared to the verified caller (`bob`) — a confirmed leak, not a heuristic guess. This is what a WAF can't see. |
| ③ Prevent | `bob` retries → **403**, denied at the gateway before it reaches the app | Once AEGIS knows `alice` owns `1001`, every cross-owner attempt is blocked up front. |
| ④ No collateral | `alice` reads her own `1001` → **200** | The real owner is untouched. |

## How to present it (to security engineers)

1. **Lead with the gap, not the tool.** "A WAF matches payloads. This is a
   *valid* request from a *logged-in* user — no payload to match. That's BOLA,
   the #1 API risk, and it's what Salt/Noname sell."
2. Run interactively and narrate each step. The money moment is ②: *"AEGIS read
   the response, saw it belonged to alice, and the caller was bob — confirmed
   leak."*
3. Invite them to poke: change the config (`demo/gateway.demo-idor.yaml`), flip
   `object_ownership_block` off to show detect-only, or point `owner_fields` at a
   different field.
4. Be honest about the edge (they'll ask): the owner field value must be
   comparable to the JWT subject; different id-spaces need a claim mapping (next
   on the roadmap). Say it before they find it.

## How it works

- Config: `security.abuse.object_ownership` + `owner_fields: ["user_id"]` +
  `object_ownership_block` in `gateway.demo-idor.yaml`.
- Detection + blocking live in `internal/middleware/abuse.go`
  (`AbuseDetection`); the owner binding is stored in Redis
  (`store.SetObjectOwner` / `GetObjectOwner`).
- The gateway derives the verified caller identity from the JWT (`sub`), so the
  comparison is against a real authenticated subject, not a spoofable header.

The backend (`demo/orders-backend`) and token minter (`demo/mint-jwt`) are demo
helpers only — never ship them.
