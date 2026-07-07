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

The stand is a deliberately **vulnerable orders API** (order `1001` is owned by
user id `7` = alice) behind AEGIS. `alice` and `bob` hold real HS256 JWTs whose
subject is an **email** and whose owner id is a numeric **`uid`** claim (7 and 9)
— the realistic case where the resource owner is not the subject.

| Step | What happens | The point |
|---|---|---|
| ① Attack | `bob` (uid 9) requests `GET /api/orders/1001` (owned by uid 7) → backend returns **200** and the body `user_id: 7` | The app has an IDOR: it hands any order to any logged-in user. |
| ② Detect | AEGIS read the response and recorded a **confirmed, critical** `bola_object_ownership` finding | The owner (`user_id: 7`) is read from the **response body** and compared to the caller's real id (`uid: 9`, via `auth.identity_claim`) — a confirmed leak, not a heuristic guess, and not fooled by the email subject. This is what a WAF can't see. |
| ③ Prevent | `bob` retries → **403**, denied at the gateway before it reaches the app | Once AEGIS knows uid 7 owns `1001`, every cross-owner attempt is blocked up front. |
| ④ No collateral | `alice` (uid 7) reads her own `1001` → **200** | The real owner is untouched. |

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
4. Pre-empt the obvious objection: "real JWTs carry an email/UUID subject, not
   the user id." This demo already models that — the token's `sub` is an email
   and the owner id is a numeric `uid` claim, wired via `auth.identity_claim: uid`
   so the gateway compares the right identities. Point it out; it lands well.

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
