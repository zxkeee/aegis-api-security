#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AEGIS — live IDOR / BOLA demo
#
# Tells the story in front of an audience: a vulnerable backend leaks another
# user's order, AEGIS catches it as a CONFIRMED IDOR from the response body, and
# then blocks every repeat attempt before it reaches the app.
#
# Usage:  ./demo/idor-demo.sh          # interactive: press Enter between steps
#         ./demo/idor-demo.sh -y       # run straight through (no pauses)
#
# Requires: docker (for redis), go, curl. jq is used if present (nicer output).
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

AUTO=0
[ "${1:-}" = "-y" ] && AUTO=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$(mktemp -d)"
REDIS_NAME="aegis-demo-idor-redis"

GW=http://127.0.0.1:18080
ADMIN=http://127.0.0.1:18081

C_HDR='\033[1;36m'; C_OK='\033[0;32m'; C_BAD='\033[0;31m'; C_DIM='\033[0;90m'; C_Y='\033[1;33m'; NC='\033[0m'

cleanup() {
  echo -e "\n${C_DIM}— tearing down —${NC}"
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "${BE_PID:-}" ] && kill "$BE_PID" 2>/dev/null || true
  docker rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
  rm -rf "$BIN"
}
trap cleanup EXIT

pause() { [ "$AUTO" = "1" ] && return; echo -en "${C_DIM}   (press Enter)${NC}"; read -r; }
hdr()   { echo -e "\n${C_HDR}$1${NC}"; }
pretty(){ if command -v jq >/dev/null 2>&1; then jq -C .; else cat; fi; }

# ── Bring up the stand ────────────────────────────────────────────────────────
echo -e "${C_HDR}AEGIS — IDOR / BOLA live demo${NC}"
echo -e "${C_DIM}Building gateway + vulnerable backend + token minter…${NC}"

export AEGIS_ADMIN_SECRET="$(openssl rand -hex 32)"
export AEGIS_REDIS_PASSWORD="$(openssl rand -hex 16)"
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"

# Pre-flight: clear a stale demo gateway from an earlier aborted run (it would
# hold :18080 with a different JWT secret and 401 the new tokens).
pkill -f "gateway --config demo/gateway.demo-idor.yaml" >/dev/null 2>&1 || true
docker rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
sleep 1
docker run -d --rm --name "$REDIS_NAME" -p 16380:6379 redis:7-alpine \
  redis-server --requirepass "$AEGIS_REDIS_PASSWORD" >/dev/null

( cd "$ROOT" && go build -o "$BIN/gateway" ./cmd/gateway )
( cd "$ROOT" && go build -o "$BIN/backend" ./demo/orders-backend )
( cd "$ROOT" && go build -o "$BIN/mint"    ./demo/mint-jwt )

"$BIN/backend" -addr :19000 >/dev/null 2>&1 & BE_PID=$!
( cd "$ROOT" && "$BIN/gateway" --config demo/gateway.demo-idor.yaml ) >/dev/null 2>&1 & GW_PID=$!
disown "$BE_PID" "$GW_PID" 2>/dev/null || true  # keep job-control chatter out of the demo

for i in $(seq 1 30); do curl -fsS -o /dev/null "$ADMIN/health" 2>/dev/null && break; sleep 1; done

ALICE="$("$BIN/mint" -secret "$AEGIS_JWT_SECRET" -sub alice@corp.com -uid 7 -roles user)"
BOB="$(  "$BIN/mint" -secret "$AEGIS_JWT_SECRET" -sub bob@corp.com   -uid 9 -roles user)"
echo -e "${C_OK}stand up.${NC} alice (uid 7) + bob (uid 9) authenticated with real JWTs.\n"
echo -e "${C_DIM}Note: the JWT subject is an email; the owner id is a numeric 'uid' claim —"
echo -e "the realistic case where the resource owner is NOT the subject."
echo -e "Backend: order 1001 belongs to uid 7 (alice). It returns any order to any"
echo -e "logged-in user — a textbook IDOR. AEGIS is in front on :18080.${NC}"
pause

# ── Step 1: the attack — bob reads alice's order ──────────────────────────────
hdr "① Attack: bob (logged in) requests alice's order /api/orders/1001"
CODE=$(curl -s -o /tmp/idor_body -w '%{http_code}' -H "Authorization: Bearer $BOB" "$GW/api/orders/1001")
echo -e "   backend response: ${C_BAD}HTTP $CODE${NC}  ${C_DIM}(the vulnerable app leaked it)${NC}"
cat /tmp/idor_body | pretty | sed 's/^/   /'
echo -e "   ${C_Y}↑ the body says user_id=7 (alice), but the caller's uid is 9 (bob).${NC}"
pause

# ── Step 2: AEGIS caught it — confirmed IDOR finding ──────────────────────────
hdr "② AEGIS read the response and flagged a CONFIRMED IDOR"
sleep 1
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" "$ADMIN/api/block-log" \
  | ( if command -v jq >/dev/null 2>&1; then \
        jq -C '[.[] | select(.reason=="bola_object_ownership")][0] | {reason, severity: .extra.severity, why: .extra.why}'; \
      else cat; fi ) | sed 's/^/   /'
echo -e "   ${C_DIM}(critical, confirmed from the body — not a heuristic guess)${NC}"
pause

# ── Step 3: prevention — the retry is blocked before the app ──────────────────
hdr "③ Now AEGIS knows alice owns 1001 — bob's next attempt is blocked"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $BOB" "$GW/api/orders/1001")
echo -e "   bob retries /api/orders/1001 → ${C_OK}HTTP $CODE${NC} ${C_DIM}(403: denied at the gateway, never reaches the app)${NC}"
pause

# ── Step 4: no collateral — the real owner is unaffected ──────────────────────
hdr "④ The real owner is untouched: alice reads her own order 1001"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ALICE" "$GW/api/orders/1001")
echo -e "   alice → ${C_OK}HTTP $CODE${NC} ${C_DIM}(allowed — she owns it)${NC}"

echo -e "\n${C_OK}Done.${NC} AEGIS detected the leak your WAF can't see, confirmed it from the"
echo -e "response body, and blocked every repeat — without touching the legitimate owner."
