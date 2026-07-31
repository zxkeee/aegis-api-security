package api

import (
	"context"
	"net/http"
	"testing"

	"api-gateway/internal/iam"
)

// GET /api/session echoes back exactly what AdminAuth already put in the
// request context (tenant/role/super_admin) — no store access, so this only
// needs redisHandlers, not a full PG-backed iam.Store.

func TestGetSession_ReflectsContext(t *testing.T) {
	h, _ := redisHandlers(t)

	rec, body := doReq(h.getSession, http.MethodGet, "/api/session", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getSession = %d, want 200", rec.Code)
	}
	if body["tenant"] != "acme" || body["role"] != string(iam.RoleViewer) || body["super_admin"] != false {
		t.Fatalf("getSession body = %v, want tenant=acme role=viewer super_admin=false", body)
	}
}

func TestGetSession_SuperAdmin(t *testing.T) {
	h, _ := redisHandlers(t)

	rec, body := doReq(h.getSession, http.MethodGet, "/api/session", ctxAs("default", iam.RoleAdmin, true), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getSession = %d, want 200", rec.Code)
	}
	if body["tenant"] != "default" || body["role"] != string(iam.RoleAdmin) || body["super_admin"] != true {
		t.Fatalf("getSession body = %v, want tenant=default role=admin super_admin=true", body)
	}
}

// No AdminAuth context at all (shouldn't happen in practice — the route sits
// behind AdminAuth — but the handler itself must degrade to the package's
// documented zero-value defaults rather than panic).
func TestGetSession_NoContext_DefaultsSafely(t *testing.T) {
	h, _ := redisHandlers(t)

	rec, body := doReq(h.getSession, http.MethodGet, "/api/session", context.Background(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getSession = %d, want 200", rec.Code)
	}
	if body["tenant"] != "default" || body["role"] != string(iam.RoleViewer) || body["super_admin"] != false {
		t.Fatalf("getSession no-context body = %v, want the package's documented zero-value defaults", body)
	}
}
