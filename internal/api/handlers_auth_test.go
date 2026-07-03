package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/middleware"
)

// TestRequireAuth_Branches exercises the in-handler defence-in-depth auth check
// across its credential paths (bearer, session cookie, none).
func TestRequireAuth_Branches(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	h.cfg.AdminSecret = "test-secret-min-32-characters-1234"

	call := func(setup func(*http.Request)) (bool, int) {
		r := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
		if setup != nil {
			setup(r)
		}
		rec := httptest.NewRecorder()
		ok := h.requireAuth(rec, r)
		return ok, rec.Code
	}

	t.Run("valid bearer passes", func(t *testing.T) {
		if ok, _ := call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+h.cfg.AdminSecret) }); !ok {
			t.Fatal("valid bearer should pass")
		}
	})
	t.Run("wrong bearer 403", func(t *testing.T) {
		ok, code := call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") })
		if ok || code != http.StatusForbidden {
			t.Fatalf("wrong bearer: ok=%v code=%d, want false/403", ok, code)
		}
	})
	t.Run("no credentials 401", func(t *testing.T) {
		ok, code := call(nil)
		if ok || code != http.StatusUnauthorized {
			t.Fatalf("no creds: ok=%v code=%d, want false/401", ok, code)
		}
	})
	t.Run("valid session cookie passes", func(t *testing.T) {
		tok := "sess-token-abc"
		if err := h.store.CreateSession(context.Background(), tok,
			iam.Session{TenantID: "default", Role: iam.RoleAdmin}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if ok, _ := call(func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: middleware.SessionCookie, Value: tok})
		}); !ok {
			t.Fatal("valid session cookie should pass")
		}
	})
	t.Run("admin_auth disabled passes (dev)", func(t *testing.T) {
		h2, _ := redisHandlers(t) // AdminAuth false
		if ok := h2.requireAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); !ok {
			t.Fatal("disabled admin_auth should pass through")
		}
	})
}

// Store-backed read handlers must surface a Redis outage as 500 (not panic).
func TestReadHandlers_RedisDown500(t *testing.T) {
	handlers := map[string]func(http.ResponseWriter, *http.Request){}
	h, mr := redisHandlers(t)
	handlers["metrics"] = h.getMetrics
	handlers["block-log"] = h.getBlockLog
	handlers["inventory"] = h.getInventory
	handlers["blocked-ips"] = h.getBlockedIPs
	handlers["effectiveness"] = h.getEffectiveness
	mr.Close() // simulate outage

	for name, fn := range handlers {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s with Redis down = %d, want 500", name, rec.Code)
		}
	}
}

// unblockIPHandler: happy path (via admin ctx) and input validation.
func TestUnblockIP(t *testing.T) {
	h, _ := redisHandlers(t)
	admin := ctxAs("default", iam.RoleAdmin, true)

	// Block then unblock a valid IP.
	_ = h.store.BlockIP(context.Background(), "203.0.113.7")
	r := httptest.NewRequest(http.MethodDelete, "/api/blocked-ips/203.0.113.7", nil).WithContext(admin)
	r.SetPathValue("ip", "203.0.113.7")
	rec := httptest.NewRecorder()
	h.unblockIPHandler(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock valid IP = %d, want 200", rec.Code)
	}
	if blocked, _ := h.store.IsIPBlocked(context.Background(), "203.0.113.7"); blocked {
		t.Fatal("IP should be unblocked")
	}

	// Malformed IP → 400.
	rBad := httptest.NewRequest(http.MethodDelete, "/api/blocked-ips/not-an-ip", nil).WithContext(admin)
	rBad.SetPathValue("ip", "not-an-ip")
	recBad := httptest.NewRecorder()
	h.unblockIPHandler(recBad, rBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("malformed IP = %d, want 400", recBad.Code)
	}

	// Viewer role → 403 (RBAC).
	viewer := ctxAs("default", iam.RoleViewer, false)
	rV := httptest.NewRequest(http.MethodDelete, "/api/blocked-ips/203.0.113.8", nil).WithContext(viewer)
	rV.SetPathValue("ip", "203.0.113.8")
	recV := httptest.NewRecorder()
	h.unblockIPHandler(recV, rV)
	if recV.Code != http.StatusForbidden {
		t.Fatalf("viewer unblock = %d, want 403", recV.Code)
	}
}
