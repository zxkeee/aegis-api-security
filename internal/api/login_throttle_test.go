package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestLogin_ThrottlesAfterRepeatedFailures verifies the per-IP brute-force gate
// in login() flips to 429 + Retry-After after loginBruteforceLimit consecutive
// failures within the window. Backed by an in-memory Redis (miniredis) so it
// runs in plain `go test ./...` with no external services.
func TestLogin_ThrottlesAfterRepeatedFailures(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true

	// Use a unique RemoteAddr so the counter is isolated.
	ip := "203.0.113.117:1111"

	post := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"secret": "wrong"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
		r.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.login(rec, r)
		return rec
	}

	// First N attempts return 401 — credentials wrong but gate not yet tripped.
	for i := 1; i <= loginBruteforceLimit; i++ {
		if code := post().Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, code)
		}
	}
	// One more: gate now denies before doing crypto work.
	rec := post()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginBruteforceLimit, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header must be set on throttle response")
	}
}

// TestLogin_ThrottleIsAtomicUnderConcurrency guards VULN H3: a burst of
// concurrent failed-login attempts must not all sail past the brute-force
// gate just because none of them had incremented the counter yet when the
// others checked it. Fire far more than loginBruteforceLimit requests at
// once and assert only loginBruteforceLimit of them ever reach the real
// credential check (401); everything else must be rejected at the gate (429)
// before doing any crypto work.
func TestLogin_ThrottleIsAtomicUnderConcurrency(t *testing.T) {
	h, _ := redisHandlers(t)
	h.cfg.AdminAuth = true
	ip := "203.0.113.118:2222"

	const burst = 50 // well over loginBruteforceLimit (8)
	var unauthorized, throttled int64
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func() {
			defer wg.Done()
			b, _ := json.Marshal(map[string]string{"secret": "wrong"})
			r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(b))
			r.RemoteAddr = ip
			rec := httptest.NewRecorder()
			h.login(rec, r)
			switch rec.Code {
			case http.StatusUnauthorized:
				atomic.AddInt64(&unauthorized, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt64(&throttled, 1)
			default:
				t.Errorf("unexpected status %d", rec.Code)
			}
		}()
	}
	wg.Wait()

	if unauthorized != loginBruteforceLimit {
		t.Fatalf("expected exactly %d requests to reach the credential check under concurrency, got %d (the atomic gate should cap this regardless of how many arrive at once)", loginBruteforceLimit, unauthorized)
	}
	if throttled != burst-loginBruteforceLimit {
		t.Fatalf("expected %d requests throttled, got %d", burst-loginBruteforceLimit, throttled)
	}
}
