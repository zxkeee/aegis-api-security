package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/config"
)

// freshTS returns the current Unix timestamp as a string, so signed test
// requests fall inside ServiceAuth's freshness window regardless of when the
// test runs.
func freshTS() string { return strconv.FormatInt(time.Now().Unix(), 10) }

// fakeRegistry implements RegistryProvider for service-auth tests.
type fakeRegistry struct {
	secret    string
	ok        bool
	rateOK    bool
	lookupErr error
}

func (f fakeRegistry) LookupService(context.Context, string) (string, bool, error) {
	return f.secret, f.ok, f.lookupErr
}
func (f fakeRegistry) CheckRateLimit(context.Context, string, config.RateLimitConfig) (bool, error) {
	return f.rateOK, nil
}

func signService(secret, method, path, ts string) string {
	payload := strings.Join([]string{method, path, ts}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func runServiceAuth(reg RegistryProvider, setup func(*http.Request)) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	cfg := config.RegistryConfig{Enabled: true, SignatureFreshnessSecs: 60}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := ServiceAuth(cfg, fakeLogger{}, &fakeStore{}, reg)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/svc/op", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	if setup != nil {
		setup(r)
	}
	h.ServeHTTP(rec, r)
	return rec
}

func TestServiceAuth_NoHeaders_Passthrough(t *testing.T) {
	if rec := runServiceAuth(fakeRegistry{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("unsigned request should pass through, got %d", rec.Code)
	}
}

func TestServiceAuth_ValidSignature(t *testing.T) {
	reg := fakeRegistry{secret: "svc-secret", ok: true, rateOK: true}
	ts := freshTS()
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "svc-1")
		r.Header.Set("X-Timestamp", ts)
		r.Header.Set("X-Service-Signature", signService("svc-secret", r.Method, r.URL.Path, ts))
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid signature: got %d, want 200", rec.Code)
	}
}

func TestServiceAuth_BadSignature_403(t *testing.T) {
	reg := fakeRegistry{secret: "svc-secret", ok: true, rateOK: true}
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "svc-1")
		r.Header.Set("X-Timestamp", freshTS())
		r.Header.Set("X-Service-Signature", "deadbeef")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature: got %d, want 403", rec.Code)
	}
}

func TestServiceAuth_UnknownService_403(t *testing.T) {
	reg := fakeRegistry{ok: false}
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "ghost")
		r.Header.Set("X-Timestamp", freshTS())
		r.Header.Set("X-Service-Signature", "whatever")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown service: got %d, want 403", rec.Code)
	}
}

func TestServiceAuth_RateLimited_429(t *testing.T) {
	reg := fakeRegistry{secret: "svc-secret", ok: true, rateOK: false}
	ts := freshTS()
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "svc-1")
		r.Header.Set("X-Timestamp", ts)
		r.Header.Set("X-Service-Signature", signService("svc-secret", r.Method, r.URL.Path, ts))
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited: got %d, want 429", rec.Code)
	}
}

// TestServiceAuth_StaleTimestamp_403 guards VULN L1: a captured, otherwise
// valid (X-Service-ID, X-Service-Signature, X-Timestamp) triple must not be
// replayable once its timestamp falls outside the freshness window.
func TestServiceAuth_StaleTimestamp_403(t *testing.T) {
	reg := fakeRegistry{secret: "svc-secret", ok: true, rateOK: true}
	staleTS := strconv.FormatInt(time.Now().Add(-5*time.Minute).Unix(), 10) // window is 60s
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "svc-1")
		r.Header.Set("X-Timestamp", staleTS)
		r.Header.Set("X-Service-Signature", signService("svc-secret", r.Method, r.URL.Path, staleTS))
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale timestamp (otherwise valid signature): got %d, want 403", rec.Code)
	}
}

// TestServiceAuth_MissingTimestamp_403 guards against a malformed/absent
// X-Timestamp being parsed as skew=0 (always "fresh") instead of rejected.
func TestServiceAuth_MissingTimestamp_403(t *testing.T) {
	reg := fakeRegistry{secret: "svc-secret", ok: true, rateOK: true}
	rec := runServiceAuth(reg, func(r *http.Request) {
		r.Header.Set("X-Service-ID", "svc-1")
		r.Header.Set("X-Service-Signature", signService("svc-secret", r.Method, r.URL.Path, ""))
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing timestamp: got %d, want 403", rec.Code)
	}
}
