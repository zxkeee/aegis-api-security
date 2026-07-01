package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/sso"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// fakeOIDC is a stand-in identity provider: AuthCodeURL echoes the state so the
// test can assert it round-trips, and Exchange returns a preset identity/error.
type fakeOIDC struct {
	ident   sso.Identity
	err     error
	gotCode string
	gotFlow sso.Flow
}

func (f *fakeOIDC) AuthCodeURL(fl sso.Flow) string {
	return "https://idp.example.com/authorize?state=" + fl.State + "&code_challenge=x"
}
func (f *fakeOIDC) Exchange(_ context.Context, fl sso.Flow, code string) (sso.Identity, error) {
	f.gotCode = code
	f.gotFlow = fl
	return f.ident, f.err
}

func oidcHandlers(t *testing.T, oidc OIDCAuthenticator) (*handlers, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_ = middleware.InitTrustedProxies(nil)
	cfg := config.GatewayConfig{AdminAuth: true, AdminSessionTTL: time.Hour, OIDC: config.OIDCConfig{Enabled: true}}
	return &handlers{store: st, log: logger.New("error"), cfg: cfg, oidc: oidc}, mr
}

func TestOIDCLogin_RedirectsAndPersistsFlow(t *testing.T) {
	h, mr := oidcHandlers(t, &fakeOIDC{})
	rec := httptest.NewRecorder()
	h.oidcLogin(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.com/authorize?state=") {
		t.Fatalf("unexpected redirect: %q", loc)
	}
	state := strings.TrimPrefix(loc[:strings.Index(loc, "&")], "https://idp.example.com/authorize?state=")
	// The flow must be persisted server-side under that state.
	keys := mr.Keys()
	found := false
	for _, k := range keys {
		if strings.Contains(k, "oidc:flow:"+state) {
			found = true
		}
	}
	if !found {
		t.Fatalf("login flow not persisted for state %q; keys=%v", state, keys)
	}
}

func TestOIDCLogin_DisabledIs404(t *testing.T) {
	h, _ := oidcHandlers(t, &fakeOIDC{})
	h.cfg.OIDC.Enabled = false
	rec := httptest.NewRecorder()
	h.oidcLogin(rec, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled SSO must 404, got %d", rec.Code)
	}
}

func TestOIDCCallback_UnknownStateRejected(t *testing.T) {
	h, _ := oidcHandlers(t, &fakeOIDC{})
	rec := httptest.NewRecorder()
	// No flow was ever stored for this state.
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=forged&code=abc", nil)
	h.oidcCallback(rec, r)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=1" {
		t.Fatalf("forged state must redirect to error, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOIDCCallback_ProviderErrorRejected(t *testing.T) {
	h, _ := oidcHandlers(t, &fakeOIDC{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?error=access_denied", nil)
	h.oidcCallback(rec, r)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/?sso_error=1" {
		t.Fatalf("provider error must redirect to error page, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// TestOIDCCallback_StateIsSingleUse verifies GETDEL semantics: after a flow is
// consumed once, a replay of the same state finds nothing. Uses a fake exchange
// that fails, so no PG is needed — we only assert the flow is gone after the
// first callback.
func TestOIDCCallback_StateIsSingleUse(t *testing.T) {
	f := &fakeOIDC{err: errors.New("exchange fails in this test")}
	h, mr := oidcHandlers(t, f)

	flow, _ := sso.NewFlow()
	if err := h.store.PutLoginFlow(context.Background(), flow.State, `{"state":"`+flow.State+`","nonce":"n","code_verifier":"v"}`, sso.FlowTTL); err != nil {
		t.Fatal(err)
	}
	// h.audit stays nil; audit.Store.Record is nil-safe, and Exchange fails before
	// any PG-backed step, so no PostgreSQL is needed for this assertion.

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state="+flow.State+"&code=abc", nil)
	h.oidcCallback(rec, r)
	if rec.Code != http.StatusFound { // exchange failed → redirect to error
		t.Fatalf("want redirect after failed exchange, got %d", rec.Code)
	}

	if _, ok, _ := h.store.TakeLoginFlow(context.Background(), flow.State); ok {
		t.Fatal("state was not consumed (GETDEL) on first callback")
	}
	_ = mr
}

// Full happy-path callback needs PostgreSQL (JIT user provisioning). Gated like
// the other integration tests so the default `go test ./...` stays hermetic.
func TestOIDCCallback_HappyPath_Integration(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set POSTGRES_DSN to run the SSO callback integration test")
	}
	users, err := iam.NewStore(dsn, logger.New("error"))
	if err != nil {
		t.Fatalf("iam.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = users.Close() })
	auditStore, err := audit.New(dsn, logger.New("error"))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })

	f := &fakeOIDC{ident: sso.Identity{
		Email: "sso-user@example.com", TenantID: "default", Role: iam.RoleAdmin, SuperAdmin: false,
	}}
	h, _ := oidcHandlers(t, f)
	h.users = users
	h.audit = auditStore

	flow, _ := sso.NewFlow()
	_ = h.store.PutLoginFlow(context.Background(), flow.State,
		`{"state":"`+flow.State+`","nonce":"`+flow.Nonce+`","code_verifier":"`+flow.CodeVerifier+`"}`, sso.FlowTTL)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state="+flow.State+"&code=thecode", nil)
	h.oidcCallback(rec, r)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("happy path must redirect to /, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The session + CSRF cookies must be set.
	var gotSession, gotCSRF bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.SessionCookie && c.Value != "" {
			gotSession = true
		}
		if c.Name == middleware.CSRFCookie && c.Value != "" {
			gotCSRF = true
		}
	}
	if !gotSession || !gotCSRF {
		t.Fatalf("callback must set session and csrf cookies (session=%v csrf=%v)", gotSession, gotCSRF)
	}
	if f.gotCode != "thecode" {
		t.Fatalf("exchange did not receive the code: %q", f.gotCode)
	}
}
