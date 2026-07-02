package api

import (
	"context"
	"encoding/json"
	"net/http"

	"api-gateway/internal/audit"
	"api-gateway/internal/iam"
	"api-gateway/internal/middleware"
	"api-gateway/internal/sso"
)

// OIDCAuthenticator is the slice of *sso.Authenticator the handlers depend on,
// declared as an interface so the callback flow can be unit-tested with a fake
// (no live identity provider). The real authenticator satisfies it.
type OIDCAuthenticator interface {
	AuthCodeURL(f sso.Flow) string
	Exchange(ctx context.Context, f sso.Flow, code string) (sso.Identity, error)
}

// oidcEnabled reports whether SSO is wired (config on AND the authenticator
// built successfully at startup). When off, the endpoints 404 so the surface is
// invisible.
func (h *handlers) oidcEnabled() bool {
	return h.cfg.OIDC.Enabled && h.oidc != nil
}

// oidcLogin (GET /api/auth/oidc/login) starts the Authorization Code flow: it
// mints per-login state/nonce/PKCE, persists them server-side keyed by state,
// and redirects the browser to the identity provider.
func (h *handlers) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if !h.oidcEnabled() {
		writeError(w, http.StatusNotFound, "sso is not enabled")
		return
	}
	flow, err := sso.NewFlow()
	if err != nil {
		h.log.Error("oidc: mint flow failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "could not start sso login")
		return
	}
	payload, err := json.Marshal(flow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start sso login")
		return
	}
	if err := h.store.PutLoginFlow(r.Context(), flow.State, string(payload), sso.FlowTTL); err != nil {
		h.log.Error("oidc: persist flow failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusServiceUnavailable, "could not start sso login")
		return
	}
	http.Redirect(w, r, h.oidc.AuthCodeURL(flow), http.StatusFound)
}

// oidcCallback (GET /api/auth/oidc/callback) completes the flow: it validates
// state against the stored (single-use) flow, exchanges the code, verifies the
// ID token, JIT-provisions the operator, and establishes the same server-side
// console session password login uses — then redirects to the dashboard.
func (h *handlers) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if !h.oidcEnabled() {
		writeError(w, http.StatusNotFound, "sso is not enabled")
		return
	}
	ip := middleware.RealIP(r)

	// A provider-side error (user denied consent, etc.) comes back as ?error=.
	if e := r.URL.Query().Get("error"); e != "" {
		h.log.Warn("oidc: provider returned error", map[string]any{"error": e, "ip": ip})
		h.oidcFail(w, r, "sso login was cancelled or rejected")
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		h.oidcFail(w, r, "malformed sso callback")
		return
	}

	// State must match a stored, unconsumed flow. GETDEL makes it single-use, so
	// a replayed callback (or a forged state) finds nothing.
	raw, ok, err := h.store.TakeLoginFlow(r.Context(), state)
	if err != nil {
		h.log.Error("oidc: load flow failed", map[string]any{"error": err.Error()})
		h.oidcFail(w, r, "sso login failed")
		return
	}
	if !ok {
		h.log.Warn("oidc: unknown or expired state", map[string]any{"ip": ip})
		h.oidcFail(w, r, "sso login expired; please try again")
		return
	}
	var flow sso.Flow
	if err := json.Unmarshal([]byte(raw), &flow); err != nil {
		h.oidcFail(w, r, "sso login failed")
		return
	}

	ident, err := h.oidc.Exchange(r.Context(), flow, code)
	if err != nil {
		h.log.Warn("oidc: exchange/verify failed", map[string]any{"error": err.Error(), "ip": ip})
		h.audit.Record(audit.Entry{
			Action: "login_failed", Method: r.Method, Path: r.URL.Path,
			Status: http.StatusUnauthorized, IP: ip, Detail: "oidc",
		})
		h.oidcFail(w, r, "sso login failed")
		return
	}

	// JIT-provision (or re-sync) the operator, then build the session.
	u, err := h.users.UpsertSSOUser(r.Context(), ident.TenantID, ident.Email, ident.Role, ident.SuperAdmin)
	if err != nil {
		h.log.Error("oidc: provision user failed", map[string]any{"error": err.Error()})
		h.oidcFail(w, r, "sso login failed")
		return
	}
	sess := iam.Session{
		TenantID:   u.TenantID,
		Role:       u.Role,
		UserID:     u.ID,
		Email:      u.Email,
		SuperAdmin: u.SuperAdmin,
	}
	if _, err := h.establishSession(r.Context(), w, sess); err != nil {
		h.log.Error("oidc: establish session failed", map[string]any{"error": err.Error()})
		h.oidcFail(w, r, "sso login failed")
		return
	}
	h.audit.Record(audit.Entry{
		TenantID: sess.TenantID, ActorID: sess.UserID, ActorEmail: sess.Email,
		Role: string(sess.Role), SuperAdmin: sess.SuperAdmin, Action: "login",
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, IP: ip, Detail: "oidc",
	})
	h.log.Info("admin_login", map[string]any{
		"ip": ip, "tenant": sess.TenantID, "role": string(sess.Role), "user": sess.UserID, "via": "oidc",
	})
	// Land on the dashboard; the session cookie is now set. The console reads its
	// CSRF token from the aegis_csrf cookie (double-submit), so no fragment needed.
	http.Redirect(w, r, "/", http.StatusFound)
}

// oidcFail redirects back to the dashboard with an error indicator the console
// can surface, rather than dumping a raw error page.
func (h *handlers) oidcFail(w http.ResponseWriter, r *http.Request, _ string) {
	http.Redirect(w, r, "/?sso_error=1", http.StatusFound)
}
