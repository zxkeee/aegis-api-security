package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP is a minimal but real OpenID Connect provider: it serves a discovery
// document, a JWKS with its RSA public key, and a token endpoint that returns a
// signed ID token. It lets us exercise the whole Authenticator (discovery →
// AuthCodeURL → Exchange → verify → claim mapping) against real OIDC crypto,
// with no external dependency.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	nonce    string // echoed into the issued ID token
	email    string
	groups   []string
}

func newFakeIdP(t *testing.T, clientID string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	f := &fakeIdP{key: key, clientID: clientID, email: "op@example.com", groups: []string{"aegis-admins"}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss,
			"authorization_endpoint":                iss + "/authorize",
			"token_endpoint":                        iss + "/token",
			"jwks_uri":                              iss + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := f.key.Public().(*rsa.PublicKey)
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "kid": "test-key", "alg": "RS256", "n": n, "e": e,
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// A real client sends grant_type=authorization_code, code, and the PKCE
		// code_verifier. We don't re-derive the challenge here (the flow-state
		// single-use + nonce are what the AEGIS-side test asserts); we just mint a
		// correctly-signed ID token.
		claims := jwt.MapClaims{
			"iss":            f.srv.URL,
			"aud":            f.clientID,
			"sub":            "subject-123",
			"email":          f.email,
			"email_verified": true,
			"groups":         f.groups,
			"nonce":          f.nonce,
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(5 * time.Minute).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test-key"
		signed, err := tok.SignedString(f.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     signed,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestAuthenticator_EndToEnd(t *testing.T) {
	idp := newFakeIdP(t, "aegis-console")

	auth, err := New(context.Background(), config.OIDCConfig{
		Issuer:       idp.srv.URL,
		ClientID:     "aegis-console",
		ClientSecret: "secret",
		RedirectURL:  "https://console.example.com/api/auth/oidc/callback",
		Scopes:       []string{"email", "groups"},
		RolesClaim:   "groups",
		AdminRoles:   []string{"aegis-admins"},
	})
	if err != nil {
		t.Fatalf("New (discovery): %v", err)
	}

	flow, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	idp.nonce = flow.Nonce // the IdP will echo this nonce into the ID token

	// AuthCodeURL must carry state, nonce, and an S256 PKCE challenge.
	au, err := url.Parse(auth.AuthCodeURL(flow))
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	q := au.Query()
	if q.Get("state") != flow.State || q.Get("nonce") != flow.Nonce {
		t.Fatalf("auth url missing state/nonce: %v", q)
	}
	if q.Get("code_challenge") != pkceChallenge(flow.CodeVerifier) || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("auth url missing PKCE S256 challenge: %v", q)
	}

	// Exchange a code → verified identity, claims mapped to admin.
	ident, err := auth.Exchange(context.Background(), flow, "the-auth-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ident.Email != "op@example.com" || ident.Role != iam.RoleAdmin {
		t.Fatalf("mapped identity wrong: %+v", ident)
	}
}

func TestAuthenticator_RejectsNonceMismatch(t *testing.T) {
	idp := newFakeIdP(t, "aegis-console")
	auth, err := New(context.Background(), config.OIDCConfig{
		Issuer: idp.srv.URL, ClientID: "aegis-console", ClientSecret: "secret",
		RedirectURL: "https://console.example.com/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	flow, _ := NewFlow()
	idp.nonce = "a-different-nonce" // IdP echoes the WRONG nonce (replay/injection)

	_, err = auth.Exchange(context.Background(), flow, "code")
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce mismatch must be rejected, got %v", err)
	}
}

func TestAuthenticator_RejectsWrongAudience(t *testing.T) {
	idp := newFakeIdP(t, "some-other-client") // token aud won't match our client_id
	auth, err := New(context.Background(), config.OIDCConfig{
		Issuer: idp.srv.URL, ClientID: "aegis-console", ClientSecret: "secret",
		RedirectURL: "https://console.example.com/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	flow, _ := NewFlow()
	idp.nonce = flow.Nonce
	if _, err := auth.Exchange(context.Background(), flow, "code"); err == nil {
		t.Fatal("ID token with wrong audience must be rejected")
	}
}
