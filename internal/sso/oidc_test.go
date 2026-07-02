package sso

import (
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

func auth(cfg config.OIDCConfig) *Authenticator { return &Authenticator{cfg: cfg} }

func TestMapIdentity_AdminAndSuperAdminRoles(t *testing.T) {
	a := auth(config.OIDCConfig{
		RolesClaim:      "groups",
		AdminRoles:      []string{"aegis-admins"},
		SuperAdminRoles: []string{"aegis-superadmins"},
	})

	t.Run("admin group → admin, not super", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "Op@Example.com", "groups": []any{"aegis-admins", "other"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Email != "op@example.com" {
			t.Fatalf("email not normalised: %q", id.Email)
		}
		if id.Role != iam.RoleAdmin || id.SuperAdmin {
			t.Fatalf("want admin/non-super, got %s super=%v", id.Role, id.SuperAdmin)
		}
	})

	t.Run("superadmin group → admin+super, pinned to default tenant", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "root@example.com", "groups": []any{"aegis-superadmins"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Role != iam.RoleAdmin || !id.SuperAdmin {
			t.Fatalf("want admin+super, got %s super=%v", id.Role, id.SuperAdmin)
		}
		if id.TenantID != tenant.Default {
			t.Fatalf("super-admin must pin to default tenant, got %q", id.TenantID)
		}
	})

	t.Run("no matching group → viewer", func(t *testing.T) {
		id, err := a.mapIdentity(map[string]any{
			"email": "user@example.com", "groups": []any{"unrelated"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if id.Role != iam.RoleViewer || id.SuperAdmin {
			t.Fatalf("want viewer, got %s super=%v", id.Role, id.SuperAdmin)
		}
	})
}

func TestMapIdentity_RequireMappedRoleRejectsUnmapped(t *testing.T) {
	a := auth(config.OIDCConfig{
		RolesClaim: "groups", AdminRoles: []string{"admins"}, RequireMappedRole: true,
	})
	if _, err := a.mapIdentity(map[string]any{
		"email": "user@example.com", "groups": []any{"nope"},
	}); err == nil {
		t.Fatal("unmapped user must be rejected when require_mapped_role is set")
	}
}

func TestMapIdentity_TenantClaim(t *testing.T) {
	a := auth(config.OIDCConfig{RolesClaim: "groups", TenantClaim: "org", AdminRoles: []string{"admins"}})
	id, err := a.mapIdentity(map[string]any{
		"email": "u@example.com", "org": "acme", "groups": []any{"admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != "acme" {
		t.Fatalf("tenant claim not honoured: %q", id.TenantID)
	}
}

func TestMapIdentity_AllowedDomains(t *testing.T) {
	a := auth(config.OIDCConfig{AllowedDomains: []string{"example.com"}})
	if _, err := a.mapIdentity(map[string]any{"email": "u@evil.com"}); err == nil {
		t.Fatal("email outside allowed_domains must be rejected")
	}
	if _, err := a.mapIdentity(map[string]any{"email": "u@example.com"}); err != nil {
		t.Fatalf("allowed domain rejected: %v", err)
	}
}

func TestMapIdentity_RejectsUnverifiedEmailAndMissingEmail(t *testing.T) {
	a := auth(config.OIDCConfig{})
	if _, err := a.mapIdentity(map[string]any{"email": "u@x.com", "email_verified": false}); err == nil {
		t.Fatal("unverified email must be rejected")
	}
	if _, err := a.mapIdentity(map[string]any{"sub": "123"}); err == nil {
		t.Fatal("missing email must be rejected")
	}
}

func TestMapIdentity_RolesClaimAsSingleString(t *testing.T) {
	a := auth(config.OIDCConfig{RolesClaim: "role", AdminRoles: []string{"admin"}})
	id, err := a.mapIdentity(map[string]any{"email": "u@x.com", "role": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != iam.RoleAdmin {
		t.Fatalf("single-string roles claim not handled: %s", id.Role)
	}
}

func TestNewFlow_UniqueAndPKCEDeterministic(t *testing.T) {
	f1, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	f2, err := NewFlow()
	if err != nil {
		t.Fatal(err)
	}
	if f1.State == f2.State || f1.Nonce == f2.Nonce || f1.CodeVerifier == f2.CodeVerifier {
		t.Fatal("flows must be unique per call")
	}
	// PKCE challenge is a pure function of the verifier (S256): same verifier →
	// same challenge, different verifier → different challenge.
	c1a := pkceChallenge(f1.CodeVerifier)
	c1b := pkceChallenge(f1.CodeVerifier)
	if c1a != c1b {
		t.Fatal("pkce challenge must be deterministic for a verifier")
	}
	if c1a == pkceChallenge(f2.CodeVerifier) {
		t.Fatal("different verifiers must yield different challenges")
	}
}

func TestNormaliseScopes_AlwaysOpenIDOnce(t *testing.T) {
	got := normaliseScopes([]string{"email", "openid", "groups", "email"})
	if got[0] != "openid" {
		t.Fatalf("openid must be first, got %v", got)
	}
	count := 0
	for _, s := range got {
		if s == "openid" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("openid must appear exactly once, got %v", got)
	}
}
