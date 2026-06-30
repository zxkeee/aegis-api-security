package config

import (
	"math/rand"
	"strings"
	"testing"
)

// TestValidateMultitenancy_RejectsUnsafeTenantID covers the isolation-critical
// charset rule: ids carrying ':' (or other unsafe chars) must be rejected, since
// they could alias another tenant's Redis keyspace.
func TestValidateMultitenancy_RejectsUnsafeTenantID(t *testing.T) {
	bad := []string{"a:x", "ten ant", "a/b", "té", "a\tb", strings.Repeat("x", 65), ""}
	for _, id := range bad {
		cfg := GatewayConfig{
			Multitenancy: MultitenancyConfig{
				Enabled: true,
				Tenants: []TenantConfig{{ID: id}},
			},
		}
		if err := validateMultitenancy(cfg); err == nil {
			t.Errorf("tenant id %q should be rejected", id)
		}
	}
}

func TestValidateMultitenancy_AcceptsSafeTenantID(t *testing.T) {
	good := []string{"acme", "acme-corp", "acme_corp", "tenant.1", "T-123", strings.Repeat("a", 64)}
	for _, id := range good {
		cfg := GatewayConfig{
			Multitenancy: MultitenancyConfig{
				Enabled: true,
				Tenants: []TenantConfig{{ID: id}},
			},
			Routes: []RouteConfig{{Path: "/", TenantID: id, Upstreams: []string{"http://u"}}},
		}
		if err := validateMultitenancy(cfg); err != nil {
			t.Errorf("tenant id %q should be accepted, got: %v", id, err)
		}
	}
}

// TestTenantIDPattern_NoColonAccepted is a property check: any string the
// validator accepts is guaranteed ':'-free, which is exactly the precondition
// tkey isolation relies on.
func TestTenantIDPattern_NoColonAccepted(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	const alphabet = "abcXYZ012:._-/ \t" // includes unsafe chars on purpose
	for i := 0; i < 50000; i++ {
		n := r.Intn(70)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		s := string(b)
		if tenantIDPattern.MatchString(s) && strings.ContainsRune(s, ':') {
			t.Fatalf("accepted tenant id %q contains ':' — isolation precondition violated", s)
		}
	}
}
