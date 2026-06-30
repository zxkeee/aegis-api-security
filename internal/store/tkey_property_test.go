package store

import (
	"math/rand"
	"strings"
	"testing"
)

// These property tests pin the core multi-tenant isolation invariant: the Redis
// key namespace of one tenant can never overlap another's. Isolation rests on
// tkey building "gw:t:<tenant>:<suffix>" AND tenant ids being constrained to a
// ':'-free charset (enforced in config.validateMultitenancy). Together they make
// the tenant segment of every key unambiguous.

const keyPrefix = "gw:t:"

// safeTenant generates a random tenant id from the validated charset
// ([A-Za-z0-9._-]) — the same set config accepts. Crucially it never contains
// ':' so the tenant boundary in a key stays unambiguous.
func safeTenant(r *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	n := 1 + r.Intn(20)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// arbitrarySuffix generates a key suffix that MAY contain ':' (suffixes embed
// IPs, endpoints, JTIs etc.). The isolation guarantee must hold despite this.
func arbitrarySuffix(r *rand.Rand) string {
	const alphabet = "abcdef0123456789:/.{}-_"
	n := r.Intn(30)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// recoverTenant extracts the tenant segment from a tkey output: everything
// between the "gw:t:" prefix and the next ':'. Correct precisely because a valid
// tenant id contains no ':'.
func recoverTenant(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, keyPrefix)
	if !ok {
		return "", false
	}
	i := strings.IndexByte(rest, ':')
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// TestTkey_TenantBoundaryUnambiguous: for any safe tenant and ANY suffix, the
// tenant recovered from the key equals the original. This is what guarantees no
// cross-tenant aliasing regardless of suffix content.
func TestTkey_TenantBoundaryUnambiguous(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		tnt := safeTenant(r)
		suffix := arbitrarySuffix(r)
		key := tkey(ctxFor(tnt), suffix)

		if !strings.HasPrefix(key, keyPrefix+tnt+":") {
			t.Fatalf("key %q not prefixed by tenant %q", key, tnt)
		}
		got, ok := recoverTenant(key)
		if !ok || got != tnt {
			t.Fatalf("recovered tenant %q (ok=%v) from key %q, want %q", got, ok, key, tnt)
		}
	}
}

// TestTkey_DistinctTenantsDisjoint: two distinct safe tenants never produce the
// same key, for any pair of suffixes — i.e. their keyspaces are disjoint.
func TestTkey_DistinctTenantsDisjoint(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 20000; i++ {
		t1, t2 := safeTenant(r), safeTenant(r)
		if t1 == t2 {
			continue
		}
		k1 := tkey(ctxFor(t1), arbitrarySuffix(r))
		k2 := tkey(ctxFor(t2), arbitrarySuffix(r))
		if k1 == k2 {
			t.Fatalf("distinct tenants %q/%q collided on key %q", t1, t2, k1)
		}
		// Neither key may fall inside the other's namespace prefix.
		if strings.HasPrefix(k1, keyPrefix+t2+":") || strings.HasPrefix(k2, keyPrefix+t1+":") {
			t.Fatalf("tenant namespace overlap: %q vs %q", k1, k2)
		}
	}
}

// TestTkey_Deterministic: the same tenant + suffix always maps to the same key.
func TestTkey_Deterministic(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 5000; i++ {
		tnt := safeTenant(r)
		suffix := arbitrarySuffix(r)
		// Separate calls (and separate contexts) must yield the same key.
		first := tkey(ctxFor(tnt), suffix)
		second := tkey(ctxFor(tnt), suffix)
		if first != second {
			t.Fatalf("tkey not deterministic for tenant %q suffix %q: %q vs %q", tnt, suffix, first, second)
		}
	}
}

// TestTkey_ColonInTenantWouldCollide documents WHY the config charset check
// exists: an unvalidated ':'-bearing tenant id breaks the boundary. tenant "a:x"
// + suffix "y" aliases tenant "a" + suffix "x:y". This input is unreachable in
// production precisely because validateMultitenancy rejects it.
func TestTkey_ColonInTenantWouldCollide(t *testing.T) {
	aliased := tkey(ctxFor("a:x"), "y")
	legit := tkey(ctxFor("a"), "x:y")
	if aliased != legit {
		t.Fatalf("expected the documented collision; got %q vs %q", aliased, legit)
	}
}
