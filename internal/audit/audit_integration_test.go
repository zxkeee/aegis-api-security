package audit

import (
	"context"
	"os"
	"testing"
	"time"
)

type nopLogger struct{}

func (nopLogger) Info(string, ...map[string]any)  {}
func (nopLogger) Error(string, ...map[string]any) {}

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set; skipping audit PostgreSQL integration test")
	}
	s, err := New(dsn, nopLogger{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, _ = s.db.Exec(`TRUNCATE admin_audit_log`)
	return s
}

// waitFor polls List until it returns at least n entries for the filter, or fails.
func waitFor(t *testing.T, s *Store, f Filter, n int) []Entry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := s.List(context.Background(), f)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d entries, got %d", n, len(got))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAudit_RecordListAndTenantScope(t *testing.T) {
	s := testStore(t)

	s.Record(Entry{TenantID: "acme", ActorEmail: "a@acme", Role: "admin", Action: "login", Status: 200})
	s.Record(Entry{TenantID: "acme", ActorEmail: "a@acme", Role: "admin", Action: "mutation", Method: "POST", Path: "/api/users", Status: 201})
	s.Record(Entry{TenantID: "globex", ActorEmail: "b@globex", Role: "admin", Action: "mutation", Method: "DELETE", Path: "/api/x", Status: 200})

	// acme sees only its own two entries.
	acme := waitFor(t, s, Filter{TenantID: "acme"}, 2)
	if len(acme) != 2 {
		t.Fatalf("acme entries = %d, want 2", len(acme))
	}
	for _, e := range acme {
		if e.TenantID != "acme" {
			t.Errorf("cross-tenant leak: acme query returned %q", e.TenantID)
		}
	}

	// Newest first.
	if acme[0].Action != "mutation" {
		t.Errorf("expected newest (mutation) first, got %q", acme[0].Action)
	}

	// globex isolated.
	globex := waitFor(t, s, Filter{TenantID: "globex"}, 1)
	if len(globex) != 1 || globex[0].ActorEmail != "b@globex" {
		t.Fatalf("globex isolation wrong: %+v", globex)
	}

	// Action filter.
	muts, err := s.List(context.Background(), Filter{TenantID: "acme", Action: "mutation"})
	if err != nil || len(muts) != 1 || muts[0].Action != "mutation" {
		t.Fatalf("action filter wrong: %+v err=%v", muts, err)
	}

	// Super-admin span ("*") sees all three.
	all := waitFor(t, s, Filter{TenantID: "*"}, 3)
	if len(all) != 3 {
		t.Fatalf("super-admin span = %d, want 3", len(all))
	}
}
