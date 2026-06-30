package iam

import (
	"context"
	"testing"
)

func TestIAM_TenantCRUD(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()

	if err := s.CreateTenant(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("CreateTenant acme: %v", err)
	}
	if err := s.CreateTenant(ctx, "globex", "Globex"); err != nil {
		t.Fatalf("CreateTenant globex: %v", err)
	}

	tenants, err := s.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("ListTenants returned %d, want 2", len(tenants))
	}

	ok, err := s.DeleteTenant(ctx, "globex")
	if err != nil || !ok {
		t.Fatalf("DeleteTenant globex: ok=%v err=%v", ok, err)
	}
	// Deleting a non-existent tenant reports ok=false, not an error.
	ok, err = s.DeleteTenant(ctx, "ghost")
	if err != nil || ok {
		t.Fatalf("DeleteTenant ghost: ok=%v err=%v (want false,nil)", ok, err)
	}

	if tenants, _ := s.ListTenants(ctx); len(tenants) != 1 {
		t.Errorf("after delete ListTenants = %d, want 1", len(tenants))
	}
}

func TestIAM_UserListAndDelete(t *testing.T) {
	s := freshIAM(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := s.CreateTenant(ctx, "globex", "Globex"); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	for _, u := range []User{
		{ID: "u1", TenantID: "acme", Email: "a@acme.io", Role: RoleAdmin},
		{ID: "u2", TenantID: "acme", Email: "b@acme.io", Role: RoleViewer},
		{ID: "u3", TenantID: "globex", Email: "c@globex.io", Role: RoleAdmin},
	} {
		if err := s.CreateUser(ctx, u, "correct-horse-battery"); err != nil {
			t.Fatalf("CreateUser %s: %v", u.ID, err)
		}
	}

	// ListUsers is tenant-scoped.
	acme, err := s.ListUsers(ctx, "acme")
	if err != nil {
		t.Fatalf("ListUsers acme: %v", err)
	}
	if len(acme) != 2 {
		t.Errorf("acme users = %d, want 2", len(acme))
	}
	if globex, _ := s.ListUsers(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex users = %d, want 1", len(globex))
	}

	ok, err := s.DeleteUser(ctx, "u2")
	if err != nil || !ok {
		t.Fatalf("DeleteUser u2: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.DeleteUser(ctx, "ghost"); ok {
		t.Error("DeleteUser ghost should report ok=false")
	}
	if acme, _ := s.ListUsers(ctx, "acme"); len(acme) != 1 {
		t.Errorf("after delete acme users = %d, want 1", len(acme))
	}
}

func TestIAM_UserIDContext(t *testing.T) {
	ctx := WithUserID(context.Background(), "user-42")
	if got := UserID(ctx); got != "user-42" {
		t.Errorf("UserID = %q, want user-42", got)
	}
	if got := UserID(context.Background()); got != "" {
		t.Errorf("UserID on bare context = %q, want empty", got)
	}
}
