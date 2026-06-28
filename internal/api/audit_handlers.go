package api

import (
	"net/http"
	"strconv"

	"api-gateway/internal/audit"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"
)

// GET /api/audit?action=&limit=&all=true
//
// Returns the admin action trail for the caller's tenant, newest first. A
// super-admin may pass all=true to span every tenant. Scoped by the session
// tenant pinned in AdminAuth, so one tenant's operators never see another's
// audit trail.
func (h *handlers) getAudit(w http.ResponseWriter, r *http.Request) {
	if h.audit == nil {
		writeError(w, http.StatusServiceUnavailable,
			"admin audit log is disabled; set forensic_dsn (PostgreSQL) to enable it")
		return
	}

	f := audit.Filter{
		TenantID: tenant.From(r.Context()),
		Action:   r.URL.Query().Get("action"),
	}
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))

	// A super-admin can request the cross-tenant view explicitly.
	if iam.IsSuperAdmin(r.Context()) && r.URL.Query().Get("all") == "true" {
		f.TenantID = "*"
	}

	entries, err := h.audit.List(r.Context(), f)
	if err != nil {
		h.log.Error("admin: audit list failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch audit log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}
