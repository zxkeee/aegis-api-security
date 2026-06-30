// Package secevent defines the security-event record shared across layers
// (middleware that produces events, the Redis ring buffer, the PostgreSQL
// forensic sink). It is a dependency-free leaf so the HTTP/middleware layer can
// emit forensic entries without importing the concrete store package — keeping
// the middleware → store dependency edge out of the graph (audit finding F2).
package secevent

import "time"

// Entry represents a single security event for the forensic/audit trail.
type Entry struct {
	Tenant    string         `json:"tenant,omitempty"`
	Timestamp time.Time      `json:"ts"`
	IP        string         `json:"ip"`
	Path      string         `json:"path"`
	Method    string         `json:"method"`
	Reason    string         `json:"reason"`
	Code      int            `json:"code"`
	Extra     map[string]any `json:"extra,omitempty"`
}
