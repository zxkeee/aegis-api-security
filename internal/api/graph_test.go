package api

import (
	"testing"

	"api-gateway/internal/discovery"
	"api-gateway/internal/store"
)

func TestFlagAbuseNodes(t *testing.T) {
	g := &discovery.Graph{Nodes: []discovery.GraphNode{
		{ID: "endpoint:GET /api/orders/{id}", Type: "endpoint", Label: "GET /api/orders/{id}"},
		{ID: "endpoint:GET /health", Type: "endpoint", Label: "GET /health"},
		{ID: "consumer:ip:1.2.3.4", Type: "consumer", Label: "1.2.3.4"},
		{ID: "consumer:jwt:bob@corp.com", Type: "consumer", Label: "bob@corp.com"},
	}}
	entries := []store.ForensicEntry{
		{Reason: "bola_object_ownership", Method: "GET", Path: "/api/orders/1001", Extra: map[string]any{"consumer": "bob@corp.com"}},
		{Reason: "bfla_privileged_access", Method: "GET", Path: "/api/orders/1002", Extra: map[string]any{"consumer": "ip:1.2.3.4"}},
		{Reason: "waf_blocked", Method: "GET", Path: "/api/orders/9999"}, // not abuse — must be ignored
	}
	flagAbuseNodes(g, entries)

	byID := map[string]discovery.GraphNode{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	if n := byID["endpoint:GET /api/orders/{id}"]; !n.Flagged || n.AbuseCount != 2 {
		t.Fatalf("orders endpoint: flagged=%v count=%d, want true/2", n.Flagged, n.AbuseCount)
	}
	if byID["endpoint:GET /health"].Flagged {
		t.Fatal("/health must not be flagged (no abuse, waf ignored)")
	}
	if !byID["consumer:jwt:bob@corp.com"].Flagged {
		t.Fatal("bob (jwt subject suffix) must be flagged")
	}
	if !byID["consumer:ip:1.2.3.4"].Flagged {
		t.Fatal("ip consumer (exact) must be flagged")
	}
}
