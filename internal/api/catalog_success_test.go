package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// seededCatalogHandlers builds *handlers backed by a live PostgreSQL catalog
// seeded with a few observations, so the catalog GET handlers run their full
// success path (query → JSON/CSV) rather than only the nil-catalog guard covered
// elsewhere. Skips without POSTGRES_DSN.
func seededCatalogHandlers(t *testing.T) *handlers {
	t.Helper()
	dsn := pgDSN(t) // schema-isolated "test_api"; skips without POSTGRES_DSN
	eng := discovery.NewPostureEngine(config.GatewayConfig{})

	// Seed via one catalog instance, then Close to flush the window to PG.
	seed, err := discovery.NewCatalog(dsn, eng, logger.New("error"))
	if err != nil {
		t.Fatalf("NewCatalog (seed): %v", err)
	}
	seed.Record(discovery.Observation{Method: "GET", Path: "/orders/1", Status: 200, AuthPresent: true, ConsumerSubject: "u1", LatencyMs: 5})
	seed.Record(discovery.Observation{Method: "GET", Path: "/orders/2", Status: 200, AuthPresent: true, ConsumerSubject: "u1", LatencyMs: 7})
	// An anonymous response leaking PII — produces a finding for the findings
	// view and drives the risk/posture paths.
	seed.Record(discovery.Observation{Method: "GET", Path: "/cards/9", Status: 200, AuthPresent: false, PII: true, PIITypes: []string{"credit_card"}, ConsumerIP: "9.9.9.9", LatencyMs: 3})
	if err := seed.Close(); err != nil {
		t.Fatalf("seed Close (flush): %v", err)
	}

	// A second catalog instance backs the handlers (reads what was persisted).
	cat, err := discovery.NewCatalog(dsn, eng, logger.New("error"))
	if err != nil {
		t.Fatalf("NewCatalog (read): %v", err)
	}
	t.Cleanup(func() { _ = cat.Close() })

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.IncrMetric(context.Background(), "waf_blocked")
	st.IncrMetric(context.Background(), "requests_passed_waf")

	return &handlers{store: st, log: logger.New("error"), cfg: config.GatewayConfig{}, catalog: cat}
}

func TestCatalogHandlers_SuccessPaths(t *testing.T) {
	h := seededCatalogHandlers(t)

	rec, body := callGet(h.getCatalog, "/api/catalog", nil)
	if rec.Code != http.StatusOK || body["count"].(float64) < 2 {
		t.Fatalf("catalog list = %d %v", rec.Code, body)
	}
	// Filtered variant.
	if rec, _ := callGet(h.getCatalog, "/api/catalog?q=orders&risk=0&limit=10", nil); rec.Code != http.StatusOK {
		t.Fatalf("filtered catalog = %d", rec.Code)
	}

	// By-id: pull a real id from the list (it contains a space and slashes, so it
	// is passed via SetPathValue, not the URL).
	id := body["endpoints"].([]any)[0].(map[string]any)["id"].(string)
	if rec, ep := callGet(h.getCatalogEndpoint, "/api/catalog/x", map[string]string{"id": id}); rec.Code != http.StatusOK || ep["endpoint"] == nil {
		t.Fatalf("get endpoint %q = %d %v", id, rec.Code, ep)
	}
	if rec, _ := callGet(h.getCatalogEndpoint, "/api/catalog/x", map[string]string{"id": "GET no-such"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", rec.Code)
	}

	if rec, cb := callGet(h.getConsumers, "/api/consumers?limit=50", nil); rec.Code != http.StatusOK || cb["count"].(float64) < 1 {
		t.Fatalf("consumers = %d %v", rec.Code, cb)
	}
	if rec, _ := callGet(h.getPostureSummary, "/api/posture/summary", nil); rec.Code != http.StatusOK {
		t.Fatalf("posture summary = %d", rec.Code)
	}

	// Effectiveness carries coverage_pct only when a catalog is present.
	if rec, eb := callGet(h.getEffectiveness, "/api/effectiveness", nil); rec.Code != http.StatusOK {
		t.Fatalf("effectiveness = %d", rec.Code)
	} else if _, ok := eb["coverage_pct"]; !ok {
		t.Fatal("effectiveness should carry coverage_pct when a catalog is present")
	}

	if rec, fb := callGet(h.getFindings, "/api/findings", nil); rec.Code != http.StatusOK || fb["count"].(float64) < 1 {
		t.Fatalf("findings = %d %v (want >=1 for the anon PII endpoint)", rec.Code, fb)
	}
	if rec, rb := callGet(h.getReport, "/api/report", nil); rec.Code != http.StatusOK || rb["endpoints"] == nil {
		t.Fatalf("report json = %d %v", rec.Code, rb)
	}

	// CSV report path.
	recCSV, _ := callGet(h.getReport, "/api/report?format=csv", nil)
	if recCSV.Code != http.StatusOK || !strings.HasPrefix(recCSV.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("report csv = %d %q", recCSV.Code, recCSV.Header().Get("Content-Type"))
	}
	if !strings.Contains(recCSV.Body.String(), "method,path_template,posture") {
		t.Fatal("csv header missing")
	}
}
