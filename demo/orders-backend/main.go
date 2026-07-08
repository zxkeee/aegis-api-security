// orders-backend — a deliberately VULNERABLE demo API for the IDOR walkthrough.
//
// GET /api/orders/{id} returns the order to ANY authenticated caller without
// checking that the caller owns it — the classic BOLA / IDOR bug that a
// signature WAF cannot see. AEGIS sits in front and catches the leak by reading
// the owner (user_id) out of this response. Demo only; never ship this.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":19000", "listen address")
	flag.Parse()

	// Pre-seeded orders keyed by order id -> owner's numeric user id. Order 1001
	// belongs to user 7 (alice), 1002 to user 9 (bob). The owner is a numeric id,
	// deliberately unlike the JWT subject (an email) — the realistic case.
	owners := map[string]string{"1001": "7", "1002": "9"}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /api/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		owner, ok := owners[id]
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		// VULNERABLE: hands back the order regardless of who is asking.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "user_id": owner, "item": "Widget", "total": 42.00,
		})
	})
	log.Printf("orders-backend (vulnerable demo) listening on %s", *addr)
	_ = http.ListenAndServe(*addr, mux) // #nosec G114 -- demo backend, not production
}
