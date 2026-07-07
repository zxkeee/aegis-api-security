package api

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"testing"
)

// TestStoreUnavailable_Classifies locks the 503-vs-500 decision: a backing-store
// outage (PostgreSQL/Redis down) must be classed unavailable (→ 503, retryable),
// while a genuine query/logic error must not (→ 500).
func TestStoreUnavailable_Classifies(t *testing.T) {
	unavailable := []struct {
		name string
		err  error
	}{
		{"driver bad conn", driver.ErrBadConn},
		{"sql conn done", sql.ErrConnDone},
		{"net op error", &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}},
		{"connection refused string", errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")},
		{"pg starting up", errors.New("pq: the database system is starting up")},
		{"wrapped bad conn", fmt.Errorf("query catalog: %w", driver.ErrBadConn)},
		{"connection reset", errors.New("read tcp: connection reset by peer")},
	}
	for _, tc := range unavailable {
		if !storeUnavailable(tc.err) {
			t.Errorf("%s: want unavailable=true, got false (%v)", tc.name, tc.err)
		}
	}

	available := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"not found", errors.New("endpoint not found")},
		{"scan mismatch", errors.New("sql: Scan error on column index 2: converting NULL to int")},
		{"constraint", errors.New("pq: duplicate key value violates unique constraint")},
	}
	for _, tc := range available {
		if storeUnavailable(tc.err) {
			t.Errorf("%s: want unavailable=false, got true (%v)", tc.name, tc.err)
		}
	}
}
