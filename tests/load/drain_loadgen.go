//go:build ignore

// drain_loadgen — sustained traffic through a graceful SIGTERM (rolling-update
// drain). Validates the RELEASE-CHECKLIST "zero-5xx during Shutdown(ctx) under
// sustained traffic" item: a request that the gateway has accepted must finish
// with its real upstream status, never a 5xx caused by the server tearing down
// mid-flight. New connections arriving after the listener closes get a
// connection error (expected — in a real rolling update the load balancer drains
// the target first); those are reported separately and must not be counted as
// server errors.
//
// At -signal_at seconds it sends SIGTERM to the pid in -pidfile, then keeps
// driving traffic to -until seconds so the drain window is measured. Each
// response is classed ok (2xx/3xx/4xx from upstream) / server_error (5xx) /
// conn_error (refused/reset/timeout).
//
// Run (file named explicitly so the //go:build ignore tag is bypassed):
//
//	go run tests/load/drain_loadgen.go -url http://127.0.0.1:18080/get \
//	  -pidfile /path/to/gateway.pid -rate 100 -signal_at 8 -until 20
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type drainSample struct {
	elapsed time.Duration
	latency time.Duration
	class   string // "ok" | "server_error" | "conn_error"
}

func main() {
	url := flag.String("url", "http://127.0.0.1:18080/get", "data-plane target")
	pidfile := flag.String("pidfile", "", "file holding the gateway pid to SIGTERM")
	rate := flag.Int("rate", 100, "requests per second")
	signalAt := flag.Int("signal_at", 8, "seconds into run to send SIGTERM")
	until := flag.Int("until", 20, "total run seconds (must exceed signal_at)")
	flag.Parse()

	// Client with a bounded per-request timeout; keep-alive on so we exercise the
	// realistic case where Shutdown closes idle pooled connections.
	client := &http.Client{Timeout: 8 * time.Second}

	var mu sync.Mutex
	var samples []drainSample
	var wg sync.WaitGroup
	var signalled int64

	start := time.Now()

	go func() {
		time.Sleep(time.Duration(*signalAt) * time.Second)
		pid := readPid(*pidfile)
		if pid <= 0 {
			fmt.Printf("[t=%ds] NO valid pid in %q — skipping SIGTERM\n", *signalAt, *pidfile)
			return
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			fmt.Printf("[t=%ds] SIGTERM pid %d failed: %v\n", *signalAt, pid, err)
			return
		}
		atomic.StoreInt64(&signalled, 1)
		fmt.Printf("[t=%ds] SIGTERM sent to gateway pid %d\n", *signalAt, pid)
	}()

	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()
	deadline := start.Add(time.Duration(*until) * time.Second)
	for now := range ticker.C {
		if now.After(deadline) {
			break
		}
		elapsed := now.Sub(start)
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			resp, err := client.Get(*url)
			lat := time.Since(t0)
			class := "ok"
			switch {
			case err != nil:
				class = "conn_error"
			case resp.StatusCode >= 500:
				class = "server_error"
			}
			if resp != nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			samples = append(samples, drainSample{elapsed, lat, class})
			mu.Unlock()
		}()
	}
	wg.Wait()

	sig := atomic.LoadInt64(&signalled) == 1
	fmt.Printf("\nSIGTERM delivered: %v\n\n", sig)
	report("PRE   (before SIGTERM)", samples, float64(*signalAt), func(e, s float64) bool { return e < s })
	report("DRAIN (after SIGTERM) ", samples, float64(*signalAt), func(e, s float64) bool { return e >= s })

	// Gate: any 5xx at all fails the drain assertion.
	serverErrors := 0
	for _, s := range samples {
		if s.class == "server_error" {
			serverErrors++
		}
	}
	fmt.Println()
	if serverErrors == 0 {
		fmt.Println("PASS: zero 5xx across the whole run — no request was errored by the shutdown.")
	} else {
		fmt.Printf("FAIL: %d server_error (5xx) responses — the drain is not clean.\n", serverErrors)
		os.Exit(1)
	}
}

func readPid(path string) int {
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path) // #nosec G304 -- load-test tool; path is an operator-supplied flag
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func report(label string, all []drainSample, split float64, in func(e, s float64) bool) {
	var lats []time.Duration
	var ok, srv, cerr int
	for _, s := range all {
		if !in(s.elapsed.Seconds(), split) {
			continue
		}
		lats = append(lats, s.latency)
		switch s.class {
		case "ok":
			ok++
		case "server_error":
			srv++
		case "conn_error":
			cerr++
		}
	}
	n := len(lats)
	if n == 0 {
		fmt.Printf("%-24s no samples\n", label)
		return
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration { return lats[int(float64(n-1)*p)] }
	fmt.Printf("%-24s n=%-5d ok=%-5d 5xx=%-4d conn_err=%-4d  p50=%-7v p99=%-7v max=%-7v\n",
		label, n, ok, srv, cerr,
		pct(0.50).Round(time.Millisecond), pct(0.99).Round(time.Millisecond), pct(1.0).Round(time.Millisecond))
}
