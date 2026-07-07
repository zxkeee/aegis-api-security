//go:build ignore

// pg_outage_loadgen — constant-rate load with a mid-run PostgreSQL outage.
//
// Companion to redis_outage_loadgen.go, for the *PostgreSQL*-unavailable case
// (RELEASE-CHECKLIST "graceful failure under load"). PostgreSQL backs the
// discovery catalog and the forensic sink, both of which are written OFF the
// request path (async catalog worker + batched forensic logger, falling back to
// the Redis ring buffer). The hypothesis this run tests: killing PostgreSQL must
// NOT degrade the data plane — request success and latency stay flat — while the
// admin catalog read (served from PG) degrades to 503 and recovers on its own.
//
// It drives two concurrent streams:
//   - data plane: constant rate to <url>, success/latency bucketed pre/outage/recovery.
//   - admin probe: 1/s GET <admin>/api/catalog with the bearer, status bucketed.
//
// Run (file named explicitly so the //go:build ignore tag is bypassed):
//
//	AEGIS_ADMIN_SECRET=<secret> go run tests/load/pg_outage_loadgen.go \
//	  -url http://127.0.0.1:18080/get -admin http://127.0.0.1:18081 \
//	  -pg aegis-lt-pg -rate 100 -dur 90 -outage_start 45 -outage_end 65
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"
)

type sample struct {
	elapsed time.Duration
	latency time.Duration
	ok      bool
}

func main() {
	url := flag.String("url", "http://127.0.0.1:18080/get", "data-plane target")
	admin := flag.String("admin", "http://127.0.0.1:18081", "admin base URL")
	rate := flag.Int("rate", 100, "requests per second (data plane)")
	dur := flag.Int("dur", 90, "duration seconds")
	container := flag.String("pg", "aegis-lt-pg", "postgres container to stop/start")
	outStart := flag.Int("outage_start", 45, "seconds into run to stop postgres")
	outEnd := flag.Int("outage_end", 65, "seconds into run to start postgres")
	flag.Parse()

	secret := os.Getenv("AEGIS_ADMIN_SECRET")
	client := &http.Client{Timeout: 10 * time.Second}
	var mu sync.Mutex
	var samples []sample
	var wg sync.WaitGroup

	start := time.Now()

	// Outage orchestration — timed to line up exactly with the latency buckets.
	go func() {
		time.Sleep(time.Duration(*outStart) * time.Second)
		_ = exec.Command("docker", "stop", *container).Run() // #nosec G204 -- load-test tool; container is an operator-supplied flag
		fmt.Printf("[t=%ds] postgres STOPPED\n", *outStart)
	}()
	go func() {
		time.Sleep(time.Duration(*outEnd) * time.Second)
		_ = exec.Command("docker", "start", *container).Run() // #nosec G204 -- load-test tool; container is an operator-supplied flag
		fmt.Printf("[t=%ds] postgres STARTED\n", *outEnd)
	}()

	// Admin-plane probe: shows the catalog read (served from PG) degrading during
	// the outage. One request per second, labelled by phase.
	go func() {
		for i := 0; i < *dur; i++ {
			time.Sleep(time.Second)
			elapsed := time.Since(start).Seconds()
			phase := "PRE"
			if elapsed >= float64(*outStart) && elapsed < float64(*outEnd) {
				phase = "OUTAGE"
			} else if elapsed >= float64(*outEnd) {
				phase = "RECOV"
			}
			req, _ := http.NewRequest(http.MethodGet, *admin+"/api/catalog", nil)
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			code := "ERR"
			if resp, err := client.Do(req); err == nil {
				code = fmt.Sprintf("%d", resp.StatusCode)
				_ = resp.Body.Close()
			}
			fmt.Printf("  admin /api/catalog [%-6s t=%2.0fs] -> %s\n", phase, elapsed, code)
		}
	}()

	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()
	deadline := start.Add(time.Duration(*dur) * time.Second)
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
			ok := err == nil && resp != nil && resp.StatusCode == 200
			if resp != nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			samples = append(samples, sample{elapsed, lat, ok})
			mu.Unlock()
		}()
	}
	wg.Wait()

	fmt.Println()
	report(fmt.Sprintf("PRE   (0-%ds, pg up)", *outStart), samples, func(e float64) bool { return e < float64(*outStart) })
	report(fmt.Sprintf("OUTAGE(%d-%ds, pg DOWN)", *outStart, *outEnd), samples, func(e float64) bool {
		return e >= float64(*outStart) && e < float64(*outEnd)
	})
	report(fmt.Sprintf("RECOV (%d-%ds, pg up)", *outEnd, *dur), samples, func(e float64) bool { return e >= float64(*outEnd) })
}

func report(label string, all []sample, in func(float64) bool) {
	var lats []time.Duration
	ok := 0
	for _, s := range all {
		if !in(s.elapsed.Seconds()) {
			continue
		}
		lats = append(lats, s.latency)
		if s.ok {
			ok++
		}
	}
	n := len(lats)
	if n == 0 {
		fmt.Printf("%-26s no samples\n", label)
		return
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) time.Duration { return lats[int(float64(n-1)*p)] }
	fmt.Printf("%-26s n=%-5d ok=%5.1f%%  p50=%-7v p95=%-7v p99=%-7v max=%-7v\n",
		label, n, 100*float64(ok)/float64(n),
		pct(0.50).Round(time.Millisecond), pct(0.95).Round(time.Millisecond),
		pct(0.99).Round(time.Millisecond), pct(1.0).Round(time.Millisecond))
}
