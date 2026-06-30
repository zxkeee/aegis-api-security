package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"api-gateway/internal/alert"
	"api-gateway/internal/api"
	"api-gateway/internal/audit"
	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
	"api-gateway/internal/gateway"
	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/store"
	"api-gateway/internal/tlsfp"

	"github.com/fsnotify/fsnotify"
)

// Build-time variables set via -ldflags
var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config/gateway.yaml", "path to gateway config")
	flag.Parse()

	// ── Load Configuration ────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	if err := config.Validate(cfg); err != nil {
		panic("unsafe configuration: " + err.Error())
	}

	// Pre-parse trusted proxy CIDRs once so RealIP() never does it per-request.
	if err := middleware.InitTrustedProxies(cfg.TrustedProxies); err != nil {
		panic("invalid trusted_proxies config: " + err.Error())
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	log := logger.New(cfg.Logging.Level)
	log.Info("AEGIS API Security Gateway starting", map[string]any{
		"listen":       cfg.Listen,
		"admin_listen": cfg.AdminListen,
		"version":      version,
		"commit":       commit,
		"build_time":   buildTime,
	})

	// ── Redis Store ───────────────────────────────────────────────────────────
	st, err := store.NewWithConfig(store.SentinelOptions{
		Addr:             cfg.Redis.Addr,
		Password:         cfg.Redis.Password,
		DB:               cfg.Redis.DB,
		MasterName:       cfg.Redis.Sentinel.MasterName,
		SentinelAddrs:    cfg.Redis.Sentinel.Addrs,
		SentinelPassword: cfg.Redis.Sentinel.SentinelPassword,
	})
	if err != nil {
		log.Error("failed to connect to Redis", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	// ── Alert Engine ──────────────────────────────────────────────────────────
	alerts := alert.NewWithConfig(cfg.Alerting.WebhookURL, cfg.Alerting.Format, cfg.Alerting.MinSeverity, log)
	if cfg.Alerting.WebhookURL != "" {
		log.Info("outbound alerting enabled", map[string]any{
			"format":       cfg.Alerting.Format,
			"min_severity": cfg.Alerting.MinSeverity,
		})
	}

	// ── Forensic Log Sink (PostgreSQL persistence) ──────────────────────────
	var fSink *forensic.PGSink
	if cfg.ForensicDSN != "" {
		fSink, err = forensic.NewPGSink(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("forensic sink init failed (falling back to Redis-only)", map[string]any{"error": err.Error()})
		} else {
			defer fSink.Close()
			st.SetForensicSink(fSink)
			log.Info("forensic log persistence enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── API Discovery Catalog (passive posture management) ──────────────────
	// Reuses the forensic PostgreSQL instance. When no DSN is configured the
	// catalog is nil and the Discovery middleware degrades to a passthrough.
	postureEng := discovery.NewPostureEngine(cfg)
	var catalog *discovery.Catalog
	if cfg.ForensicDSN != "" {
		catalog, err = discovery.NewCatalog(cfg.ForensicDSN, postureEng, log)
		if err != nil {
			log.Error("api catalog init failed (discovery disabled)", map[string]any{"error": err.Error()})
			catalog = nil
		} else {
			defer func() { _ = catalog.Close() }()
			log.Info("api discovery catalog enabled", map[string]any{"backend": "postgresql"})
			loadConfigSpec(cfg, catalog, log)
		}
	} else {
		log.Warn("forensic_dsn not set — API discovery catalog disabled")
	}

	// ── IAM (tenants + admin users) ──────────────────────────────────────────
	// Shares the forensic PostgreSQL instance. Without it, the console can only
	// log in with the legacy bearer secret (no per-tenant operators).
	var iamStore *iam.Store
	if cfg.ForensicDSN != "" {
		iamStore, err = iam.NewStore(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("iam store init failed (password login disabled)", map[string]any{"error": err.Error()})
			iamStore = nil
		} else {
			defer func() { _ = iamStore.Close() }()
			// First-boot bootstrap: if no users exist and AEGIS_ROOT_EMAIL +
			// AEGIS_ROOT_PASSWORD are set, create a super-admin so the operator
			// has a real account on day one without ever using the bearer secret.
			if email := os.Getenv("AEGIS_ROOT_EMAIL"); email != "" {
				if pw := os.Getenv("AEGIS_ROOT_PASSWORD"); pw != "" {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := iamStore.BootstrapRoot(ctx, "default", email, pw); err != nil {
						log.Error("iam root bootstrap failed", map[string]any{"error": err.Error()})
					}
					cancel()
				}
			}
			log.Info("iam store enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── Audit log (admin action trail) ────────────────────────────────────────
	// Shares the forensic PostgreSQL instance. Without it, admin actions are only
	// in the application log (not durable / queryable / tenant-scoped).
	var auditStore *audit.Store
	if cfg.ForensicDSN != "" {
		auditStore, err = audit.New(cfg.ForensicDSN, log)
		if err != nil {
			log.Error("audit store init failed (admin action trail disabled)", map[string]any{"error": err.Error()})
			auditStore = nil
		} else {
			defer func() { _ = auditStore.Close() }()
			log.Info("admin audit log enabled", map[string]any{"backend": "postgresql"})
		}
	}

	// ── Build Handler Chain ───────────────────────────────────────────────────
	var activeHandler atomic.Value
	handler, gw, err := gateway.BuildHandlerChain(cfg, log, st, catalog, postureEng)
	if err != nil {
		log.Error("failed to build handler chain", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	activeHandler.Store(handler)

	// ── Gateway Server (Hot Reload via atomic swap) ───────────────────────────
	// fpRegistry captures a real TLS fingerprint from each ClientHello when the
	// gateway terminates TLS, replacing the spoofable X-JA3-Fingerprint header.
	fpRegistry := tlsfp.NewRegistry()
	gwServer := &http.Server{
		Addr: cfg.Listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			activeHandler.Load().(http.Handler).ServeHTTP(w, r)
		}),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // ARCH: prevent slowloris
		MaxHeaderBytes:    1 << 20,         // 1MB max header
		ConnContext:       fpRegistry.ConnContext,
		ConnState:         fpRegistry.ConnState,
	}
	if cfg.TLS.Enabled {
		gwServer.TLSConfig = fpRegistry.TLSConfig(nil)
	}

	// ── Admin API Server ──────────────────────────────────────────────────────
	// Assign the audit recorder only for a real store, so a nil *audit.Store does
	// not become a non-nil interface holding a typed-nil pointer.
	var auditRec audit.Recorder
	if auditStore != nil {
		auditRec = auditStore
	}
	adminSrv := api.NewServer(st, log, cfg, gw, alerts, catalog, iamStore, auditStore)

	// FIX SEC: Protect admin API against brute force and DDoS
	adminRateLimit := config.RateLimitConfig{
		Enabled:    true,
		Requests:   5,
		Window:     time.Second,
		BurstLimit: 10,
	}

	if !cfg.AdminAuth {
		log.Warn("SECURITY WARNING: admin_auth is disabled — admin API is open to anyone", map[string]any{
			"admin_listen": cfg.AdminListen,
		})
	}

	if !cfg.TLS.Enabled {
		log.Warn("SECURITY WARNING: TLS is not terminated at the gateway — ensure a trusted upstream terminates TLS, or set tls.enabled (and require_tls) in production", nil)
	}

	// Identity-propagation signature: in JWKS mode the JWT secret is unset, so
	// backends only get a signed X-Gateway-Signature if a separate
	// propagation_secret is configured. Flag this loudly — without a signature,
	// the gatewayverify SDK on backends will reject every request.
	if cfg.Security.Auth.Enabled && cfg.Security.Auth.JWKSURL != "" && cfg.Security.Auth.PropagationSecret == "" {
		log.Warn("SECURITY WARNING: JWKS auth is on but auth.propagation_secret is empty — "+
			"backends will not receive X-Gateway-Signature and the gatewayverify SDK will reject every request. "+
			"Set AEGIS_PROPAGATION_SECRET to a strong random value", nil)
	}

	adminHandler := middleware.Chain(adminSrv,
		middleware.RequestID(),       // outermost: stamp every request before anything else
		middleware.SecurityHeaders(), // must wrap AdminAuth so 401/403 responses carry CSP/HSTS
		// RateLimit must sit OUTSIDE AdminAuth: AdminAuth returns early on a failed
		// credential, so a limiter placed inside it would never see unauthenticated
		// brute-force / DDoS traffic — exactly what this limit is meant to absorb.
		middleware.RateLimit(adminRateLimit, "admin", log, st),
		middleware.AdminAuth(cfg, log, st, auditRec),
		middleware.CORS(cfg.Security.CORS),
	)
	adminServer := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           adminHandler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// ── Hot Reload Watcher ────────────────────────────────────────────────────
	go watchConfigFile(*cfgPath, &activeHandler, log, st, catalog)

	// ── Start Servers ─────────────────────────────────────────────────────────
	go func() {
		if cfg.TLS.Enabled {
			log.Info("gateway listening (TLS terminated at gateway)", map[string]any{"addr": cfg.Listen})
			if err := gwServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Error("gateway server error", map[string]any{"error": err.Error()})
			}
			return
		}
		log.Info("gateway listening", map[string]any{"addr": cfg.Listen})
		if err := gwServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("gateway server error", map[string]any{"error": err.Error()})
		}
	}()

	go func() {
		log.Info("admin API listening", map[string]any{"addr": cfg.AdminListen})
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("admin server error", map[string]any{"error": err.Error()})
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────────
	// FIX SEC-5: Use Shutdown(ctx) with deadline to drain in-flight requests
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Info("shutdown signal received", map[string]any{"signal": sig.String()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully drain existing connections
	if err := gwServer.Shutdown(ctx); err != nil {
		log.Error("gateway shutdown error", map[string]any{"error": err.Error()})
	}
	if err := adminServer.Shutdown(ctx); err != nil {
		log.Error("admin shutdown error", map[string]any{"error": err.Error()})
	}

	log.Info("AEGIS gateway stopped gracefully")
}

// loadConfigSpec loads the optional config-level OpenAPI spec (discovery.
// spec_path) and installs it as the catalog's fallback for drift detection. A
// missing path clears the fallback; a read/parse error is logged and leaves the
// previous fallback in place rather than failing the gateway over a bad spec.
func loadConfigSpec(cfg config.GatewayConfig, catalog *discovery.Catalog, log *logger.Logger) {
	path := cfg.Discovery.SpecPath
	if path == "" {
		catalog.SetConfigSpec(nil)
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, not user input
	if err != nil {
		log.Error("discovery: spec_path read failed", map[string]any{"error": err.Error(), "path": path})
		return
	}
	spec, err := discovery.ParseSpec(raw)
	if err != nil {
		log.Error("discovery: spec_path parse failed", map[string]any{"error": err.Error(), "path": path})
		return
	}
	catalog.SetConfigSpec(spec)
	log.Info("discovery: config spec loaded", map[string]any{
		"path": path, "version": spec.Version, "operations": spec.OpCount(),
	})
}

// watchConfigFile uses fsnotify for instant config hot-reload (zero-downtime).
// Falls back to 5s polling if fsnotify setup fails.
func watchConfigFile(path string, activeHandler *atomic.Value, log *logger.Logger, st *store.Store, catalog *discovery.Catalog) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	reload := func() {
		log.Info("config change detected, hot-reloading...")

		newCfg, err := config.Load(absPath)
		if err != nil {
			log.Error("hot-reload: config parse error", map[string]any{"error": err.Error()})
			return
		}

		// Rebuild the posture engine from the new config; it is the authority for
		// both posture classification and the per-route enforcement gates, so the
		// chain and the catalog must share the same fresh instance.
		newPosture := discovery.NewPostureEngine(newCfg)

		newHandler, _, err := gateway.BuildHandlerChain(newCfg, log, st, catalog, newPosture)
		if err != nil {
			log.Error("hot-reload: chain build error", map[string]any{"error": err.Error()})
			return
		}

		// Re-classify future traffic against the new configuration.
		if catalog != nil {
			catalog.SetPostureEngine(newPosture)
			loadConfigSpec(newCfg, catalog, log)
		}

		activeHandler.Store(newHandler)
		log.Info("hot-reload: success", map[string]any{
			"routes": len(newCfg.Routes),
		})
	}

	// Try fsnotify for instant reload
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warn("fsnotify unavailable, falling back to polling", map[string]any{"error": err.Error()})
		pollConfigFile(absPath, reload)
		return
	}
	defer func() { _ = watcher.Close() }()

	// Watch the directory (handles atomic renames used by editors)
	dir := filepath.Dir(absPath)
	if err := watcher.Add(dir); err != nil {
		log.Warn("fsnotify watch failed, falling back to polling", map[string]any{"error": err.Error()})
		pollConfigFile(absPath, reload)
		return
	}

	log.Info("fsnotify: watching config for changes", map[string]any{"path": absPath})

	// Debounce: ignore rapid successive events
	var debounce *time.Timer

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Only react to writes/renames of our config file
			if filepath.Base(event.Name) != filepath.Base(absPath) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce 500ms to avoid rapid reloads
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(500*time.Millisecond, reload)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Error("fsnotify error", map[string]any{"error": err.Error()})
		}
	}
}

// pollConfigFile is the fallback watcher using 5s polling.
func pollConfigFile(path string, reload func()) {
	var lastMod time.Time
	if info, err := os.Stat(path); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.ModTime().After(lastMod) {
			lastMod = info.ModTime()
			reload()
		}
	}
}
