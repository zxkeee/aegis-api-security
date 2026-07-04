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
	"api-gateway/internal/retention"
	"api-gateway/internal/sso"
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
	cfg, err := loadValidatedConfig(*cfgPath)
	if err != nil {
		panic("unsafe configuration: " + err.Error())
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

	// ── Retention sweep (bounds durable-table growth) ─────────────────────────
	// Needs PostgreSQL (the tables it prunes). Runs on a cancelable context tied
	// to shutdown so the periodic sweep drains cleanly.
	retentionCtx, stopRetention := context.WithCancel(context.Background())
	defer stopRetention()
	if cfg.Retention.Enabled && cfg.ForensicDSN != "" {
		rw, rerr := retention.New(cfg.ForensicDSN, cfg.Retention, log)
		if rerr != nil {
			log.Error("retention init failed (sweep disabled)", map[string]any{"error": rerr.Error()})
		} else {
			defer func() { _ = rw.Close() }()
			go rw.Run(retentionCtx)
			log.Info("retention sweep enabled", map[string]any{
				"interval":           cfg.Retention.Interval.String(),
				"forensic_days":      cfg.Retention.ForensicDays,
				"audit_days":         cfg.Retention.AuditDays,
				"consumer_idle_days": cfg.Retention.ConsumerIdleDays,
			})
		}
	}

	// ── OIDC single sign-on (admin console) ───────────────────────────────────
	// Discovery is a network call; bound it and fail startup loudly if SSO is
	// configured but the provider is unreachable — a half-configured SSO is worse
	// than an obvious boot failure. Requires the iam store (validated in config).
	var ssoAuth *sso.Authenticator
	if cfg.OIDC.Enabled {
		// SSO just-in-time provisions operators in the iam store, so it cannot
		// function without one. Config validation requires forensic_dsn, but if
		// the iam store failed to initialise at runtime (DB unreachable) we must
		// NOT enable SSO — otherwise the callback would have no user store. Leave
		// ssoAuth nil so the endpoints stay 404 rather than 500.
		if iamStore == nil {
			log.Error("OIDC SSO configured but the iam store is unavailable; SSO disabled", nil)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			ssoAuth, err = sso.New(ctx, cfg.OIDC)
			cancel()
			if err != nil {
				log.Error("failed to initialise OIDC SSO", map[string]any{"error": err.Error(), "issuer": cfg.OIDC.Issuer})
				os.Exit(1)
			}
			log.Info("OIDC SSO enabled", map[string]any{"issuer": cfg.OIDC.Issuer})
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
	// Pass a nil interface (not a typed-nil *sso.Authenticator) when SSO is off,
	// so the handlers' oidc != nil check works correctly.
	var ssoIface api.OIDCAuthenticator
	if ssoAuth != nil {
		ssoIface = ssoAuth
	}
	adminSrv := api.NewServer(st, log, cfg, gw, alerts, catalog, iamStore, auditStore, ssoIface)

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

	// The admin plane gets its own CORS policy when admin_cors is set; otherwise
	// it inherits security.cors (legacy behaviour). The console is same-origin,
	// so most deployments never need to set either for the admin plane.
	adminCORS := cfg.Security.CORS
	if cfg.AdminCORS != nil {
		adminCORS = *cfg.AdminCORS
	}
	adminHandler := middleware.Chain(adminSrv,
		middleware.RequestID(),       // outermost: stamp every request before anything else
		middleware.SecurityHeaders(), // must wrap AdminAuth so 401/403 responses carry CSP/HSTS
		// RateLimit must sit OUTSIDE AdminAuth: AdminAuth returns early on a failed
		// credential, so a limiter placed inside it would never see unauthenticated
		// brute-force / DDoS traffic — exactly what this limit is meant to absorb.
		middleware.RateLimit(adminRateLimit, "admin", log, st),
		middleware.AdminAuth(cfg, log, st, auditRec),
		middleware.CORS(adminCORS),
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

	// Stop the retention sweep BEFORE the deferred rw.Close() runs, so an
	// in-flight sweep is cancelled while its connection pool is still open
	// (cancel-then-close, not the reverse the defer order would give).
	stopRetention()

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

// loadValidatedConfig parses the config file and runs the SAME safety gate for
// both startup and hot-reload: config.Validate (rejects insecure combinations
// such as placeholder secrets, wildcard CORS with auth, non-HTTPS threat feeds)
// and middleware.InitTrustedProxies (re-parses trusted_proxies so RealIP
// resolution tracks the config). Hot-reload previously skipped both, which let
// an unsafe edit go live and silently ignored trusted_proxies changes — the
// setting every per-IP control depends on.
func loadValidatedConfig(path string) (config.GatewayConfig, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.GatewayConfig{}, err
	}
	if err := config.Validate(cfg); err != nil {
		return config.GatewayConfig{}, err
	}
	if err := middleware.InitTrustedProxies(cfg.TrustedProxies); err != nil {
		return config.GatewayConfig{}, err
	}
	return cfg, nil
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

		// The full startup gate (parse + Validate + trusted-proxy re-init) also
		// guards hot-reload: an edit that would be rejected at boot must not go
		// live either. On any error the previous configuration stays active.
		newCfg, err := loadValidatedConfig(absPath)
		if err != nil {
			log.Error("hot-reload: rejected, previous config stays active", map[string]any{"error": err.Error()})
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
		// Only the data-plane chain is swapped. The admin server (admin_listen,
		// admin_auth/secret, admin_cors, session TTL) is built once at startup —
		// changes to those fields need a restart.
		log.Info("hot-reload: success (data plane swapped; admin-plane settings need a restart)", map[string]any{
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
