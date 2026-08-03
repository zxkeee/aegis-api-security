package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/config"
)

// ServiceAuth validates HMAC signatures for service-to-service communication.
func ServiceAuth(cfg config.RegistryConfig, log Logger, st DenySink, reg RegistryProvider) Middleware {
	if !cfg.Enabled {
		return passthrough
	}
	freshness := time.Duration(cfg.SignatureFreshnessSecs) * time.Second

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serviceID := r.Header.Get("X-Service-ID")
			signature := r.Header.Get("X-Service-Signature")

			if serviceID == "" || signature == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Freshness — reject a stale/replayed timestamp before doing any
			// crypto or registry lookup, mirroring sdk/gatewayverify's Verify
			// (the analogous gateway->backend identity signature). Without
			// this a captured (X-Service-ID, X-Service-Signature, X-Timestamp)
			// triple would be valid to replay indefinitely.
			ts := r.Header.Get("X-Timestamp")
			secs, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				SecurityDeny(w, r, log, st, "service_bad_timestamp", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}
			if skew := time.Since(time.Unix(secs, 0)); skew > freshness || skew < -freshness {
				SecurityDeny(w, r, log, st, "service_stale_signature", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}

			// Lookup service secret
			secret, ok, err := reg.LookupService(r.Context(), serviceID)
			if err != nil {
				log.Error("service_auth: registry error", map[string]any{"error": err.Error()})
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if !ok {
				SecurityDeny(w, r, log, st, "service_unknown", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}

			// Verify HMAC
			payload := strings.Join([]string{
				r.Method,
				r.URL.Path,
				ts,
			}, "\n")

			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			expected := hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(signature), []byte(expected)) {
				SecurityDeny(w, r, log, st, "service_bad_signature", RealIP(r), http.StatusForbidden,
					map[string]any{"service_id": serviceID})
				return
			}

			// Check service-specific rate limits
			allowed, err := reg.CheckRateLimit(r.Context(), serviceID, config.RateLimitConfig{})
			if err != nil {
				log.Error("service_auth: rate limit error", map[string]any{"error": err.Error()})
			}
			if !allowed {
				SecurityDeny(w, r, log, st, "service_rate_exceeded", RealIP(r), http.StatusTooManyRequests,
					map[string]any{"service_id": serviceID})
				return
			}

			r.Header.Set("X-Gateway-Service", serviceID)
			next.ServeHTTP(w, r)
		})
	}
}
