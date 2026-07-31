// Command aegis-site serves the AEGIS visiting-card static site and captures
// pilot-request form submissions to a JSONL file. Standard library only, so it
// builds to a single static binary and runs anywhere.
//
//	go run . -addr :8090
//	# then open http://localhost:8090
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	dir := flag.String("dir", ".", "directory of static site files")
	out := flag.String("out", "pilot-requests.jsonl", "file to append pilot requests to")
	flag.Parse()

	srv := &site{dir: *dir, out: *out, seen: map[string][]time.Time{}}
	if mc, ok := mailFromEnv(); ok {
		srv.mail = &mc
		log.Printf("email delivery enabled: %s -> %s via %s", mc.from, mc.to, mc.host)
	} else {
		log.Printf("email delivery disabled (set SMTP_USER, SMTP_PASS, MAIL_TO to enable); submissions saved to file only")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/pilot", srv.pilot)
	mux.Handle("/", srv.static())

	s := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf("aegis-site listening on %s (serving %q, capturing to %q)", *addr, *dir, *out)
	log.Fatal(s.ListenAndServe())
}

type site struct {
	dir  string
	out  string
	mail *mailCfg
	mu   sync.Mutex
	seen map[string][]time.Time // per-IP submit timestamps (rate limit)
}

// mailCfg holds SMTP delivery settings, all sourced from the environment so no
// secret ever lives in code or the image.
type mailCfg struct {
	host, port, user, pass, from, to string
}

func mailFromEnv() (mailCfg, bool) {
	c := mailCfg{
		host: envOr("SMTP_HOST", "smtp.gmail.com"),
		port: envOr("SMTP_PORT", "587"),
		user: os.Getenv("SMTP_USER"),
		pass: os.Getenv("SMTP_PASS"),
		to:   os.Getenv("MAIL_TO"),
	}
	c.from = envOr("MAIL_FROM", c.user)
	if c.user == "" || c.pass == "" || c.to == "" {
		return c, false
	}
	return c, true
}

// send delivers one submission as a plain-text email. Header fields are stripped
// of CR/LF to prevent SMTP header injection via the user-supplied email address.
func (c *mailCfg) send(rec pilotRecord) error {
	subject := hdr("New AEGIS pilot request — " + firstNonEmpty(rec.Company, rec.Name))
	body := fmt.Sprintf(
		"Name:    %s\r\nEmail:   %s\r\nCompany: %s\r\nTraffic: %s\r\n\r\n%s\r\n\r\n—\r\nreceived %s · ip %s\r\nua %s\r\n",
		rec.Name, rec.Email, rec.Company, rec.Scale, rec.Message, rec.At, rec.IP, rec.UA)
	msg := "From: AEGIS site <" + hdr(c.from) + ">\r\n" +
		"To: " + hdr(c.to) + "\r\n" +
		"Reply-To: " + hdr(rec.Email) + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	auth := smtp.PlainAuth("", c.user, c.pass, c.host)
	return smtp.SendMail(c.host+":"+c.port, auth, c.from, []string{c.to}, []byte(msg))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// hdr strips characters that could break out of an email header / log line.
func hdr(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

// static serves the site files but never lists directories.
func (s *site) static() http.Handler {
	fs := http.FileServer(http.Dir(s.dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
}

type pilotReq struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Scale   string `json:"scale"`
	Message string `json:"message"`
}

type pilotRecord struct {
	pilotReq
	At string `json:"at"`
	IP string `json:"ip"`
	UA string `json:"ua"`
}

func (s *site) pilot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !s.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "rate limited"})
		return
	}

	var req pilotReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if req.Name == "" || !strings.Contains(req.Email, "@") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "name and a valid email are required"})
		return
	}
	// Cap field sizes so a bad actor can't bloat the capture file.
	req.Name = clip(req.Name, 200)
	req.Email = clip(req.Email, 200)
	req.Company = clip(strings.TrimSpace(req.Company), 200)
	req.Scale = clip(strings.TrimSpace(req.Scale), 60)
	req.Message = clip(strings.TrimSpace(req.Message), 4000)

	rec := pilotRecord{pilotReq: req, At: time.Now().UTC().Format(time.RFC3339), IP: ip, UA: clip(r.UserAgent(), 300)}
	if err := s.append(rec); err != nil {
		log.Printf("pilot: append failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "could not save"})
		return
	}
	// Email delivery is best-effort and async: the file save already succeeded,
	// so a slow/failed SMTP never blocks or fails the visitor's request.
	if s.mail != nil {
		go func(m *mailCfg, rec pilotRecord) {
			if err := m.send(rec); err != nil {
				log.Printf("pilot: email send failed (saved to file): %v", err)
			}
		}(s.mail, rec)
	}
	log.Printf("pilot request: %s <%s> company=%q ip=%s", hdr(rec.Name), hdr(rec.Email), hdr(rec.Company), ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *site) append(rec pilotRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(line, '\n'))
	return err
}

// allow permits at most 5 submissions per IP per 10 minutes.
func (s *site) allow(ip string) bool {
	const limit, window = 5, 10 * time.Minute
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []time.Time
	for _, t := range s.seen[ip] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		s.seen[ip] = kept
		return false
	}
	s.seen[ip] = append(kept, now)
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	// Behind Cloudflare the true client is CF-Connecting-IP, which the visitor
	// cannot forge (Cloudflare overwrites it). Prefer it so the rate limiter
	// can't be bypassed by sending a fake X-Forwarded-For.
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
