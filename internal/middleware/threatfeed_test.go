package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestIsPrivateOrLocalHost(t *testing.T) {
	blocked := []string{
		"localhost", "LocalHost",
		"127.0.0.1", "::1",
		"10.0.0.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", // cloud metadata (link-local)
		"0.0.0.0",
	}
	for _, h := range blocked {
		if !isPrivateOrLocalHost(h) {
			t.Errorf("host %q should be treated as private/local", h)
		}
	}
	allowed := []string{"93.184.216.34", "8.8.8.8", "feeds.example.com", "example.org"}
	for _, h := range allowed {
		if isPrivateOrLocalHost(h) {
			t.Errorf("host %q should be allowed", h)
		}
	}
}

// checkFeedRedirect is the actual policy used by threatFeed.refresh.
func TestCheckFeedRedirect(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	cases := []struct {
		target  string
		blocked bool
	}{
		{"https://feeds.example.com/list.txt", false},
		{"https://169.254.169.254/latest/meta-data/", true}, // cloud metadata
		{"https://127.0.0.1/x", true},                       // loopback
		{"https://localhost/x", true},                       // localhost
		{"https://10.1.2.3/x", true},                        // private
		{"http://feeds.example.com/list.txt", true},         // downgraded to http
	}
	for _, c := range cases {
		err := checkFeedRedirect(mk(c.target), nil)
		if c.blocked && err == nil {
			t.Errorf("redirect to %q should be refused", c.target)
		}
		if !c.blocked && err != nil {
			t.Errorf("redirect to %q should be allowed, got %v", c.target, err)
		}
	}
	// Hop-count cap.
	if err := checkFeedRedirect(mk("https://ok.example.com/"), make([]*http.Request, 5)); err == nil {
		t.Error("too many redirects should be refused")
	}
}

// End-to-end: an http.Client using the policy must not follow a redirect that
// points at an internal address.
func TestThreatFeed_ClientRefusesInternalRedirect(t *testing.T) {
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirector.Close()

	client := &http.Client{CheckRedirect: checkFeedRedirect}
	resp, err := client.Get(redirector.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("client followed the redirect to an internal address; must be refused")
	}
	if !strings.Contains(err.Error(), "threat_feed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
