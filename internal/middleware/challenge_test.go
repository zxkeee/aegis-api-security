package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"api-gateway/internal/config"
)

// challengeAnswer must be exact 32-bit FNV-1a (the JS in the challenge page
// implements the same algorithm with Math.imul; these are published FNV test
// vectors, so a drift on either side breaks the pair).
func TestChallengeAnswer_KnownVectors(t *testing.T) {
	cases := map[string]string{
		"":    "811c9dc5", // offset basis
		"a":   "e40c292c",
		"foo": "a9f37ed7",
	}
	for in, want := range cases {
		if got := challengeAnswer(in); got != want {
			t.Fatalf("challengeAnswer(%q) = %q, want %q", in, got, want)
		}
	}
}

// recordingChallengeStore captures what the middleware stores as the expected
// token, plus the standard ChallengeStore behaviour needed by the flow.
type recordingChallengeStore struct {
	issued string
}

func (r *recordingChallengeStore) IssueChallenge(_ context.Context, _, token string, _ time.Duration) error {
	r.issued = token
	return nil
}
func (r *recordingChallengeStore) IsValidChallengeToken(_ context.Context, _, token string) (bool, error) {
	return r.issued != "" && token == r.issued, nil
}
func (r *recordingChallengeStore) MarkChallengeSolved(context.Context, string, time.Duration) error {
	return nil
}
func (r *recordingChallengeStore) IsChallengeSolved(context.Context, string) (bool, error) {
	return false, nil
}

var seedRe = regexp.MustCompile(`var seed = "([0-9a-f]{32})"`)

// The value stored server-side must be the ANSWER (transform of the seed), not
// the seed embedded in the HTML. Otherwise a client can pass the challenge by
// scraping the page and echoing the seed back — no JS execution required.
func TestChallenge_EchoingSeedDoesNotPass(t *testing.T) {
	_ = InitTrustedProxies(nil)
	st := &recordingChallengeStore{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Challenge(config.ChallengeConfig{Enabled: true}, fakeLogger{}, st)(next)

	// First request: get the challenge page and extract the embedded seed.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "9.9.9.9:1000"
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected challenge page, got %d", rec.Code)
	}
	m := seedRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("challenge page carries no seed: %q", rec.Body.String())
	}
	seed := m[1]

	if st.issued == seed {
		t.Fatal("stored token equals the embedded seed — scraping the page defeats the challenge")
	}
	if want := challengeAnswer(seed); st.issued != want {
		t.Fatalf("stored token = %q, want challengeAnswer(seed) = %q", st.issued, want)
	}

	// Sending the computed answer (what the page JS produces) passes.
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "9.9.9.9:1000"
	r2.Header.Set("X-Challenge-Token", challengeAnswer(seed))
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("computed answer rejected: %d", rec2.Code)
	}

	// Echoing a scraped seed back must NOT pass. (A failed attempt re-issues a
	// fresh challenge, so extract the current seed from the newly served page
	// and replay exactly that value.)
	st2 := &recordingChallengeStore{}
	h2 := Challenge(config.ChallengeConfig{Enabled: true}, fakeLogger{}, st2)(next)
	rec3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.RemoteAddr = "8.8.8.8:1000"
	h2.ServeHTTP(rec3, r3)
	m3 := seedRe.FindStringSubmatch(rec3.Body.String())
	if m3 == nil {
		t.Fatalf("challenge page carries no seed: %q", rec3.Body.String())
	}
	rec4 := httptest.NewRecorder()
	r4 := httptest.NewRequest(http.MethodGet, "/", nil)
	r4.RemoteAddr = "8.8.8.8:1000"
	r4.Header.Set("X-Challenge-Token", m3[1]) // the raw seed, not the answer
	h2.ServeHTTP(rec4, r4)
	if rec4.Code != http.StatusForbidden {
		t.Fatalf("echoed seed passed the challenge: %d", rec4.Code)
	}
}
