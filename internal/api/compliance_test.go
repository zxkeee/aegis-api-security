package api

import (
	"testing"

	"api-gateway/internal/discovery"
)

func fr(owasp, sev, title, method, path string) findingRow {
	return findingRow{Method: method, PathTemplate: path, Finding: discovery.Finding{OWASP: owasp, Severity: sev, Title: title}}
}

func TestBuildCompliance(t *testing.T) {
	rows := []findingRow{
		fr("API3:2023", "critical", "Sensitive data exposed to unauthenticated callers", "GET", "/users/{id}"),
		fr("API9:2023", "critical", "Shadow endpoint serving sensitive data", "GET", "/legacy/{id}"),
	}
	abuse := map[string]int{"bola_object_ownership": 3, "bfla_privileged_access": 1, "waf_blocked": 9}

	rep := buildCompliance(rows, abuse)

	// Frameworks present and ordered OWASP → NIS2 → ISO.
	if len(rep.Frameworks) != 3 {
		t.Fatalf("frameworks = %d, want 3 (%+v)", len(rep.Frameworks), rep.Frameworks)
	}
	order := []string{fwOWASP, fwNIS2, fwISO}
	for i, want := range order {
		if rep.Frameworks[i].Framework != want {
			t.Fatalf("framework[%d] = %s, want %s", i, rep.Frameworks[i].Framework, want)
		}
	}

	// NIS2 must carry an access-control control (from BOLA/BFLA/API-mappings).
	var nis2Access bool
	for _, c := range rep.Frameworks[1].Controls {
		if c.Control == "Art. 21(2)(i)" {
			nis2Access = true
		}
	}
	if !nis2Access {
		t.Fatal("NIS2 Art. 21(2)(i) access control not mapped")
	}

	// waf_blocked is not an access-control abuse → must not inflate the report.
	// Summary critical = 2 findings + 3 (bola) + 1 (bfla) = 6.
	if rep.Summary.Critical != 6 {
		t.Fatalf("summary critical = %d, want 6", rep.Summary.Critical)
	}
	if rep.Summary.ControlsAffected == 0 {
		t.Fatal("no controls affected")
	}
}
