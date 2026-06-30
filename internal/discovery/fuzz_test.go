package discovery

import "testing"

// FuzzParseSpec drives the OpenAPI/Swagger parser (including the schema
// extension) with arbitrary bytes. The parser consumes untrusted operator input
// (uploaded specs), so it must never panic; it must either error (and return no
// Spec) or return a usable Spec whose lookups also never panic.
func FuzzParseSpec(f *testing.F) {
	for _, s := range []string{
		openapi3WithSchema, swagger2WithSchema, openapi3CyclicRef, specForValidation,
		"", "openapi: 3.0.0", "swagger: \"2.0\"", "{}", "paths: {}",
		"openapi: 3.0.0\npaths:\n  /x: {get: {}}",
		"paths:\n  /a/{id}:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/Missing'}",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		spec, err := ParseSpec(raw)
		if err != nil {
			if spec != nil {
				t.Fatalf("error returned alongside a non-nil spec")
			}
			return
		}
		if spec == nil {
			t.Fatal("nil spec with nil error")
		}
		// ParseSpec guarantees at least one operation, otherwise it errors.
		if spec.OpCount() == 0 {
			t.Fatal("parsed spec reports 0 operations but did not error")
		}
		// Every documented operation must be safely queryable and, when it has a
		// schema, validatable against arbitrary input without panicking.
		for _, op := range spec.operations() {
			if !spec.HasOp(op.Method, op.Template) {
				t.Errorf("operations() listed %s %s but HasOp is false", op.Method, op.Template)
			}
			_ = spec.HasPath(op.Template)
			if os := spec.LookupOp(op.Method, op.Template); os != nil {
				_ = os.ValidateRequest(nil, []byte(`{"a":1,"b":[2,{"c":"d"}]}`))
			}
		}
	})
}

// FuzzValidateRequest fixes a documented operation and fuzzes the request body,
// which is fully attacker-controlled at runtime. Validation must never panic and
// always return (an empty or non-empty violation slice).
func FuzzValidateRequest(f *testing.F) {
	spec, err := ParseSpec([]byte(specForValidation))
	if err != nil {
		f.Fatalf("seed spec parse: %v", err)
	}
	op := spec.LookupOp("POST", "/users")
	if op == nil {
		f.Fatal("seed op missing")
	}

	for _, s := range []string{
		`{}`, `{"email":"a@b.c","age":3}`, `{"age":1}`, `{"email":"x","extra":true}`,
		`[]`, `null`, `"x"`, `123`, `1.5`, `true`, ``, `{`, `{"tags":[1,2,3]}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		_ = op.ValidateRequest(nil, body)
	})
}

// FuzzNormalizePath exercises the path normaliser with arbitrary input: it runs
// on every request path (untrusted) and feeds both the catalog and the schema
// template lookup, so a panic here is a data-plane crash. Normalisation must be
// idempotent — re-normalising an already-normalised path must not change it.
func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{
		"/", "/users/42", "/users/{id}", "/a//b", "/a/../b", "//", "", "a/b",
		"/users/42/orders/7", "/%2e%2e/", "/café/π",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, p string) {
		got := NormalizePath(p)
		if again := NormalizePath(got); again != got {
			t.Errorf("NormalizePath not idempotent: %q -> %q -> %q", p, got, again)
		}
	})
}
