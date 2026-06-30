package discovery

import (
	"net/url"
	"testing"
)

// specForValidation documents GET /search (query params) and POST /users
// (strict JSON body) so the validator can be exercised end-to-end through the
// real parser.
const specForValidation = `
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /search:
    get:
      parameters:
        - {name: q, in: query, required: true, schema: {type: string}}
        - {name: limit, in: query, schema: {type: integer}}
        - {name: order, in: query, schema: {type: string, enum: [asc, desc]}}
      responses: {"200": {description: ok}}
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewUser'}
      responses: {"201": {description: ok}}
components:
  schemas:
    NewUser:
      type: object
      additionalProperties: false
      required: [email, age]
      properties:
        email: {type: string}
        age: {type: integer}
        role: {type: string, enum: [user, admin]}
        tags: {type: array, items: {type: string}}
`

func mustOp(t *testing.T, method, tmpl string) *OpSchema {
	t.Helper()
	s, err := ParseSpec([]byte(specForValidation))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	op := s.LookupOp(method, tmpl)
	if op == nil {
		t.Fatalf("no op for %s %s", method, tmpl)
	}
	return op
}

func ruleSet(vs []Violation) map[string]bool {
	m := map[string]bool{}
	for _, v := range vs {
		m[v.Field+"/"+v.Rule] = true
	}
	return m
}

func TestValidate_QueryParams(t *testing.T) {
	op := mustOp(t, "GET", "/search")

	tests := []struct {
		name  string
		query string
		want  []string // expected "field/rule" keys; nil = conformant
	}{
		{"all valid", "q=hello&limit=10&order=asc", nil},
		{"missing required", "limit=10", []string{"q/required"}},
		{"bad integer", "q=x&limit=abc", []string{"limit/type"}},
		{"bad enum", "q=x&order=sideways", []string{"order/enum"}},
		{"unknown param ignored", "q=x&debug=1", nil},
		{"multiple problems", "limit=abc&order=nope", []string{"q/required", "limit/type", "order/enum"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, _ := url.ParseQuery(tc.query)
			got := ruleSet(op.ValidateRequest(q, nil))
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing expected violation %q (got %v)", w, got)
				}
			}
		})
	}
}

func TestValidate_JSONBody(t *testing.T) {
	op := mustOp(t, "POST", "/users")

	tests := []struct {
		name string
		body string
		want []string
	}{
		{"valid", `{"email":"a@b.c","age":30}`, nil},
		{"valid full", `{"email":"a@b.c","age":30,"role":"admin","tags":["x","y"]}`, nil},
		{"missing required", `{"email":"a@b.c"}`, []string{"age/required"}},
		{"wrong type", `{"email":"a@b.c","age":"thirty"}`, []string{"age/type"}},
		{"integer not float", `{"email":"a@b.c","age":30.5}`, []string{"age/type"}},
		{"bad enum", `{"email":"a@b.c","age":1,"role":"root"}`, []string{"role/enum"}},
		{"mass assignment", `{"email":"a@b.c","age":1,"is_admin":true}`, []string{"is_admin/unknown_field"}},
		{"array item type", `{"email":"a@b.c","age":1,"tags":["ok",5]}`, []string{"tags[1]/type"}},
		{"invalid json", `{not json`, []string{"/invalid_json"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleSet(op.ValidateRequest(nil, []byte(tc.body)))
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing expected violation %q (got %v)", w, got)
				}
			}
		})
	}
}

func TestValidate_NilOpAndEmptyBody(t *testing.T) {
	var op *OpSchema
	if vs := op.ValidateRequest(nil, []byte(`{}`)); vs != nil {
		t.Errorf("nil op should yield no violations, got %v", vs)
	}
	// Documented body but none sent: not enforced in v1.
	op = mustOp(t, "POST", "/users")
	if vs := op.ValidateRequest(nil, nil); len(vs) != 0 {
		t.Errorf("absent body should not be enforced, got %v", vs)
	}
}
