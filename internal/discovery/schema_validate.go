package discovery

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// Violation is one way a request departed from its documented contract.
type Violation struct {
	Location string `json:"location"` // "query" | "body"
	Field    string `json:"field,omitempty"`
	Rule     string `json:"rule"` // required | type | enum | unknown_field | invalid_json
	Detail   string `json:"detail,omitempty"`
}

func (v Violation) String() string {
	if v.Field == "" {
		return fmt.Sprintf("%s: %s (%s)", v.Location, v.Rule, v.Detail)
	}
	return fmt.Sprintf("%s.%s: %s (%s)", v.Location, v.Field, v.Rule, v.Detail)
}

// ValidateRequest checks a request against the documented operation contract and
// returns every violation (empty == conformant). It is pure: query parameters and
// the raw JSON body in, violations out — no I/O, no request mutation. Only query
// parameters and the application/json body are enforced in v1.
//
// A documented body is validated only when a body is present; body-required is
// not enforced in v1. Unknown query parameters are allowed (only documented ones
// are constrained); unknown *body* fields are rejected only when the schema sets
// additionalProperties:false.
func (op *OpSchema) ValidateRequest(query url.Values, body []byte) []Violation {
	if op == nil {
		return nil
	}
	var vs []Violation

	for _, p := range op.Params {
		if !strings.EqualFold(p.In, "query") {
			continue // v1 enforces query params; path/header validation is future
		}
		vals, present := query[p.Name]
		if !present {
			if p.Required {
				vs = append(vs, Violation{"query", p.Name, "required", "missing required query parameter"})
			}
			continue
		}
		for _, v := range vals {
			if p.Type != "" && !paramTypeMatches(v, p.Type) {
				vs = append(vs, Violation{"query", p.Name, "type", "expected " + p.Type})
			}
			if len(p.Enum) > 0 && !contains(p.Enum, v) {
				vs = append(vs, Violation{"query", p.Name, "enum", "value not in allowed set"})
			}
		}
	}

	if op.Body != nil && len(body) > 0 {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			vs = append(vs, Violation{"body", "", "invalid_json", "request body is not valid JSON"})
		} else {
			validateValue(parsed, op.Body, "", &vs)
		}
	}
	return vs
}

// validateValue recursively checks a decoded JSON value against a schema,
// appending violations. A type mismatch stops recursion into that node (the
// nested rules no longer apply). A JSON null is treated leniently (skipped) since
// nullability is not modelled in v1.
func validateValue(val any, schema *JSONSchema, path string, vs *[]Violation) {
	if schema == nil || val == nil {
		return
	}

	if schema.Type != "" && !jsonTypeMatches(val, schema.Type) {
		*vs = append(*vs, Violation{"body", path, "type", "expected " + schema.Type})
		return
	}
	if len(schema.Enum) > 0 && !contains(schema.Enum, scalarString(val)) {
		*vs = append(*vs, Violation{"body", path, "enum", "value not in allowed set"})
	}

	switch schema.Type {
	case "object":
		m, ok := val.(map[string]any)
		if !ok {
			return
		}
		for _, req := range schema.Required {
			if _, present := m[req]; !present {
				*vs = append(*vs, Violation{"body", join(path, req), "required", "missing required field"})
			}
		}
		// additionalProperties:false — the anti mass-assignment lever.
		if schema.AdditionalProperties != nil && !*schema.AdditionalProperties && schema.Properties != nil {
			for k := range m {
				if _, known := schema.Properties[k]; !known {
					*vs = append(*vs, Violation{"body", join(path, k), "unknown_field", "field not permitted by schema"})
				}
			}
		}
		for k, sub := range schema.Properties {
			if v, present := m[k]; present {
				validateValue(v, sub, join(path, k), vs)
			}
		}
	case "array":
		arr, ok := val.([]any)
		if !ok {
			return
		}
		if schema.Items != nil {
			for i, item := range arr {
				validateValue(item, schema.Items, fmt.Sprintf("%s[%d]", path, i), vs)
			}
		}
	}
}

// jsonTypeMatches reports whether a decoded JSON value matches an OpenAPI type.
// JSON numbers decode to float64; "integer" additionally requires a whole value.
func jsonTypeMatches(val any, typ string) bool {
	switch typ {
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "number":
		_, ok := val.(float64)
		return ok
	case "integer":
		f, ok := val.(float64)
		return ok && f == math.Trunc(f)
	default:
		return true // unknown/empty type: no constraint
	}
}

// paramTypeMatches reports whether a raw query-string value is coercible to the
// documented parameter type.
func paramTypeMatches(v, typ string) bool {
	switch typ {
	case "integer":
		_, err := strconv.ParseInt(v, 10, 64)
		return err == nil
	case "number":
		_, err := strconv.ParseFloat(v, 64)
		return err == nil
	case "boolean":
		return v == "true" || v == "false"
	default:
		return true // string / array / unknown: unconstrained
	}
}

// scalarString renders a decoded JSON scalar for enum comparison, formatting
// whole-number floats without a trailing ".0" so 2 matches the enum token "2".
func scalarString(val any) string {
	switch x := val.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func join(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}
