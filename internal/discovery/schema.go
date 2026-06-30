package discovery

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// This file extends the OpenAPI/Swagger parser (spec.go) with the per-operation
// request *schema* needed for positive-security enforcement: documented
// parameters and the JSON request-body shape. Drift detection only needs the
// path/method inventory; schema enforcement needs the constraints, parsed in the
// same pass and resolved through $ref. See docs/design/schema-enforcement.md.

// OpSchema is the documented request contract for one operation (METHOD+template).
type OpSchema struct {
	Params []ParamSchema
	// Body is the application/json request-body schema, or nil if the operation
	// documents no JSON body.
	Body *JSONSchema
}

// ParamSchema is a documented query/path/header parameter.
type ParamSchema struct {
	Name     string
	In       string // "query" | "path" | "header" | "body" (swagger 2)
	Required bool
	Type     string   // "integer" | "number" | "boolean" | "string" | "array" | ""
	Enum     []string // allowed values (string form); empty = unconstrained
}

// JSONSchema is the subset of JSON Schema we enforce in v1: type, required
// properties, per-property schemas, array items, enum, and additionalProperties
// (only its `false` form, which forbids undocumented fields — the anti
// mass-assignment lever). Unsupported keywords (allOf/oneOf, formats, numeric
// bounds) are intentionally ignored, not rejected.
type JSONSchema struct {
	Type                 string
	Required             []string
	Properties           map[string]*JSONSchema
	Items                *JSONSchema
	Enum                 []string
	AdditionalProperties *bool // non-nil && false => reject unknown properties
}

// ── raw decode shapes ────────────────────────────────────────────────────────

type specOperation struct {
	Parameters  []specParameter `yaml:"parameters"`
	RequestBody specRequestBody `yaml:"requestBody"`
}

type specParameter struct {
	Ref      string        `yaml:"$ref"`
	Name     string        `yaml:"name"`
	In       string        `yaml:"in"`
	Required bool          `yaml:"required"`
	Schema   specRawSchema `yaml:"schema"` // OpenAPI 3 (and swagger body param)
	Type     string        `yaml:"type"`   // Swagger 2 inline param type
	Enum     []yaml.Node   `yaml:"enum"`   // Swagger 2 inline param enum
}

type specRequestBody struct {
	Content map[string]specMediaType `yaml:"content"`
}

type specMediaType struct {
	Schema specRawSchema `yaml:"schema"`
}

type specRawSchema struct {
	Ref                  string                   `yaml:"$ref"`
	Type                 string                   `yaml:"type"`
	Required             []string                 `yaml:"required"`
	Properties           map[string]specRawSchema `yaml:"properties"`
	Items                *specRawSchema           `yaml:"items"`
	Enum                 []yaml.Node              `yaml:"enum"`
	AdditionalProperties additionalProps          `yaml:"additionalProperties"`
}

// additionalProps captures OpenAPI's `additionalProperties`, which may be a
// boolean OR a schema object. We only enforce the `false` form (forbid unknown
// fields — the anti mass-assignment lever); a schema object or `true` imposes no
// restriction in v1. A custom unmarshaller is required because decoding a bare
// bool into yaml.Node fails and would abort the whole schema decode.
type additionalProps struct {
	forbidExtra bool // set only when the value is exactly `false`
}

func (a *additionalProps) UnmarshalYAML(value *yaml.Node) error {
	var b bool
	if err := value.Decode(&b); err == nil {
		a.forbidExtra = !b
	}
	// Non-bool (a schema object) leaves forbidExtra false: additional properties
	// are allowed (we do not recurse into the additionalProperties schema in v1).
	return nil
}

// parseOpSchemas walks the documented paths a second time, decoding each
// operation's parameters and JSON body into resolved OpSchema values keyed by
// "METHOD template" (the same key space as Spec.ops). Path-level parameters are
// merged into every operation on that path (OpenAPI semantics).
func (sd *specDoc) parseOpSchemas(base string) map[string]*OpSchema {
	out := map[string]*OpSchema{}
	for rawPath, item := range sd.Paths {
		tmpl := canonicalSpecPath(base + rawPath)

		// Path-level parameters apply to every operation on the path.
		var pathParams []specParameter
		if n, ok := item["parameters"]; ok {
			_ = n.Decode(&pathParams)
		}

		for method, node := range item {
			m := strings.ToLower(strings.TrimSpace(method))
			if !httpMethods[m] {
				continue
			}
			var op specOperation
			if err := node.Decode(&op); err != nil {
				continue
			}
			os := sd.buildOpSchema(append(append([]specParameter{}, pathParams...), op.Parameters...), op.RequestBody)
			out[strings.ToUpper(m)+" "+tmpl] = os
		}
	}
	return out
}

func (sd *specDoc) buildOpSchema(params []specParameter, body specRequestBody) *OpSchema {
	os := &OpSchema{}
	for _, p := range params {
		// Swagger 2.0 carries the request body as a parameter with in:"body".
		if strings.EqualFold(p.In, "body") {
			if os.Body == nil {
				os.Body = sd.resolveSchema(p.Schema, map[string]bool{})
			}
			continue
		}
		typ := p.Type
		if typ == "" {
			typ = p.Schema.Type // OpenAPI 3 nests under schema
		}
		enum := enumStrings(p.Enum)
		if len(enum) == 0 {
			enum = enumStrings(p.Schema.Enum)
		}
		os.Params = append(os.Params, ParamSchema{
			Name: p.Name, In: p.In, Required: p.Required, Type: typ, Enum: enum,
		})
	}
	// OpenAPI 3 request body.
	if os.Body == nil {
		if mt, ok := body.Content["application/json"]; ok {
			os.Body = sd.resolveSchema(mt.Schema, map[string]bool{})
		}
	}
	return os
}

// resolveSchema converts a raw schema into the enforced JSONSchema, following a
// $ref into components/schemas (OpenAPI 3) or definitions (Swagger 2). seen
// guards against $ref cycles along the current resolution path.
func (sd *specDoc) resolveSchema(raw specRawSchema, seen map[string]bool) *JSONSchema {
	if raw.Ref != "" {
		if seen[raw.Ref] {
			return nil // cycle: stop without recursing forever
		}
		target, ok := sd.lookupRef(raw.Ref)
		if !ok {
			return nil
		}
		next := cloneSeen(seen)
		next[raw.Ref] = true
		return sd.resolveSchema(target, next)
	}

	js := &JSONSchema{Type: raw.Type, Required: raw.Required, Enum: enumStrings(raw.Enum)}
	if raw.AdditionalProperties.forbidExtra {
		no := false
		js.AdditionalProperties = &no
	}
	if len(raw.Properties) > 0 {
		js.Properties = make(map[string]*JSONSchema, len(raw.Properties))
		for name, p := range raw.Properties {
			js.Properties[name] = sd.resolveSchema(p, cloneSeen(seen))
		}
	}
	if raw.Items != nil {
		js.Items = sd.resolveSchema(*raw.Items, cloneSeen(seen))
	}
	return js
}

// lookupRef resolves a local component reference to its raw schema. Only local
// refs (#/components/schemas/* and #/definitions/*) are supported; external
// refs return false (fail-open: the operation simply has no enforced body).
func (sd *specDoc) lookupRef(ref string) (specRawSchema, bool) {
	var node yaml.Node
	switch {
	case strings.HasPrefix(ref, "#/components/schemas/"):
		n, ok := sd.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
		if !ok {
			return specRawSchema{}, false
		}
		node = n
	case strings.HasPrefix(ref, "#/definitions/"):
		n, ok := sd.Definitions[strings.TrimPrefix(ref, "#/definitions/")]
		if !ok {
			return specRawSchema{}, false
		}
		node = n
	default:
		return specRawSchema{}, false
	}
	var s specRawSchema
	if err := node.Decode(&s); err != nil {
		return specRawSchema{}, false
	}
	return s, true
}

// LookupOp returns the documented schema for an operation, or nil when the
// operation is not documented (callers fail-open on nil).
func (s *Spec) LookupOp(method, template string) *OpSchema {
	if s == nil || s.opSchemas == nil {
		return nil
	}
	return s.opSchemas[strings.ToUpper(method)+" "+template]
}

// enumStrings flattens scalar enum nodes to their string form.
func enumStrings(nodes []yaml.Node) []string {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.Value != "" {
			out = append(out, n.Value)
		}
	}
	return out
}

func cloneSeen(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k := range in {
		out[k] = true
	}
	return out
}
