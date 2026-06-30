package discovery

import "testing"

const openapi3WithSchema = `
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: integer}
    get:
      parameters:
        - name: verbose
          in: query
          required: false
          schema: {type: boolean}
        - name: sort
          in: query
          schema: {type: string, enum: [asc, desc]}
      responses: {"200": {description: ok}}
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/NewUser'}
      responses: {"201": {description: created}}
components:
  schemas:
    NewUser:
      type: object
      additionalProperties: false
      required: [email]
      properties:
        email: {type: string}
        age: {type: integer}
        role: {type: string, enum: [user, admin]}
`

func TestParseSpec_OpenAPI3_OpSchema(t *testing.T) {
	s, err := ParseSpec([]byte(openapi3WithSchema))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}

	// GET params: path id (int, required), query verbose (bool), query sort (enum)
	get := s.LookupOp("GET", "/users/{id}")
	if get == nil {
		t.Fatal("GET /users/{id}: no op schema")
	}
	byName := map[string]ParamSchema{}
	for _, p := range get.Params {
		byName[p.Name] = p
	}
	if p := byName["id"]; p.In != "path" || !p.Required || p.Type != "integer" {
		t.Errorf("path id param = %+v", p)
	}
	if p := byName["verbose"]; p.Type != "boolean" || p.Required {
		t.Errorf("query verbose param = %+v", p)
	}
	if p := byName["sort"]; len(p.Enum) != 2 || p.Enum[0] != "asc" {
		t.Errorf("query sort enum = %v", p.Enum)
	}

	// POST body: resolved via $ref, additionalProperties:false, required email,
	// typed properties + nested enum.
	post := s.LookupOp("POST", "/users/{id}")
	if post == nil || post.Body == nil {
		t.Fatal("POST /users/{id}: no body schema")
	}
	b := post.Body
	if b.AdditionalProperties == nil || *b.AdditionalProperties {
		t.Errorf("additionalProperties = %v, want false", b.AdditionalProperties)
	}
	if len(b.Required) != 1 || b.Required[0] != "email" {
		t.Errorf("required = %v", b.Required)
	}
	if b.Properties["age"] == nil || b.Properties["age"].Type != "integer" {
		t.Errorf("age property = %+v", b.Properties["age"])
	}
	if role := b.Properties["role"]; role == nil || len(role.Enum) != 2 {
		t.Errorf("role enum = %+v", role)
	}
}

const swagger2WithSchema = `
swagger: "2.0"
basePath: /v1
paths:
  /items:
    post:
      parameters:
        - name: body
          in: body
          required: true
          schema: {$ref: '#/definitions/Item'}
      responses: {"200": {description: ok}}
definitions:
  Item:
    type: object
    required: [sku]
    properties:
      sku: {type: string}
      qty: {type: integer}
`

func TestParseSpec_Swagger2_BodyParam(t *testing.T) {
	s, err := ParseSpec([]byte(swagger2WithSchema))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	// basePath /v1 is folded into the template.
	op := s.LookupOp("POST", "/v1/items")
	if op == nil || op.Body == nil {
		t.Fatalf("POST /v1/items: no body schema (op=%v)", op)
	}
	if len(op.Body.Required) != 1 || op.Body.Required[0] != "sku" {
		t.Errorf("required = %v", op.Body.Required)
	}
	if op.Body.Properties["qty"] == nil || op.Body.Properties["qty"].Type != "integer" {
		t.Errorf("qty property = %+v", op.Body.Properties["qty"])
	}
}

const openapi3CyclicRef = `
openapi: 3.0.0
info: {title: t, version: "1"}
paths:
  /tree:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Node'}
      responses: {"200": {description: ok}}
components:
  schemas:
    Node:
      type: object
      properties:
        name: {type: string}
        child: {$ref: '#/components/schemas/Node'}
`

func TestParseSpec_CyclicRef_Terminates(t *testing.T) {
	// A self-referential schema must not loop forever. The body itself is $ref
	// Node, so Node is already on the resolution path; its `child` property (also
	// $ref Node) hits the cycle guard immediately and resolves to nil. Non-cyclic
	// siblings (name) still resolve. The point is termination + safe fail-open on
	// the recursive subtree (it simply isn't enforced).
	s, err := ParseSpec([]byte(openapi3CyclicRef))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	op := s.LookupOp("POST", "/tree")
	if op == nil || op.Body == nil {
		t.Fatal("POST /tree: no body schema")
	}
	if op.Body.Properties["name"] == nil || op.Body.Properties["name"].Type != "string" {
		t.Errorf("name property = %+v", op.Body.Properties["name"])
	}
	if op.Body.Properties["child"] != nil {
		t.Errorf("recursive child should be nil (cycle guard), got %+v", op.Body.Properties["child"])
	}
}

func TestLookupOp_NilSafe(t *testing.T) {
	var s *Spec
	if s.LookupOp("GET", "/x") != nil {
		t.Error("nil Spec.LookupOp should return nil")
	}
}
