package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func reqSpec(t *testing.T, top, opSec string) map[string]any {
	t.Helper()
	s := `{"paths":{"/v1/x/{id}":{"put":{` + opSec + `}}}`
	if top != "" {
		s += `,"security":` + top
	}
	return mustDoc(t, s+`}`)
}

func TestOperationRequirements_KeepsAlternativesSeparate(t *testing.T) {
	got := operationRequirements(reqSpec(t, "", `"security":[{"bearer":["a"]},{"bearer":["b","c"]}]`))
	want := map[string][][]string{"PUT /v1/x/{id}": {{"a"}, {"b", "c"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOperationRequirements_UnionsSchemes(t *testing.T) {
	got := operationRequirements(reqSpec(t, "", `"security":[{"oauth2":["a"],"apiKeyHeader":["a"]}]`))
	want := map[string][][]string{"PUT /v1/x/{id}": {{"a"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOperationRequirements_OptionalAuth(t *testing.T) {
	got := operationRequirements(reqSpec(t, "", `"security":[{},{"bearer":["a"]}]`))
	want := map[string][][]string{"PUT /v1/x/{id}": {{"a"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := operationRequirements(reqSpec(t, "", `"security":[{}]`)); len(got) != 0 {
		t.Fatalf("only {} must have no entry, got %v", got)
	}
}

func TestOperationRequirements_TopLevelInheritance(t *testing.T) {
	doc := mustDoc(t, `{"security":[{"bearer":["t"]}],"paths":{
		"/a":{"get":{}},
		"/b":{"get":{"security":[]}}}}`)
	got := operationRequirements(doc)
	want := map[string][][]string{"GET /a": {{"t"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOperationRequirements_AuthenticatedOnly(t *testing.T) {
	got := operationRequirements(reqSpec(t, "", `"security":[{"apiKeyQuery":[]}]`))
	want := map[string][][]string{"PUT /v1/x/{id}": {{}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if alt := got["PUT /v1/x/{id}"][0]; alt == nil {
		t.Fatal("alternative must be a non-nil empty slice")
	}
}

func TestOperationRequirements_PreparedEqualsUnprepared(t *testing.T) {
	raw, err := os.ReadFile("../test-fixtures/openapi-spec-oauth2.json")
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, err := prepareSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(prepared, &b); err != nil {
		t.Fatal(err)
	}
	before, after := operationRequirements(a), operationRequirements(b)
	if len(before) == 0 {
		t.Fatal("fixture should declare requirements")
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("unprepared %v != prepared %v", before, after)
	}
}
