package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

const canonicalSchemes = `{"bearer":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}}`

func mustDoc(t *testing.T, s string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestBearerOnlySecurity(t *testing.T) {
	op := func(sec string) string {
		return `{"paths":{"/x":{"put":{"security":` + sec + `}}}}`
	}
	tests := []struct {
		name string
		in   string
		want string // expected put security
	}{
		{"merged and deduped in sorted scheme order",
			op(`[{"oauth2":["b","a"],"apiKeyHeader":["a","c"]}]`), `[{"bearer":["a","c","b"]}]`},
		{"alternatives stay separate",
			op(`[{"bearer":["a"]},{"bearer":["b","c"]}]`), `[{"bearer":["a"]},{"bearer":["b","c"]}]`},
		{"empty alternative stays empty",
			op(`[{},{"oidc":["x"]}]`), `[{},{"bearer":["x"]}]`},
		{"scheme without strings",
			op(`[{"apiKeyCookie":[]}]`), `[{"bearer":[]}]`},
		{"schemes reduced to canonical",
			`{"components":{"securitySchemes":{"jwt":{"type":"http","scheme":"bearer"},"apiKeyHeader":{"type":"apiKey","in":"header","name":"X"}}},"paths":{"/x":{"put":{"security":[{"jwt":["a"]}]}}}}`,
			`[{"bearer":["a"]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := mustDoc(t, tt.in)
			if !bearerOnlySecurity(doc) {
				t.Fatal("expected changed")
			}
			got := doc["paths"].(map[string]any)["/x"].(map[string]any)["put"].(map[string]any)["security"]
			if !reflect.DeepEqual(got, mustDoc(t, `{"s":`+tt.want+`}`)["s"]) {
				t.Errorf("security = %v, want %s", got, tt.want)
			}
			schemes := doc["components"].(map[string]any)["securitySchemes"]
			if !reflect.DeepEqual(schemes, mustDoc(t, canonicalSchemes)) {
				t.Errorf("securitySchemes = %v", schemes)
			}
		})
	}
}

func TestBearerOnlySecurity_TopLevelAndOperations(t *testing.T) {
	doc := mustDoc(t, `{"security":[{"oauth2":["a"]}],"paths":{
		"/x":{"parameters":[{"name":"p"}],"x-kdex-metadata":{"k":1},
			"get":{"security":[]},"put":{}}}}`)
	if !bearerOnlySecurity(doc) {
		t.Fatal("expected changed")
	}
	if !reflect.DeepEqual(doc["security"], mustDoc(t, `{"s":[{"bearer":["a"]}]}`)["s"]) {
		t.Errorf("top-level security = %v", doc["security"])
	}
	item := doc["paths"].(map[string]any)["/x"].(map[string]any)
	if !reflect.DeepEqual(item["get"].(map[string]any)["security"], []any{}) {
		t.Errorf("get security = %v", item["get"])
	}
	if _, has := item["put"].(map[string]any)["security"]; has {
		t.Error("put gained a security key")
	}
	if !reflect.DeepEqual(item["parameters"], []any{map[string]any{"name": "p"}}) ||
		!reflect.DeepEqual(item["x-kdex-metadata"], map[string]any{"k": float64(1)}) {
		t.Errorf("path item extras changed: %v", item)
	}
}

func TestBearerOnlySecurity_NoSecurityUntouched(t *testing.T) {
	in := `{"paths":{"/x":{"get":{"responses":{}}}}}`
	doc := mustDoc(t, in)
	if bearerOnlySecurity(doc) {
		t.Error("changed = true for a spec with no security")
	}
	if !reflect.DeepEqual(doc, mustDoc(t, in)) {
		t.Error("doc was mutated")
	}
}

func TestBearerOnlySecurity_AlreadyCanonical(t *testing.T) {
	doc := mustDoc(t, `{"components":{"securitySchemes":`+canonicalSchemes+`},
		"paths":{"/x":{"get":{"security":[{"bearer":["a"]},{}]}}}}`)
	if bearerOnlySecurity(doc) {
		t.Error("changed = true for a canonical spec")
	}
}

func TestUnionAlternative(t *testing.T) {
	if got := unionAlternative(map[string]any{"a": []any{}}); got == nil || len(got) != 0 {
		t.Errorf("got %#v, want empty non-nil", got)
	}
}

func TestPrepareSpec_BearerOnlyCanonicalIsUnchanged(t *testing.T) {
	spec := []byte(`{"components":{"securitySchemes":` + canonicalSchemes + `},"paths":{"/x":{"get":{"security":[{"bearer":["a"]}]}}}}`)
	out, changed, err := prepareSpec(spec)
	if err != nil || changed || string(out) != string(spec) {
		t.Errorf("changed=%v err=%v out=%s", changed, err, out)
	}
}

func TestPrepareSpec_RewritesSecurity(t *testing.T) {
	spec := []byte(`{"paths":{"/x":{"get":{"security":[{"oauth2":["a"]}]}}}}`)
	out, changed, err := prepareSpec(spec)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	doc := mustDoc(t, string(out))
	if _, ok := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)["bearer"]; !ok {
		t.Errorf("no bearer scheme: %s", out)
	}
}
