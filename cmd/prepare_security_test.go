package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
			if changed, err := bearerOnlySecurity(doc); err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
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
	if changed, err := bearerOnlySecurity(doc); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
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
	if changed, err := bearerOnlySecurity(doc); err != nil || changed {
		t.Errorf("changed=%v err=%v for a spec with no security", changed, err)
	}
	if !reflect.DeepEqual(doc, mustDoc(t, in)) {
		t.Error("doc was mutated")
	}
}

func TestBearerOnlySecurity_AlreadyCanonical(t *testing.T) {
	doc := mustDoc(t, `{"components":{"securitySchemes":`+canonicalSchemes+`},
		"paths":{"/x":{"get":{"security":[{"bearer":["a"]},{}]}}}}`)
	if changed, err := bearerOnlySecurity(doc); err != nil || changed {
		t.Errorf("changed=%v err=%v for a canonical spec", changed, err)
	}
}

func TestUnionAlternative(t *testing.T) {
	if got, err := unionAlternative(map[string]any{"a": []any{}}); err != nil || got == nil || len(got) != 0 {
		t.Errorf("got %#v err %v, want empty non-nil", got, err)
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

// TestBearerOnlySecurity_RejectsMalformed: a security value ogen would reject
// must fail preparation. Read leniently, `{"oauth2": "users:write"}` became
// {"bearer": []}, which any valid token satisfies (fail open).
func TestBearerOnlySecurity_RejectsMalformed(t *testing.T) {
	for name, sec := range map[string]string{
		"scheme value not an array": `[{"oauth2":"users:write"}]`,
		"non-string scope":          `[{"oauth2":[123]}]`,
		"null scheme value":         `[{"oauth2":null}]`,
		"alternative not an object": `["bearer"]`,
		"security not an array":     `{"bearer":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			for where, doc := range map[string]string{
				"operation": `{"paths":{"/x":{"put":{"security":` + sec + `}}}}`,
				"top-level": `{"security":` + sec + `,"paths":{"/x":{"put":{}}}}`,
			} {
				if _, err := bearerOnlySecurity(mustDoc(t, doc)); err == nil {
					t.Errorf("%s: no error for %s", where, sec)
				}
			}
		})
	}
}

func TestPrepareSpec_RejectsMalformedSecurity(t *testing.T) {
	_, _, err := prepareSpec([]byte(`{"paths":{"/x":{"get":{"security":[{"oauth2":"users:write"}]}}}}`))
	if err == nil || !strings.Contains(err.Error(), "GET /x") {
		t.Errorf("err = %v, want an error naming GET /x", err)
	}
}

func TestRun_RejectsMalformedSecurity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openapi-spec.json")
	spec := []byte(`{"paths":{"/x":{"get":{"security":[{"oauth2":[123]}]}}}}`)
	if err := os.WriteFile(path, spec, 0644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--prepare", "--spec", path}); err == nil {
		t.Error("run --prepare accepted a malformed security requirement")
	}
	if out, _ := os.ReadFile(path); string(out) != string(spec) {
		t.Errorf("spec rewritten: %s", out)
	}
}
