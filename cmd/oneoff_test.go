package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/yaml"
)

// TestBuildOneOffByteIdentical asserts that BuildOneOff, driven by a real
// KDexFunction CR, reproduces the exact openapi-spec.json host-manager's
// in-cluster codegen produces — byte-for-byte. Because BuildOneOff reuses the
// same kin-openapi library and the same json.MarshalIndent(doc, "", "  ")
// call host-manager uses (internal/generate/generate.go), the output is
// identical to the cluster's by construction. That is the guarantee that makes
// local codegen (fngogen#2) safe: no churn when the cluster regenerates.
//
// Fixtures are the KDexFunction CRs + committed openapi-spec.json from
// RSI/knowdrive-site:
//   - tenancy-service: exercises schemas + the used-scheme filter (only the
//     referenced `bearer` scheme + the Unauthorized response are emitted).
//   - user-service-auth: a public (no-scheme) function. NOTE: its fixture was
//     corrected to drop a spurious `"schemas": {}` that knowdrive-site's prior
//     Python wrapper (scripts/codegen-local.sh) always emitted — kin-openapi
//     v0.133.0 (Components.MarshalJSON: `if len(x) != 0`) omits an empty
//     schemas map, so true cluster output omits it. This CLI matches the
//     cluster, and is more faithful than that wrapper.
func TestBuildOneOffByteIdentical(t *testing.T) {
	const serverURL = "https://dev.knowdrive.ai" // codegen-local.sh default

	cases := []string{"tenancy-service", "user-service-auth"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			crPath := filepath.Join("..", "test-fixtures", "oneoff", name+".kdexfunction.yaml")
			wantPath := filepath.Join("..", "test-fixtures", "oneoff", name+".openapi-spec.json")

			crBytes, err := os.ReadFile(crPath)
			if err != nil {
				t.Fatalf("read CR: %v", err)
			}
			var fn kdexv1alpha1.KDexFunction
			if err := yaml.Unmarshal(crBytes, &fn); err != nil {
				t.Fatalf("decode KDexFunction: %v", err)
			}

			doc := BuildOneOff(serverURL, &fn)
			got, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatalf("marshal one-off doc: %v", err)
			}
			got = append(got, '\n') // committed files end with a trailing newline

			want, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatalf("read golden spec: %v", err)
			}

			if string(got) != string(want) {
				gotPath := filepath.Join("..", "test-fixtures", "oneoff", name+".got.json")
				_ = os.WriteFile(gotPath, got, 0o644)
				t.Fatalf("one-off spec not byte-identical to the cluster's committed openapi-spec.json\n"+
					"got %d bytes, want %d bytes; wrote got to %s", len(got), len(want), gotPath)
			}
		})
	}
}
