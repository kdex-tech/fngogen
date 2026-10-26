package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBuildOneOffByteIdentical asserts that `fngogen build-spec` / `fngogen
// local` reproduce, byte-for-byte, the openapi-spec.json host-manager's
// in-cluster codegen produces for the same KDexFunction CR. Both render it with
// the shared kdex.dev/crds/openapi builder; this pins the CLI's own decode and
// serialization around it (sigs.k8s.io/yaml, MarshalIndent with a two-space
// indent, entry-point.sh's trailing newline). That is the guarantee that makes
// local codegen (fngogen#2) safe: no churn when the cluster regenerates.
//
// Fixtures are real KDexFunction CRs from knowdrive-site; the expected
// documents are kdex-crds' openapi/testdata/oneoff goldens.
func TestBuildOneOffByteIdentical(t *testing.T) {
	const serverURL = "https://dev.knowdrive.ai"

	cases := []string{"tenancy-service", "user-service-auth"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			crPath := filepath.Join("..", "test-fixtures", "oneoff", name+".kdexfunction.yaml")
			wantPath := filepath.Join("..", "test-fixtures", "oneoff", name+".openapi-spec.json")

			got, err := oneOffFromCR(crPath, serverURL)
			if err != nil {
				t.Fatalf("oneOffFromCR: %v", err)
			}

			want, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatalf("read golden spec: %v", err)
			}

			if string(got) != string(want) {
				gotPath := filepath.Join("..", "test-fixtures", "oneoff", name+".got.json")
				_ = os.WriteFile(gotPath, got, 0o644)
				t.Fatalf("one-off spec not byte-identical to the cluster's openapi-spec.json\n"+
					"got %d bytes, want %d bytes; wrote got to %s", len(got), len(want), gotPath)
			}
		})
	}
}
