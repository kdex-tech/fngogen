package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ogen-go/ogen"
	"github.com/ogen-go/ogen/gen"
	"github.com/ogen-go/ogen/gen/genfs"
)

// generateAPI runs ogen in-process to produce the api/ package from a resolved
// OpenAPI document — the library equivalent of the image's
// `ogen --target api --clean openapi-spec.json` (entry-point.sh). Doing it
// in-process removes the `go run github.com/ogen-go/ogen/cmd/ogen` hop, so the
// local CLI needs neither the Go toolchain nor network access to generate api/.
// It is a faithful port of ogen's cmd/ogen generate(): parse -> build IR ->
// (clean) -> FormattedSource.WriteSource, with ogen's default options (matching
// a bare invocation with no ogen.yaml / flags).
func generateAPI(specData []byte, packageName, targetDir string) error {
	spec, err := ogen.Parse(specData)
	if err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}

	g, err := gen.NewGenerator(spec, gen.Options{})
	if err != nil {
		return fmt.Errorf("build IR: %w", err)
	}

	// Clean the target dir of previously-generated ogen files, then (re)create
	// it — same order as ogen's cmd (only after parse + IR build succeed).
	switch files, err := os.ReadDir(targetDir); {
	case os.IsNotExist(err):
		if err := os.MkdirAll(targetDir, 0o750); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if err := cleanOgenDir(targetDir, files); err != nil {
			return fmt.Errorf("clean: %w", err)
		}
	}

	// Format:false — WriteSource already runs imports.Process (go/format).
	fs := genfs.FormattedSource{Format: false, Root: targetDir}
	if err := g.WriteSource(fs, packageName); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// cleanOgenDir removes ogen-generated files (oas_*_gen.go / openapi_*_gen.go and
// their _gen_test.go siblings) before regeneration, matching ogen cmd's
// cleanDir so hand-authored files in the target dir are left untouched.
func cleanOgenDir(targetDir string, files []os.DirEntry) (rerr error) {
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, "_gen.go") && !strings.HasSuffix(name, "_gen_test.go") {
			continue
		}
		if !strings.HasPrefix(name, "openapi") && !strings.HasPrefix(name, "oas") {
			continue
		}
		if err := os.Remove(filepath.Join(targetDir, name)); err != nil && !os.IsNotExist(err) {
			rerr = errors.Join(rerr, err)
		}
	}
	return rerr
}
