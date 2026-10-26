package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/yaml"
)

// defaultServerURL is servers[0].url in the generated one-off document when
// --server-url is not given. It only affects the cosmetic server entry; pass
// your deploying host (e.g. https://dev.knowdrive.ai) to keep openapi-spec.json
// byte-identical to what the cluster commits.
const defaultServerURL = "http://localhost:8080"

// runLocal runs the whole codegen pipeline locally — the in-process, no-Docker
// equivalent of the image's entry-point.sh — from a KDexFunction CR (or an
// already-resolved spec). It writes openapi-spec.json, generates api/ via ogen
// (library), and renders cmd/{main,default,custom}.go, all without a cluster
// round-trip. It is gen-only: it does NOT run go mod tidy / vet / fmt (that
// needs the Go toolchain and is left to the caller). See kdex-tech/fngogen#2.
//
//	fngogen local --kdexfunction <cr.yaml> [--server-url URL] [--dir DIR] [--api-import PATH]
//	fngogen local --spec <openapi-spec.json>                   [--dir DIR] [--api-import PATH]
func runLocal(args []string) error {
	flags := flag.NewFlagSet("local", flag.ContinueOnError)
	crPath := flags.String("kdexfunction", "", "path to a KDexFunction CR YAML; its spec.api is resolved into the one-off OpenAPI doc")
	specIn := flags.String("spec", "", "path to an already-resolved one-off openapi-spec.json (alternative to --kdexfunction)")
	serverURL := flags.String("server-url", defaultServerURL, "servers[0].url in the generated doc (match your host for byte-identical output)")
	dir := flags.String("dir", ".", "the function directory to generate into (holds openapi-spec.json, api/, cmd/)")
	apiImport := flags.String("api-import", defaultAPIImport, "import path of the ogen-generated api package, for a head inside an existing module")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateAPIImport(*apiImport); err != nil {
		return err
	}

	if (*crPath == "") == (*specIn == "") {
		return fmt.Errorf("provide exactly one of --kdexfunction or --spec")
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}

	// 1. Obtain the resolved one-off document bytes.
	var specData []byte
	if *crPath != "" {
		doc, err := oneOffFromCR(*crPath, *serverURL)
		if err != nil {
			return err
		}
		specData = doc
	} else {
		data, err := os.ReadFile(*specIn)
		if err != nil {
			return fmt.Errorf("read --spec: %w", err)
		}
		specData = data
	}

	// Write openapi-spec.json (the committed, source-of-truth doc). entry-point.sh
	// wrote FUNCTION_API_SPEC via `echo` (trailing newline); match that.
	specPath := filepath.Join(*dir, "openapi-spec.json")
	if err := os.WriteFile(specPath, specData, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", specPath, err)
	}

	// Route text/event-stream responses to ogen's RawHandler, rewriting
	// openapi-spec.json in place exactly as entry-point.sh's `fngogen --prepare`
	// step does, so ogen and the templates see the same document the cluster
	// commits. See kdex-tech/fngogen#9.
	if err := prepareSpecFile(specPath); err != nil {
		return fmt.Errorf("prepare %s: %w", specPath, err)
	}
	specData, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}

	// 2. Generate api/ via ogen (in-process).
	apiDir := filepath.Join(*dir, "api")
	if err := generateAPI(specData, "api", apiDir); err != nil {
		return fmt.Errorf("ogen: %w", err)
	}

	// 3. Render cmd/{main,default,custom}.go from the generated Handler.
	cmdDir := filepath.Join(*dir, "cmd")
	if err := generateTemplates(filepath.Join(apiDir, "oas_server_gen.go"), specPath, cmdDir, *apiImport); err != nil {
		return fmt.Errorf("templates: %w", err)
	}

	fmt.Fprintf(os.Stderr, "generated %s, %s/, %s/ (gen-only: run `go mod tidy && go build ./...` to compile)\n", specPath, apiDir, cmdDir)
	return nil
}

// runBuildSpec resolves a KDexFunction CR's spec.api into the one-off OpenAPI
// document and writes it (default: stdout). This is BuildOneOff on its own —
// useful for inspecting or piping the doc without running the full pipeline.
//
//	fngogen build-spec --kdexfunction <cr.yaml> [--server-url URL] [-o out.json]
func runBuildSpec(args []string) error {
	flags := flag.NewFlagSet("build-spec", flag.ContinueOnError)
	crPath := flags.String("kdexfunction", "", "path to a KDexFunction CR YAML (required)")
	serverURL := flags.String("server-url", defaultServerURL, "servers[0].url in the generated doc")
	out := flags.String("o", "", "output path (default: stdout)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *crPath == "" {
		return fmt.Errorf("--kdexfunction is required")
	}

	doc, err := oneOffFromCR(*crPath, *serverURL)
	if err != nil {
		return err
	}

	if *out == "" || *out == "-" {
		_, err := os.Stdout.Write(doc)
		return err
	}
	return os.WriteFile(*out, doc, 0o644)
}

// oneOffFromCR decodes a KDexFunction CR and returns the resolved one-off
// OpenAPI document, marshaled exactly as host-manager does (MarshalIndent with
// a two-space indent) plus a trailing newline, so it is byte-identical to the
// cluster's committed openapi-spec.json.
func oneOffFromCR(crPath, serverURL string) ([]byte, error) {
	crBytes, err := os.ReadFile(crPath)
	if err != nil {
		return nil, fmt.Errorf("read KDexFunction: %w", err)
	}
	var fn kdexv1alpha1.KDexFunction
	if err := yaml.Unmarshal(crBytes, &fn); err != nil {
		return nil, fmt.Errorf("decode KDexFunction: %w", err)
	}
	if fn.Kind != "" && fn.Kind != "KDexFunction" {
		return nil, fmt.Errorf("%s is a %s, not a KDexFunction", crPath, fn.Kind)
	}

	doc := BuildOneOff(serverURL, &fn)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal one-off doc: %w", err)
	}
	return append(b, '\n'), nil
}
