package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_run(t *testing.T) {
	if _, err := os.Stat("../tmp"); err != nil {
		if err := os.MkdirAll("../tmp", 0755); err != nil {
			t.Fatalf("failed to create tmp dir: %v", err)
		}
	}

	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Could not get current directory: %v\n", err)
	}

	tests := []struct {
		name      string
		openapi   string
		workDir   string
		targetDir string
	}{
		{
			name:    "default target dir",
			openapi: `../../test-fixtures/openapi-spec.json`,
			workDir: "t1",
		},
		{
			name:      "non-default target dir",
			openapi:   `../../test-fixtures/openapi-spec.json`,
			workDir:   "t2",
			targetDir: "test",
		},
		{
			name:    "with content-less response",
			openapi: `../../test-fixtures/openapi-spec-contentless.json`,
			workDir: "t9",
		},
		{
			name:    "with bearer security",
			openapi: `../../test-fixtures/openapi-spec-bearer.json`,
			workDir: "t3",
		},
		{
			name:    "with bearer security 2",
			openapi: `../../test-fixtures/openapi-spec-bearer-2.json`,
			workDir: "t4",
		},
		{
			name:    "with oauth2 security",
			openapi: `../../test-fixtures/openapi-spec-oauth2.json`,
			workDir: "t5",
		},
		{
			name:    "with apiKey security - cookie",
			openapi: `../../test-fixtures/openapi-spec-apikey-cookie.json`,
			workDir: "t6",
		},
		{
			name:    "with apiKey security - header",
			openapi: `../../test-fixtures/openapi-spec-apikey-header.json`,
			workDir: "t7",
		},
		{
			name:    "with apiKey security - query",
			openapi: `../../test-fixtures/openapi-spec-apikey-query.json`,
			workDir: "t8",
		},
		// OpenID Connect security is not implemented yet in ogen
		// {
		// 	name:    "with openIdConnect security",
		// 	openapi: `../../test-fixtures/openapi-spec-openIdConnect.json`,
		// 	workDir: "t7",
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat("../tmp/" + tt.workDir); err == nil {
				if err := os.RemoveAll("../tmp/" + tt.workDir); err != nil {
					t.Fatalf("failed to remove work dir: %v", err)
				}
			}
			if err := os.MkdirAll("../tmp/"+tt.workDir, 0755); err != nil {
				t.Fatalf("failed to create work dir: %v", err)
			}
			//defer os.RemoveAll("../tmp/" + tt.workDir)
			err := os.Chdir("../tmp/" + tt.workDir)
			if err != nil {
				t.Fatalf("Could not change directory: %v\n", err)
			}
			defer func() {
				_ = os.Chdir(currentDir)
			}()

			goModInit := exec.Command("go", "mod", "init", "function")
			_, err = goModInit.Output()
			if !assert.NoError(t, err) {
				return
			}

			generateFile := fmt.Sprintf(`package project

//go:generate go run github.com/ogen-go/ogen/cmd/ogen@latest --target api --clean %s
`, tt.openapi)
			if err := os.WriteFile("generate.go", []byte(generateFile), 0644); err != nil {
				t.Fatalf("failed to write generate.go: %v", err)
			}

			goGenerate := exec.Command("go", "generate", "./...")
			out, err := goGenerate.CombinedOutput()
			if !assert.NoError(t, err, string(out)) {
				return
			}

			args := []string{}
			if tt.targetDir != "" {
				args = append(args, "--target", tt.targetDir)
			}
			if tt.openapi != "" {
				args = append(args, "--spec", tt.openapi)
			}

			targetDir := tt.targetDir
			if targetDir == "" {
				targetDir = "cmd"
			}

			if err := run(args); err != nil {
				t.Errorf("run() error = %v", err)
				return
			}

			goModTidy := exec.Command("go", "mod", "tidy")
			out, err = goModTidy.CombinedOutput()
			if !assert.NoError(t, err, string(out)) {
				return
			}

			assert.FileExists(t, targetDir+"/main.go")
			assert.FileExists(t, targetDir+"/default.go")
			assert.FileExists(t, targetDir+"/custom.go")

			goBuild := exec.Command("go", "build", "./...")
			out, err = goBuild.CombinedOutput()
			assert.NoError(t, err, string(out))
		})
	}
}

// TestGenerate_BearerHandlerFlowsRawToken asserts the generated main.go
// stashes the raw inbound bearer token on the context (RFC 8693 token
// exchange support: a downstream handler/Exchange() call reads it back via
// RequestTokenFromContext).
func TestGenerate_BearerHandlerFlowsRawToken(t *testing.T) {
	if _, err := os.Stat("../tmp"); err != nil {
		if err := os.MkdirAll("../tmp", 0755); err != nil {
			t.Fatalf("failed to create tmp dir: %v", err)
		}
	}

	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Could not get current directory: %v\n", err)
	}

	workDir := "t10"
	if _, err := os.Stat("../tmp/" + workDir); err == nil {
		if err := os.RemoveAll("../tmp/" + workDir); err != nil {
			t.Fatalf("failed to remove work dir: %v", err)
		}
	}
	if err := os.MkdirAll("../tmp/"+workDir, 0755); err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}
	if err := os.Chdir("../tmp/" + workDir); err != nil {
		t.Fatalf("Could not change directory: %v\n", err)
	}
	defer func() {
		_ = os.Chdir(currentDir)
	}()

	goModInit := exec.Command("go", "mod", "init", "function")
	if _, err := goModInit.Output(); !assert.NoError(t, err) {
		return
	}

	openapi := "../../test-fixtures/openapi-spec-bearer.json"
	generateFile := fmt.Sprintf(`package project

//go:generate go run github.com/ogen-go/ogen/cmd/ogen@latest --target api --clean %s
`, openapi)
	if err := os.WriteFile("generate.go", []byte(generateFile), 0644); err != nil {
		t.Fatalf("failed to write generate.go: %v", err)
	}

	goGenerate := exec.Command("go", "generate", "./...")
	out, err := goGenerate.CombinedOutput()
	if !assert.NoError(t, err, string(out)) {
		return
	}

	if err := run([]string{"--spec", openapi}); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	generated, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	out2 := string(generated)

	assert.Contains(t, out2, "RequestTokenContextKey ContextKey")
	assert.Contains(t, out2, "func RequestTokenFromContext(ctx context.Context) (string, bool)")
	// HandleBearer must put the raw token into the context it returns
	assert.Contains(t, out2, "context.WithValue(ctx, RequestTokenContextKey, t.Token)")
}

// generateFixture drives the full ogen + fngogen generation for one fixture
// into ../tmp/<workDir>, leaving the process chdir'd there (restored on
// cleanup) so a focused generation test can read the generated files under
// cmd/. It mirrors Test_run's per-case setup without repeating it.
func generateFixture(t *testing.T, workDir, fixture string) {
	t.Helper()
	if err := os.MkdirAll("../tmp", 0755); err != nil {
		t.Fatalf("failed to create tmp dir: %v", err)
	}
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Could not get current directory: %v", err)
	}
	if _, err := os.Stat("../tmp/" + workDir); err == nil {
		if err := os.RemoveAll("../tmp/" + workDir); err != nil {
			t.Fatalf("failed to remove work dir: %v", err)
		}
	}
	if err := os.MkdirAll("../tmp/"+workDir, 0755); err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}
	if err := os.Chdir("../tmp/" + workDir); err != nil {
		t.Fatalf("Could not change directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(currentDir) })

	if _, err := exec.Command("go", "mod", "init", "function").Output(); err != nil {
		t.Fatalf("go mod init: %v", err)
	}
	// Mirror entry-point.sh: the spec lands as openapi-spec.json, is prepared
	// for ogen, then ogen and fngogen run over it.
	spec, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile("openapi-spec.json", spec, 0644); err != nil {
		t.Fatalf("write openapi-spec.json: %v", err)
	}
	if err := run([]string{"--prepare", "--spec", "openapi-spec.json"}); err != nil {
		t.Fatalf("run(--prepare) error = %v", err)
	}
	generateFile := `package project

//go:generate go run github.com/ogen-go/ogen/cmd/ogen@latest --target api --clean openapi-spec.json
`
	if err := os.WriteFile("generate.go", []byte(generateFile), 0644); err != nil {
		t.Fatalf("failed to write generate.go: %v", err)
	}
	if out, err := exec.Command("go", "generate", "./...").CombinedOutput(); err != nil {
		t.Fatalf("go generate: %v\n%s", err, out)
	}
	if err := run([]string{"--spec", "openapi-spec.json"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if out, err := exec.Command("go", "mod", "tidy").CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
}

// TestGenerate_SecurityExposesServerOptionsSeam asserts that when a spec
// declares security, generated main.go threads a hand-authored ServerOptions()
// into api.NewServer alongside NewSecurity(), and the never-overwritten
// custom.go scaffold defines that hook (defaulting to nil). This is the seam a
// consumer needs to combine the generated security handler with custom ogen
// ServerOptions such as api.WithMiddleware. Before the fix the security branch
// emitted only NewServer(NewHandler(), NewSecurity()), with nowhere to pass an
// option. See kdex-tech/fngogen#7.
func TestGenerate_SecurityExposesServerOptionsSeam(t *testing.T) {
	generateFixture(t, "t11", "../../test-fixtures/openapi-spec-bearer.json")

	mainSrc, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(mainSrc), "NewSecurity(), ServerOptions()...)",
		"generated main.go must thread ServerOptions() into NewServer alongside NewSecurity()")

	customSrc, err := os.ReadFile("cmd/custom.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(customSrc), "func ServerOptions() []api.ServerOption",
		"custom.go scaffold must define the hand-authored ServerOptions hook")

	if out, err := exec.Command("go", "build", "./...").CombinedOutput(); !assert.NoError(t, err, string(out)) {
		return
	}
}

// TestGenerate_NoSecurityOmitsServerOptionsSeam guards issue #7's backward-
// compatibility promise: a spec with no security scheme is untouched. main.go
// stays the bare NewServer(NewHandler()) — whose multi-value-return spread is
// the existing options seam — and custom.go gains no ServerOptions hook. See
// kdex-tech/fngogen#7.
func TestGenerate_NoSecurityOmitsServerOptionsSeam(t *testing.T) {
	generateFixture(t, "t12", "../../test-fixtures/openapi-spec.json")

	mainSrc, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.NotContains(t, string(mainSrc), "ServerOptions",
		"non-security main.go must not reference ServerOptions — the NewHandler() spread is its seam")

	customSrc, err := os.ReadFile("cmd/custom.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.NotContains(t, string(customSrc), "ServerOptions",
		"non-security custom.go scaffold must be unchanged")
}

func Test_generateSourceFile(t *testing.T) {
	err := generateSourceFile("{{.Name}}", TemplateData{}, "/invalid/path/that/does/not/exist", "out.go", true)
	if err == nil {
		t.Error("Expected error writing to invalid path")
		t.Log("BUG: Expected write to fail but it succeeded")
	}

	// Test template execution failure
	err = generateSourceFile("{{.InvalidMethod}}", TemplateData{}, ".", "out.go", true)
	if err == nil {
		t.Error("Expected error trying to execute invalid template")
	}
}

func Test_prefixType(t *testing.T) {
	// Test basic prefixing
	p := prefixType(&ast.Ident{Name: "context"}, "api")
	if _, ok := p.(*ast.Ident); !ok {
		t.Error("Expected Ident for context")
	}

	p2 := prefixType(&ast.Ident{Name: "MyType"}, "api")
	if sel, ok := p2.(*ast.SelectorExpr); !ok {
		t.Error("Expected SelectorExpr for MyType")
	} else if sel.X.(*ast.Ident).Name != "api" {
		t.Error("Expected X to be api")
	}

	// Make sure we test the case where we can't parse or fallthrough default
	p3 := prefixType(&ast.StarExpr{X: &ast.Ident{Name: "int"}}, "api")
	if star, ok := p3.(*ast.StarExpr); !ok {
		t.Error("Expected StarExpr")
	} else {
		if _, ok := star.X.(*ast.Ident); !ok {
			t.Error("Expected X to remain Ident int")
		}
	}

	// Test array type
	p4 := prefixType(&ast.ArrayType{Elt: &ast.Ident{Name: "User"}}, "api")
	if arr, ok := p4.(*ast.ArrayType); !ok {
		t.Error("Expected ArrayType")
	} else if sel, ok := arr.Elt.(*ast.SelectorExpr); !ok || sel.X.(*ast.Ident).Name != "api" {
		t.Error("Expected element to be api.User")
	}

	// Test selector expr leaves it alone
	p5 := prefixType(&ast.SelectorExpr{X: &ast.Ident{Name: "foo"}, Sel: &ast.Ident{Name: "bar"}}, "api")
	if _, ok := p5.(*ast.SelectorExpr); !ok {
		t.Error("Expected SelectorExpr to remain SelectorExpr")
	}
}

func Test_parseParamsAndStringifyFields(t *testing.T) {
	// Cover the nil inputs
	full, names := parseParams(token.NewFileSet(), nil)
	if full != "" || names != nil {
		t.Error("Expected empty results from nil field list")
	}

	str := stringifyFields(token.NewFileSet(), nil)
	if str != "" {
		t.Error("Expected empty result from nil field list")
	}
}

// TestGenerate_SSEBuilds is kdex-tech/fngogen#9: a spec declaring
// text/event-stream responses -- typed and untyped -- must generate a function
// that builds. The prepared spec routes those operations to ogen's
// RawHandler, which main.go must pass to api.NewServer, and whose constructor
// lives in its own never-overwritten custom_raw.go.
func TestGenerate_SSEBuilds(t *testing.T) {
	generateFixture(t, "t13", "../../test-fixtures/openapi-spec-sse.json")

	mainSrc, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(mainSrc), "api.NewServer(NewHandler(), NewRawHandler())")

	defaultSrc, err := os.ReadFile("cmd/default.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(defaultSrc), "var _ api.RawHandler = (*defaultRawHandler)(nil)")

	customRawSrc, err := os.ReadFile("cmd/custom_raw.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(customRawSrc), "func NewRawHandler() api.RawHandler")
	// Go source is rendered verbatim: the example's channel receives must not
	// be HTML-escaped into "&lt;-".
	assert.Contains(t, string(customRawSrc), "case <-ctx.Done():")

	if out, err := exec.Command("go", "build", "./...").CombinedOutput(); !assert.NoError(t, err, string(out)) {
		return
	}
}

// TestGenerate_SSEWithSecurityBuilds covers the raw handler alongside the
// generated security handler and the ServerOptions seam (#7).
func TestGenerate_SSEWithSecurityBuilds(t *testing.T) {
	generateFixture(t, "t14", "../../test-fixtures/openapi-spec-sse-bearer.json")

	mainSrc, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.Contains(t, string(mainSrc), "api.NewServer(NewHandler(), NewRawHandler(), NewSecurity(), ServerOptions()...)")

	if out, err := exec.Command("go", "build", "./...").CombinedOutput(); !assert.NoError(t, err, string(out)) {
		return
	}
}

// TestGenerate_SSEStreamsLiveAndIsGated drives the generated SSE function over
// HTTP: an operation implemented the way custom_raw.go's example shows must be
// security-gated and deliver each event as it is written, not at stream end.
// ogen runs at @latest, so this also guards against an ogen release that stops
// running security before raw handlers or breaks flushing through its
// response-writer wrapper. See kdex-tech/fngogen#9.
func TestGenerate_SSEStreamsLiveAndIsGated(t *testing.T) {
	generateFixture(t, "t15", "../../test-fixtures/openapi-spec-sse-bearer.json")

	probe := `package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"function/api"
)

type streamingHandler struct{ *defaultRawHandler }

func (streamingHandler) GenV1EventsGet(ctx context.Context, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	for i := 0; i < 3; i++ {
		if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
			return err
		}
		if err := rc.Flush(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(300 * time.Millisecond):
		}
	}
	return nil
}

type stubSecurity struct{}

func (stubSecurity) HandleBearer(ctx context.Context, _ api.OperationName, t api.Bearer) (context.Context, error) {
	if t.Token != "good" {
		return nil, errors.New("bad token")
	}
	return ctx, nil
}

func TestSSE(t *testing.T) {
	srv, err := api.NewServer(NewHandler(), streamingHandler{&defaultRawHandler{}}, stubSecurity{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer good")
	start := time.Now()
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if sc.Text() == "data: 0" {
			if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
				t.Fatalf("first event arrived after %v: the stream is buffered", elapsed)
			}
			return
		}
	}
	t.Fatal("no event received")
}
`
	if err := os.WriteFile("cmd/sse_probe_test.go", []byte(probe), 0644); !assert.NoError(t, err) {
		return
	}
	out, err := exec.Command("go", "test", "./cmd/", "-run", "TestSSE", "-count=1").CombinedOutput()
	assert.NoError(t, err, string(out))
}

// TestGenerate_NoSSEOmitsRawHandler guards #9's backward compatibility: a spec
// with no event-stream response generates exactly as before.
func TestGenerate_NoSSEOmitsRawHandler(t *testing.T) {
	generateFixture(t, "t16", "../../test-fixtures/openapi-spec.json")

	mainSrc, err := os.ReadFile("cmd/main.go")
	if !assert.NoError(t, err) {
		return
	}
	assert.NotContains(t, string(mainSrc), "RawHandler")
	assert.NoFileExists(t, "cmd/custom_raw.go")
}
