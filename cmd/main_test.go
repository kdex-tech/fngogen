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
