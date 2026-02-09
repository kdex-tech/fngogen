package main

import (
	"fmt"
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

	// get the current directory
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Could not get current directory: %v\n", err)
		return
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
			name:    "with apiKey security",
			openapi: `../../test-fixtures/openapi-spec-apikey.json`,
			workDir: "t6",
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
				fmt.Printf("Could not change directory: %v\n", err)
				return
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
