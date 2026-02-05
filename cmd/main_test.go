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
		os.MkdirAll("../tmp", 0755)
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
			name:    "with security",
			openapi: `../../test-fixtures/openapi-spec-sec.json`,
			workDir: "t3",
		},
		{
			name:    "with security 2",
			openapi: `../../test-fixtures/openapi-spec-2-sec.json`,
			workDir: "t4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat("../tmp/" + tt.workDir); err == nil {
				os.RemoveAll("../tmp/" + tt.workDir)
			}
			os.MkdirAll("../tmp/"+tt.workDir, 0755)
			//defer os.RemoveAll("../tmp/" + tt.workDir)
			err := os.Chdir("../tmp/" + tt.workDir)
			if err != nil {
				fmt.Printf("Could not change directory: %v\n", err)
				return
			}
			defer os.Chdir(currentDir)

			goModInit := exec.Command("go", "mod", "init", "function")
			_, err = goModInit.Output()
			if !assert.NoError(t, err) {
				return
			}

			generateFile := fmt.Sprintf(`package project

//go:generate go run github.com/ogen-go/ogen/cmd/ogen@latest --target api --clean %s
`, tt.openapi)
			os.WriteFile("generate.go", []byte(generateFile), 0644)

			goGenerate := exec.Command("go", "generate", "./...")
			_, err = goGenerate.Output()
			if !assert.NoError(t, err) {
				return
			}

			args := []string{}
			if tt.targetDir != "" {
				args = append(args, "--target", tt.targetDir)
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
			_, err = goModTidy.Output()
			if !assert.NoError(t, err) {
				return
			}

			assert.FileExists(t, targetDir+"/main.go")
			assert.FileExists(t, targetDir+"/impl.go")
		})
	}
}
