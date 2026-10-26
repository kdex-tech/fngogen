package main

import (
	"fmt"
	"regexp"
	"strings"
)

// defaultAPIImport is where the generated head finds the ogen package when it
// is its own `module function` (entry-point.sh's `go mod init function`).
const defaultAPIImport = "function/api"

var importPathElement = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// validateAPIImport checks an -api-import value before it is spliced into
// generated Go source (verbatim: the templates render with text/template). It
// must be a module-qualified import path whose last element is `api`, because
// entry-point.sh always runs ogen with `--target api`, which generates package
// api. See kdex-tech/fngogen#11.
func validateAPIImport(path string) error {
	elems := strings.Split(path, "/")
	if len(elems) < 2 || elems[len(elems)-1] != "api" {
		return fmt.Errorf("-api-import %q: must be a module-qualified import path ending in /api (ogen generates package api)", path)
	}
	for _, e := range elems {
		if e == "." || e == ".." || !importPathElement.MatchString(e) {
			return fmt.Errorf("-api-import %q: invalid import path element %q", path, e)
		}
	}
	return nil
}
