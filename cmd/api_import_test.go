package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAPIImport(t *testing.T) {
	for _, ok := range []string{
		"function/api",
		"github.com/recoursellm/proxy-model/head/api",
		"example.com/svc/v2/head/api",
		"gopkg.in/x.v1/api",
	} {
		assert.NoError(t, validateAPIImport(ok), ok)
	}
	for _, bad := range []string{
		"",
		"api",                         // no module path in front of the package
		"function/oas",                // ogen always generates package api
		"function/api/",               // trailing slash
		"/function/api",               // absolute
		"function//api",               // empty element
		"../function/api",             // relative
		"./api",                       // relative
		"function/my api/api",         // space
		`function/api"; panic("x")//`, // would splice code into the generated import
		"function/api\nfoo",
	} {
		assert.Error(t, validateAPIImport(bad), "%q", bad)
	}
}
