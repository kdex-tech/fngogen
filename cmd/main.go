package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/Masterminds/sprig/v3"
)

const targetPkg = "api" // The package prefix you want to add

// MethodData holds the info we need for the template
type MethodData struct {
	Name       string
	FullParams string // e.g., "ctx context.Context, req api.OptUser"
	ParamNames string // e.g., "ctx, req"
	Returns    string // e.g., "(*api.User, error)"
}

type TemplateData struct {
	APIKeySecurity        bool
	BearerSecurity        bool
	Methods               []MethodData
	OAuth2Security        bool
	OpenIdConnectSecurity bool
	Security              bool
}

//go:embed templates/main.go.tmpl
var mainTemplate string

//go:embed templates/default.go.tmpl
var defaultTemplate string

//go:embed templates/custom.go.tmpl
var customTemplate string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("app", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetPtr := flags.String("target", "cmd", "the target directory to generate the code")
	specPtr := flags.String("spec", "api/openapi.json", "the path to the openapi spec")

	if err := flags.Parse(args); err != nil {
		return err
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "api/oas_server_gen.go", nil, parser.ParseComments)
	if err != nil {
		return err
	}

	var methods []MethodData

	ast.Inspect(node, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Handler" {
			return true
		}
		inter, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}

		for _, method := range inter.Methods.List {
			fType, ok := method.Type.(*ast.FuncType)
			if !ok {
				continue
			}

			fullParams, names := parseParams(fset, fType.Params)
			methods = append(methods, MethodData{
				Name:       method.Names[0].Name,
				FullParams: fullParams,
				ParamNames: strings.Join(names, ", "),
				Returns:    stringifyFields(fset, fType.Results),
			})
		}
		return false
	})

	// read the openapi spec to check for all the security schemes implemented
	if _, err := os.Stat(*specPtr); err != nil {
		return err
	}

	content, err := os.ReadFile(*specPtr)
	if err != nil {
		return err
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(content, &spec); err != nil {
		return err
	}

	security := false
	apiKeySecurity := false
	bearerSecurity := false
	oauth2Security := false
	openIdConnectSecurity := false
	if spec["components"] != nil {
		if components, ok := spec["components"].(map[string]interface{}); ok {
			if securitySchemes, ok := components["securitySchemes"].(map[string]interface{}); ok {
				if len(securitySchemes) > 0 {
					security = true
				}
				for _, securityScheme := range securitySchemes {
					if securityScheme.(map[string]interface{})["type"] == "apiKey" {
						apiKeySecurity = true
					}
					if securityScheme.(map[string]interface{})["type"] == "http" {
						if securityScheme.(map[string]interface{})["scheme"] == "bearer" {
							bearerSecurity = true
						}
					}
					if securityScheme.(map[string]interface{})["type"] == "oauth2" {
						oauth2Security = true
					}
					if securityScheme.(map[string]interface{})["type"] == "openIdConnect" {
						openIdConnectSecurity = true
					}
				}
			}
		}
	}

	templateData := TemplateData{
		APIKeySecurity:        apiKeySecurity,
		BearerSecurity:        bearerSecurity,
		Methods:               methods,
		OAuth2Security:        oauth2Security,
		OpenIdConnectSecurity: openIdConnectSecurity,
		Security:              security,
	}

	if _, err := os.Stat(*targetPtr); err != nil {
		if err := os.MkdirAll(*targetPtr, 0755); err != nil {
			return err
		}
	}

	if err := generateSourceFile(mainTemplate, templateData, *targetPtr, "main.go", true); err != nil {
		return err
	}
	if err := generateSourceFile(defaultTemplate, templateData, *targetPtr, "default.go", true); err != nil {
		return err
	}
	if err := generateSourceFile(customTemplate, templateData, *targetPtr, "custom.go", false); err != nil {
		return err
	}

	return nil
}

func generateSourceFile(templateString string, templateData TemplateData, outputDir string, outputFileName string, overwrite bool) error {
	tmpl := template.Must(template.New("impl").Funcs(sprig.TxtFuncMap()).Parse(templateString))
	var implBuf bytes.Buffer
	if err := tmpl.Execute(&implBuf, templateData); err != nil {
		return err
	}

	formattedOut, err := format.Source(implBuf.Bytes())
	if err != nil {
		_ = os.WriteFile(outputDir+"/debug-"+outputFileName, implBuf.Bytes(), 0644)
		return err
	}

	if !overwrite {
		if _, err := os.Stat(outputDir + "/" + outputFileName); err == nil {
			return nil
		}
	}

	return os.WriteFile(outputDir+"/"+outputFileName, formattedOut, 0644)
}

func prefixType(expr ast.Expr, prefix string) ast.Expr {
	switch t := expr.(type) {
	case *ast.Ident:
		// Basic types like 'string', 'int', 'error', 'context' should NOT be prefixed
		// You can add more to this list as needed
		builtins := map[string]bool{"string": true, "int": true, "error": true, "bool": true, "context": true}
		if builtins[t.Name] {
			return t
		}
		// Return a SelectorExpr: prefix.Name
		return &ast.SelectorExpr{
			X:   ast.NewIdent(prefix),
			Sel: t,
		}
	case *ast.StarExpr:
		// Handle pointers recursively: *User -> *api.User
		t.X = prefixType(t.X, prefix)
		return t
	case *ast.ArrayType:
		// Handle slices: []User -> []api.User
		t.Elt = prefixType(t.Elt, prefix)
		return t
	case *ast.SelectorExpr:
		// Type is already prefixed (e.g., context.Context), leave it alone
		return t
	default:
		return expr
	}
}

func parseParams(fset *token.FileSet, list *ast.FieldList) (string, []string) {
	if list == nil {
		return "", nil
	}
	var full []string
	var names []string

	for i, field := range list.List {
		prefixedType := prefixType(field.Type, targetPkg)

		var typeBuf bytes.Buffer
		_ = printer.Fprint(&typeBuf, fset, prefixedType)
		typeStr := strings.ReplaceAll(strings.ReplaceAll(typeBuf.String(), "\n", ""), "\t", "")

		if len(field.Names) > 0 {
			for _, n := range field.Names {
				names = append(names, n.Name)
				full = append(full, fmt.Sprintf("%s %s", n.Name, typeStr))
			}
		} else {
			argName := fmt.Sprintf("arg%d", i)
			names = append(names, argName)
			full = append(full, fmt.Sprintf("%s %s", argName, typeStr))
		}
	}
	return strings.Join(full, ", "), names
}

func stringifyFields(fset *token.FileSet, list *ast.FieldList) string {
	if list == nil {
		return ""
	}
	var parts []string
	for _, f := range list.List {
		prefixedType := prefixType(f.Type, targetPkg)

		var b bytes.Buffer
		_ = printer.Fprint(&b, fset, prefixedType)
		bString := strings.ReplaceAll(strings.ReplaceAll(b.String(), "\n", ""), "\t", "")
		parts = append(parts, bString)
	}
	if len(parts) > 1 {
		return "(" + strings.Join(parts, ", ") + ")"
	}
	return strings.Join(parts, ", ")
}
