package main

import (
	"fmt"
	"strings"
)

// bindingExtensionKey is the operation-level OpenAPI extension declaring where
// a requirement placeholder's value comes from. host-manager's gate reads the
// same extension (internal/host/binding.go); the generated security mirrors it
// so the function binds a placeholder to the value the gate checked.
// See kdex-tech/fngogen#15.
const bindingExtensionKey = "x-entitlement-binding"

// BindingSource is one link in a placeholder's source chain: In is path, query
// or header, and Name is the parameter or header name. First match wins.
type BindingSource struct {
	In   string
	Name string
}

var bindingMethods = []string{"connect", "delete", "get", "head", "options", "patch", "post", "put", "trace"}

// entitlementBindings collects every operation's x-entitlement-binding, keyed
// "METHOD /path" like the host gate. Only sources the authorization layer can
// read are legal; a body source is not.
//
// A malformed declaration is reported as a warning and kept as a route with an
// EMPTY spec, which the generated code reads as "bind nothing": its
// placeholders stay unbound and the operation fails closed, even for one named
// like a path parameter -- falling back to the path would bind a source the
// author did not declare. That is what the host gate does with the same CR. A
// valid but empty declaration declares nothing and is omitted, so an empty spec
// always means malformed.
func entitlementBindings(spec map[string]any) (map[string]map[string][]BindingSource, []string) {
	bindings := map[string]map[string][]BindingSource{}
	var warnings []string
	paths, _ := spec["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for _, method := range bindingMethods {
			op, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			raw, ok := op[bindingExtensionKey]
			if !ok {
				continue
			}
			route := strings.ToUpper(method) + " " + path
			b, err := parseBindingSpec(raw)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: invalid %s, its placeholders will not bind: %v", route, bindingExtensionKey, err))
				bindings[route] = nil
				continue
			}
			if len(b) > 0 {
				bindings[route] = b
			}
		}
	}
	return bindings, warnings
}

func parseBindingSpec(raw any) (map[string][]BindingSource, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be an object mapping a placeholder key to a source chain")
	}
	spec := make(map[string][]BindingSource, len(obj))
	for key, v := range obj {
		list, ok := v.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("%s must be a non-empty array of sources", key)
		}
		chain := make([]BindingSource, 0, len(list))
		for i, entry := range list {
			m, _ := entry.(map[string]any)
			in, _ := m["in"].(string)
			name, _ := m["name"].(string)
			switch in {
			case "path", "query", "header":
			default:
				return nil, fmt.Errorf("%s[%d]: 'in' must be path, query or header (got %q)", key, i, in)
			}
			if name == "" {
				return nil, fmt.Errorf("%s[%d]: 'name' must not be empty", key, i)
			}
			chain = append(chain, BindingSource{In: in, Name: name})
		}
		spec[key] = chain
	}
	return spec, nil
}
