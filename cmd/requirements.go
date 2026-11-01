package main

import "strings"

// operationRequirements builds the per-operation authorization table the
// generated server enforces. ogen merges same-scheme security alternatives
// into one AND list, so the generated code cannot rely on ogen's view of the
// spec; it authorizes from this table of the ORIGINAL alternatives instead.
//
// Keys are "METHOD /path", the key format of entitlementBindings. Each value
// holds one []string per non-empty alternative (the union of that alternative's
// scheme strings, via unionAlternative), in declaration order; satisfying any
// one alternative admits the call. An operation inherits the top-level
// security when it has no security key. An operation whose effective security
// is [] or contains only {} alternatives has no entry, and {} alternatives are
// dropped from an operation that also has non-empty ones. The result is the
// same for a prepared and an unprepared spec.
func operationRequirements(spec map[string]any) map[string][][]string {
	table := map[string][][]string{}
	top, _ := spec["security"].([]any)
	paths, _ := spec["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for _, method := range bindingMethods {
			op, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			sec := top
			if own, ok := op["security"]; ok {
				sec, _ = own.([]any)
			}
			var alts [][]string
			for _, a := range sec {
				if alt, ok := a.(map[string]any); ok && len(alt) > 0 {
					alts = append(alts, unionAlternative(alt))
				}
			}
			if len(alts) > 0 {
				table[strings.ToUpper(method)+" "+path] = alts
			}
		}
	}
	return table
}
