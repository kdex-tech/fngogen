package main

import (
	"fmt"
	"strings"
)

// operationRequirements builds the per-operation authorization table the
// generated server enforces. ogen merges same-scheme security alternatives
// into one AND list, so the generated code cannot rely on ogen's view of the
// spec; it authorizes from this table of the ORIGINAL alternatives instead.
//
// Keys are "METHOD /path", the key format of entitlementBindings. Each value
// holds one []string per non-empty alternative (the union of that alternative's
// scheme strings, via unionAlternative), in declaration order; satisfying any
// one alternative admits the call. An operation inherits the top-level
// security when it has no security key or a null one, as ogen does. An
// operation whose effective security is [] or contains only {} alternatives
// has no entry, and {} alternatives are dropped from an operation that also
// has non-empty ones. The result is the same for a prepared and an unprepared
// spec. A malformed security value is an error (see securityOf and
// unionAlternative): generation fails rather than drop or weaken a requirement.
func operationRequirements(spec map[string]any) (map[string][][]string, error) {
	table := map[string][][]string{}
	top, _, err := securityOf(spec, "top-level security")
	if err != nil {
		return nil, err
	}
	paths, _ := spec["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for _, method := range bindingMethods {
			op, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			sec := top
			own, present, err := securityOf(op, "security of "+key)
			if err != nil {
				return nil, err
			}
			if present {
				sec = own
			}
			var alts [][]string
			for _, a := range sec {
				if alt := a.(map[string]any); len(alt) > 0 {
					union, err := unionAlternative(alt)
					if err != nil {
						return nil, fmt.Errorf("security of %s: %w", key, err)
					}
					alts = append(alts, union)
				}
			}
			if len(alts) > 0 {
				table[key] = alts
			}
		}
	}
	return table, nil
}
