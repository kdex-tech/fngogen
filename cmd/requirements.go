package main

import "fmt"

// operationRequirements builds the per-operation authorization table the
// generated server enforces. ogen merges same-scheme security alternatives
// into one AND list, so the generated code cannot rely on ogen's view of the
// spec; it authorizes from this table of the ORIGINAL alternatives instead.
//
// WORKAROUND for ogen, which runs at @latest (v1.24.0 as of 2026-11-01): its
// generated operationRoles<Scheme> holds ONE role list per operation per
// scheme, the union of every alternative's, so [{bearer:[a]},{bearer:[b,c]}]
// becomes roles [a b c], checked as one AND. ogen-go/ogen#1510 asks for the OR
// (open; its draft fix, PR #1535, was closed unmerged). Delete this table and
// its template counterpart once an ogen release keeps alternatives apart and
// hands the security handler the alternative it is checking.
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
// unionAlternative): generation fails rather than drop or weaken a requirement,
// as does a path item whose operations it cannot see (see eachOperation).
func operationRequirements(spec map[string]any) (map[string][][]string, error) {
	table := map[string][][]string{}
	top, _, err := securityOf(spec, "top-level security")
	if err != nil {
		return nil, err
	}
	err = eachOperation(spec, func(key string, op map[string]any) error {
		sec, err := effectiveSecurity(top, op, key)
		if err != nil {
			return err
		}
		var alts [][]string
		for _, a := range sec {
			if alt := a.(map[string]any); len(alt) > 0 {
				union, err := unionAlternative(alt)
				if err != nil {
					return fmt.Errorf("security of %s: %w", key, err)
				}
				alts = append(alts, union)
			}
		}
		if len(alts) > 0 {
			table[key] = alts
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return table, nil
}
