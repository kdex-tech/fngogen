package main

import (
	"reflect"
	"sort"
)

// bearerSchemeName is the one security scheme a prepared spec keeps: the
// host-minted JWT (FAT) presented as a bearer token.
const bearerSchemeName = "bearer"

// bearerOnlySecurity rewrites every security alternative of the spec (the
// top-level one and each operation's) to bearer-only, so a generated function
// accepts only the host-minted JWT whatever scheme the author declared. A
// non-empty alternative becomes {"bearer": <union of its schemes' strings>};
// an empty alternative ({}) stays empty, an operation without a security key
// is left to inherit, and security: [] stays an explicit opt-out. When any
// scheme is still referenced, components.securitySchemes becomes exactly the
// canonical bearer scheme. It reports whether doc changed; a spec already in
// canonical form, or with no security at all, reports false.
func bearerOnlySecurity(doc map[string]any) bool {
	changed := false
	used := false
	rewrite := func(holder map[string]any) {
		sec, ok := holder["security"].([]any)
		if !ok {
			return
		}
		out := make([]any, len(sec))
		for i, a := range sec {
			alt, ok := a.(map[string]any)
			if !ok || len(alt) == 0 {
				out[i] = a
				continue
			}
			used = true
			scopes := unionAlternative(alt)
			list := make([]any, len(scopes))
			for j, s := range scopes {
				list[j] = s
			}
			out[i] = map[string]any{bearerSchemeName: list}
		}
		if !reflect.DeepEqual(sec, out) {
			holder["security"] = out
			changed = true
		}
	}

	rewrite(doc)
	if paths, ok := doc["paths"].(map[string]any); ok {
		for _, item := range paths {
			pathItem, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for _, method := range bindingMethods {
				if operation, ok := pathItem[method].(map[string]any); ok {
					rewrite(operation)
				}
			}
		}
	}

	if !used {
		return changed
	}
	canonical := map[string]any{bearerSchemeName: map[string]any{
		"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
	}}
	components, ok := doc["components"].(map[string]any)
	if !ok {
		components = map[string]any{}
		doc["components"] = components
	}
	if !reflect.DeepEqual(components["securitySchemes"], canonical) {
		components["securitySchemes"] = canonical
		changed = true
	}
	return changed
}

// unionAlternative flattens one security alternative into a single string
// list: the strings of each scheme in sorted scheme-name order (map order is
// random, the output must be stable), first occurrence kept, duplicates
// dropped. It never returns nil.
func unionAlternative(alt map[string]any) []string {
	names := make([]string, 0, len(alt))
	for name := range alt {
		names = append(names, name)
	}
	sort.Strings(names)

	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		list, _ := alt[name].([]any)
		for _, v := range list {
			if s, ok := v.(string); ok && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
