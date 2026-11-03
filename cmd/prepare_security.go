package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// bearerSchemeName is the one security scheme a prepared spec keeps: the
// host-minted JWT (FAT) presented as a bearer token.
const bearerSchemeName = "bearer"

// bearerOnlySecurity rewrites every security alternative of the spec (the
// top-level one and each operation's) to bearer-only, so a generated function
// accepts only the host-minted JWT whatever scheme the author declared. A
// non-empty alternative becomes {"bearer": <union of its schemes' strings>};
// an empty alternative ({}) stays empty, an operation without a security key
// (or with security: null) is left to inherit, and security: [] stays an
// explicit opt-out. When any scheme is still referenced,
// components.securitySchemes becomes exactly the canonical bearer scheme. It
// reports whether doc changed; a spec already in canonical form, or with no
// security at all, reports false. A malformed security value is an error (see
// securityOf), and doc must then be discarded: it may be partly rewritten.
func bearerOnlySecurity(doc map[string]any) (bool, error) {
	changed := false
	used := false
	rewrite := func(holder map[string]any, where string) error {
		sec, present, err := securityOf(holder, where)
		if err != nil || !present {
			return err
		}
		out := make([]any, len(sec))
		for i, a := range sec {
			alt := a.(map[string]any)
			if len(alt) == 0 {
				out[i] = a
				continue
			}
			used = true
			scopes, err := unionAlternative(alt)
			if err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
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
		return nil
	}

	if err := rewrite(doc, "top-level security"); err != nil {
		return false, err
	}
	if paths, ok := doc["paths"].(map[string]any); ok {
		for path, item := range paths {
			pathItem, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for _, method := range bindingMethods {
				if operation, ok := pathItem[method].(map[string]any); ok {
					if err := rewrite(operation, "security of "+strings.ToUpper(method)+" "+path); err != nil {
						return false, err
					}
				}
			}
		}
	}

	if !used {
		return changed, nil
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
	return changed, nil
}

// securityOf returns holder's security alternatives (the spec's top-level
// security, or an operation's), each a map[string]any. present is false when
// the key is absent or JSON null, which ogen reads alike: the operation
// inherits the top-level security. Any other value that is not an array of
// objects is an error naming where: ogen rejects such a spec, and skipping the
// value here would drop the requirement it meant to state.
func securityOf(holder map[string]any, where string) (alts []any, present bool, err error) {
	raw, ok := holder["security"]
	if !ok || raw == nil {
		return nil, false, nil
	}
	sec, ok := raw.([]any)
	if !ok {
		return nil, false, fmt.Errorf("%s: want an array of requirement objects, got %T", where, raw)
	}
	for i, a := range sec {
		if _, ok := a.(map[string]any); !ok {
			return nil, false, fmt.Errorf("%s: alternative %d: want an object, got %T", where, i, a)
		}
	}
	return sec, true, nil
}

// unionAlternative flattens one security alternative into a single string
// list: the strings of each scheme in sorted scheme-name order (map order is
// random, the output must be stable), first occurrence kept, duplicates
// dropped. It never returns a nil list. A scheme value that is not an array of
// strings is an error: read leniently, {"oauth2": "users:write"} would become
// a requirement any valid token satisfies.
func unionAlternative(alt map[string]any) ([]string, error) {
	names := make([]string, 0, len(alt))
	for name := range alt {
		names = append(names, name)
	}
	sort.Strings(names)

	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		list, ok := alt[name].([]any)
		if !ok {
			return nil, fmt.Errorf("security scheme %q: want an array of strings, got %T", name, alt[name])
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("security scheme %q: want an array of strings, got an element of %T", name, v)
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}
