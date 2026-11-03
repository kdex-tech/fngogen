package main

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
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
// securityOf), as is a path item it cannot see into (see eachOperation), and
// doc must then be discarded: it may be partly rewritten.
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
	if err := eachOperation(doc, func(key string, op map[string]any) error {
		return rewrite(op, "security of "+key)
	}); err != nil {
		return false, err
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

// eachOperation calls fn with the "METHOD /path" key of every operation in
// doc's paths, in path then bindingMethods order, so errors and warnings come
// out in a stable order. A path item holding operations outside the fixed
// method fields is an error naming its shape, before fn sees any of its
// operations: neither the security rewrite nor the requirement table can see
// into it, so its operations would keep their declared schemes at ogen and get
// no requirement entry. That fails closed, but only at request time and
// without saying why. kdex-fnnodejsgen's src/parse.ts rejects the same shapes.
func eachOperation(doc map[string]any, fn func(key string, op map[string]any) error) error {
	paths, _ := doc["paths"].(map[string]any)
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		item, ok := paths[path].(map[string]any)
		if !ok {
			continue
		}
		if _, ok := item["$ref"]; ok {
			return fmt.Errorf("path %s: a path item $ref is not supported: generation cannot see the operations it points to; declare them inline", path)
		}
		for _, field := range []string{"query", "additionalOperations"} {
			if _, ok := item[field]; ok {
				return fmt.Errorf("path %s: the OpenAPI 3.2 path item field %q is not supported: generation cannot see the operations it holds", path, field)
			}
		}
		for _, method := range bindingMethods {
			if op, ok := item[method].(map[string]any); ok {
				if err := fn(strings.ToUpper(method)+" "+path, op); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// effectiveSecurity returns the alternatives guarding the operation at key:
// its own, else the top-level ones when it has no security key or a null one,
// as ogen reads them.
func effectiveSecurity(top []any, op map[string]any, key string) ([]any, error) {
	own, present, err := securityOf(op, "security of "+key)
	if err != nil {
		return nil, err
	}
	if present {
		return own, nil
	}
	return top, nil
}

// scopelessNonBearerWarnings names each operation guarded by a non-empty
// alternative declared only under non-bearer schemes whose strings union to
// none, such as [{"apiKeyHeader": []}]. Rewritten to {"bearer": []}, it admits
// any valid FAT. Such specs are legal and common (knowdb's), so this is a
// warning, not an error; but an author who declared an apiKey may have meant
// more. A scheme counts as bearer by its name, as the rewrite emits it. It
// must run before bearerOnlySecurity, which erases the scheme names. Its
// counterpart in kdex-fnnodejsgen is src/parse.ts; the wording is shared.
func scopelessNonBearerWarnings(doc map[string]any) ([]string, error) {
	top, _, err := securityOf(doc, "top-level security")
	if err != nil {
		return nil, err
	}
	var warnings []string
	err = eachOperation(doc, func(key string, op map[string]any) error {
		sec, err := effectiveSecurity(top, op, key)
		if err != nil {
			return err
		}
		for _, a := range sec {
			alt := a.(map[string]any)
			if _, bearer := alt[bearerSchemeName]; bearer || len(alt) == 0 {
				continue
			}
			union, err := unionAlternative(alt)
			if err != nil {
				return fmt.Errorf("security of %s: %w", key, err)
			}
			if len(union) == 0 {
				warnings = append(warnings, key+`: an alternative with no requirement strings under non-bearer schemes becomes "any valid FAT" at the function`)
				return nil
			}
		}
		return nil
	})
	return warnings, err
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
