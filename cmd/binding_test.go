package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntitlementBindings(t *testing.T) {
	var spec map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{
		"paths": {
			"/v1/stores": {
				"post": {"x-entitlement-binding": {"store": [
					{"in": "header", "name": "X-Store-Id"},
					{"in": "query", "name": "store"}
				]}},
				"get": {"security": [{"bearer": ["stores:read"]}]}
			},
			"/v1/stores/{id}": {
				"x-kdex-type": "FUNCTION",
				"put": {"x-entitlement-binding": {"store": [{"in": "path", "name": "id"}]}},
				"delete": {"x-entitlement-binding": {"store": [{"in": "body", "name": "store"}]}},
				"patch": {"x-entitlement-binding": {"store": []}},
				"get": {"x-entitlement-binding": "store"}
			}
		}
	}`), &spec))

	got, warnings := entitlementBindings(spec)

	assert.Equal(t, map[string]map[string][]BindingSource{
		"POST /v1/stores":     {"store": {{In: "header", Name: "X-Store-Id"}, {In: "query", Name: "store"}}},
		"PUT /v1/stores/{id}": {"store": {{In: "path", Name: "id"}}},
	}, got)
	// A malformed declaration is dropped, so its placeholders stay unbound and
	// the operation fails closed -- the host gate's handling of the same CR.
	assert.Len(t, warnings, 3)
}
