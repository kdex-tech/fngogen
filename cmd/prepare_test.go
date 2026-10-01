package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sseSpec is a minimal spec with one SSE operation whose text/event-stream
// media type is the given JSON object.
func sseSpec(media string) []byte {
	return []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	"paths":{"/v1/events":{"get":{"operationId":"streamEvents",
	"responses":{"200":{"description":"ok","content":{"text/event-stream":` + media + `}}}}}}}`)
}

// rawResponseAt decodes spec and returns the x-ogen-raw-response value at the
// given media type of GET /v1/events' 200 response (nil when absent).
func rawResponseAt(t *testing.T, spec []byte, mediaType string) any {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(spec, &doc))
	media := doc["paths"].(map[string]any)["/v1/events"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)[mediaType].(map[string]any)
	return media[rawResponseExtension]
}

func TestPrepareSpec_MarksTypedSSEResponseRaw(t *testing.T) {
	out, changed, err := prepareSpec(sseSpec(`{"schema":{"type":"object","properties":{"message":{"type":"string"}}}}`))
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, true, rawResponseAt(t, out, "text/event-stream"))
}

// The untyped (io.Reader) route generates, but ogen's encoder io.Copy's
// without flushing, so events reach the client only when the stream ends.
// It is marked raw too. See kdex-tech/fngogen#9.
func TestPrepareSpec_MarksUntypedSSEResponseRaw(t *testing.T) {
	out, changed, err := prepareSpec(sseSpec(`{"schema":{"type":"string"}}`))
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, true, rawResponseAt(t, out, "text/event-stream"))
}

func TestPrepareSpec_MatchesMediaTypeWithParameters(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	"paths":{"/v1/events":{"get":{"responses":{"200":{"description":"ok",
	"content":{"Text/Event-Stream; charset=utf-8":{"schema":{"type":"string"}}}}}}}}}`)
	out, changed, err := prepareSpec(spec)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, true, rawResponseAt(t, out, "Text/Event-Stream; charset=utf-8"))
}

// An author who set the extension explicitly -- either way -- keeps it.
func TestPrepareSpec_KeepsExplicitRawResponse(t *testing.T) {
	spec := sseSpec(`{"schema":{"type":"string"},"x-ogen-raw-response":false}`)
	out, changed, err := prepareSpec(spec)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, spec, out)
}

// A response declared once under components.responses and $ref'd from the
// operation is marked where it is declared.
func TestPrepareSpec_MarksComponentResponses(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	"paths":{"/v1/events":{"get":{"responses":{"200":{"$ref":"#/components/responses/Events"}}}}},
	"components":{"responses":{"Events":{"description":"ok","content":{"text/event-stream":{"schema":{"type":"string"}}}}}}}`)
	out, changed, err := prepareSpec(spec)
	require.NoError(t, err)
	assert.True(t, changed)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	media := doc["components"].(map[string]any)["responses"].(map[string]any)["Events"].(map[string]any)["content"].(map[string]any)["text/event-stream"].(map[string]any)
	assert.Equal(t, true, media[rawResponseExtension])
}

// Only responses are marked: the extension means nothing on a request body.
func TestPrepareSpec_LeavesRequestBodiesAlone(t *testing.T) {
	spec := []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	"paths":{"/v1/events":{"post":{"requestBody":{"content":{"text/event-stream":{"schema":{"type":"string"}}}},
	"responses":{"204":{"description":"ok"}}}}}}`)
	out, changed, err := prepareSpec(spec)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, spec, out)
}

// A spec with no SSE response is returned byte-for-byte, so the prepare step
// is invisible to every function that does not stream.
func TestPrepareSpec_NoSSEIsUnchanged(t *testing.T) {
	spec, err := os.ReadFile("../test-fixtures/openapi-spec.json")
	require.NoError(t, err)
	out, changed, err := prepareSpec(spec)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, spec, out)
}

func TestRun_PrepareRewritesSpecInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openapi-spec.json")
	require.NoError(t, os.WriteFile(path, sseSpec(`{"schema":{"type":"string"}}`), 0644))

	require.NoError(t, run([]string{"--prepare", "--spec", path}))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, true, rawResponseAt(t, out, "text/event-stream"))
}
