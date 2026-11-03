package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"strings"
)

// rawResponseExtension is ogen's per-media-type escape hatch: the operation's
// handler moves to the generated RawHandler interface and receives the
// http.ResponseWriter, so it can write and flush the stream itself. ogen's
// security handler still runs first.
const rawResponseExtension = "x-ogen-raw-response"

const eventStreamMediaType = "text/event-stream"

// prepareSpec first marks every text/event-stream response media type with
// x-ogen-raw-response: true, so a spec that declares server-sent events
// generates a handler that can actually stream, then rewrites security to
// bearer-only (see bearerOnlySecurity). An explicit x-ogen-raw-response on the
// media type is left as the author set it. When nothing needed marking or
// rewriting, the input is returned unchanged (byte-for-byte), so the step is
// invisible to every function that neither streams nor declares a non-bearer
// scheme. Each scopelessNonBearerWarnings line is written to warnings, prefixed
// "warning: ", once the spec is prepared.
//
// WORKAROUND for ogen, which runs at @latest (v1.24.0 as of 2026-10-01):
//   - a typed text/event-stream response fails server generation with
//     `Feature "sse server response encoding" is not implemented yet`
//     (ogen-go/ogen#1742, open, no release fixes it);
//   - an untyped one (type: string / format: binary / no schema) generates an
//     io.Reader response that ogen io.Copy's without flushing, so events
//     arrive only when the stream ends.
//
// Delete this step once ogen ships typed SSE server encoding (#1742) whose
// encoder flushes per event. See kdex-tech/fngogen#9.
func prepareSpec(spec []byte, warnings io.Writer) ([]byte, bool, error) {
	doc, err := decodeSpec(spec)
	if err != nil {
		return nil, false, err
	}

	changed := false
	if paths, ok := doc["paths"].(map[string]any); ok {
		for _, item := range paths {
			pathItem, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for _, op := range pathItem {
				operation, ok := op.(map[string]any)
				if !ok {
					continue
				}
				if responses, ok := operation["responses"].(map[string]any); ok {
					changed = markResponses(responses) || changed
				}
			}
		}
	}
	if components, ok := doc["components"].(map[string]any); ok {
		if responses, ok := components["responses"].(map[string]any); ok {
			changed = markResponses(responses) || changed
		}
	}

	// Before the rewrite, which erases the scheme names the warnings read.
	warned, err := scopelessNonBearerWarnings(doc)
	if err != nil {
		return nil, false, err
	}
	secChanged, err := bearerOnlySecurity(doc)
	if err != nil {
		return nil, false, err
	}
	changed = secChanged || changed
	for _, w := range warned {
		_, _ = fmt.Fprintf(warnings, "warning: %s\n", w)
	}

	if !changed {
		return spec, false, nil
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// decodeSpec decodes an OpenAPI document for rewriting or reading, keeping
// every number as its json.Number literal. Decoded as float64, a number above
// 2^53 is rounded and re-encodes changed: int64's maximum comes back as
// 9223372036854776000, which ogen rejects as out of range, and a large enum
// value silently becomes another. Like json.Unmarshal, it rejects trailing
// data after the document.
func decodeSpec(spec []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(spec))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid JSON: data after the top-level value")
	}
	return doc, nil
}

// markResponses marks the event-stream media types of every response in a
// responses map (an operation's, or components.responses). A $ref'd response
// has no content of its own and is marked where it is declared.
func markResponses(responses map[string]any) bool {
	changed := false
	for _, r := range responses {
		response, ok := r.(map[string]any)
		if !ok {
			continue
		}
		content, ok := response["content"].(map[string]any)
		if !ok {
			continue
		}
		for mediaType, m := range content {
			media, ok := m.(map[string]any)
			if !ok || !isEventStream(mediaType) {
				continue
			}
			if _, set := media[rawResponseExtension]; set {
				continue
			}
			media[rawResponseExtension] = true
			changed = true
		}
	}
	return changed
}

func isEventStream(mediaType string) bool {
	parsed, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return strings.EqualFold(strings.TrimSpace(mediaType), eventStreamMediaType)
	}
	return parsed == eventStreamMediaType
}

// prepareSpecFile applies prepareSpec to the spec at path, rewriting the file
// only when something was marked.
func prepareSpecFile(path string) error {
	spec, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, changed, err := prepareSpec(spec, os.Stderr)
	if err != nil || !changed {
		return err
	}
	return os.WriteFile(path, out, 0644)
}
