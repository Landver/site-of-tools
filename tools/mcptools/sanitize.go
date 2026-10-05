package mcptools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxString = 2 << 10 // keeps a 4096-bit DKIM key whole
	maxResult = 80 << 10
)

var errNotObject = errors.New("structuredContent is not a JSON object")

// sanitize caps strings (unless whole) and shows invisible characters, but
// never cuts a list: the dropped item can be the one that matters.
func sanitize(r *mcp.CallToolResult, narrow string, whole bool) (*mcp.CallToolResult, int, error) {
	if r.IsError {
		for _, c := range r.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				t.Text = clean(t.Text, maxString)
			}
		}
		return r, 0, nil
	}
	raw, err := json.Marshal(r.StructuredContent)
	if err != nil {
		return nil, 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, 0, errNotObject
	}
	limit := maxString
	if whole {
		limit = maxResult
	}
	out, err := encode(walk(obj, limit))
	if err != nil {
		return nil, 0, err
	}
	if len(out) > maxResult {
		msg := fmt.Sprintf("Result too large: %d KB, over the %d KB one call may return.", len(out)>>10, maxResult>>10)
		if narrow != "" {
			msg += " " + narrow
		}
		return errorResult(msg), 0, nil
	}
	s := *r
	s.StructuredContent = json.RawMessage(out)
	s.Content = []mcp.Content{&mcp.TextContent{Text: string(out)}}
	return &s, len(out), nil
}

func walk(v any, limit int) any {
	switch t := v.(type) {
	case string:
		return clean(t, limit)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[clean(k, limit)] = walk(e, limit)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = walk(e, limit)
		}
	}
	return v
}

func clean(s string, limit int) string {
	if strings.ContainsFunc(s, invisible) {
		var b strings.Builder
		for _, r := range s {
			if invisible(r) {
				fmt.Fprintf(&b, `\u{%04X}`, r)
			} else {
				b.WriteRune(r)
			}
		}
		s = b.String()
	}
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s…[truncated %d bytes]", s[:cut], len(s)-cut)
}

// invisible: characters that hide text or carry text a reader never sees:
// format, tag block, variation selectors, DEL, C1, U+2028/9, Hangul fillers.
func invisible(r rune) bool {
	switch r {
	case 0x7F, 0x2028, 0x2029, 0x115F, 0x1160, 0x3164, 0xFFA0:
		return true
	}
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) ||
		(r >= 0x80 && r <= 0x9F) || (r >= 0xE0000 && r <= 0xE007F)
}

// encode skips HTML escaping: \u0026 for every & in a URL costs a model tokens.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func errorResult(msg string) *mcp.CallToolResult {
	r := &mcp.CallToolResult{}
	r.SetError(errors.New(msg))
	return r
}
