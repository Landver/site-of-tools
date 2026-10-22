package mcptools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
)

const maxResult = 80 << 10

// Lists are never cut: the dropped item can be the one that matters.
func sanitize(r *mcp.CallToolResult) (*mcp.CallToolResult, int, error) {
	if r.IsError {
		for _, c := range r.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				t.Text = platform.Clip(clean(t.Text), maxResult)
			}
		}
		return r, 0, nil
	}
	obj, err := object(r.StructuredContent)
	if err != nil || obj == nil {
		return nil, 0, fmt.Errorf("structuredContent is not a JSON object (%v)", err)
	}
	out, err := encode(walk(obj))
	if err != nil {
		return nil, 0, err
	}
	if len(out) > maxResult {
		return errorResult(fmt.Sprintf("Result too large: %d KB, over the %d KB one call may return. Ask for less: leave detailed off, or narrow the input.",
			len(out)>>10, maxResult>>10)), 0, nil
	}
	r.StructuredContent = json.RawMessage(out)
	r.Content = []mcp.Content{&mcp.TextContent{Text: string(out)}}
	return r, len(out), nil
}

func walk(v any) any {
	switch t := v.(type) {
	case string:
		return clean(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[clean(k)] = walk(e)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = walk(e)
		}
	}
	return v
}

func clean(s string) string {
	if !strings.ContainsFunc(s, invisible) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if invisible(r) {
			fmt.Fprintf(&b, `\u{%04X}`, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// invisible: characters that hide text or carry text a reader never sees, Hangul fillers among them.
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
