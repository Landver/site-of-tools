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

// sanitize readies a tool result for a model: in structuredContent every
// string is capped and its invisible characters shown, the text block is
// rebuilt from that same JSON, and no list is ever cut, since the one dropped
// item can be the one that matters. A result still over maxResult becomes an
// error saying how to ask for less. It returns the JSON size sent.
func sanitize(r *mcp.CallToolResult, narrow string) (*mcp.CallToolResult, int, error) {
	if r.IsError {
		for _, c := range r.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				t.Text = clean(t.Text)
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
	out, err := encode(walk(obj))
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

// clean shows what s holds: characters that change how text renders without
// being seen become \u{XXXX}, then anything past maxString is cut on a rune
// boundary, with a marker saying how much went.
func clean(s string) string {
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
	if len(s) <= maxString {
		return s
	}
	cut := maxString
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%s…[truncated %d bytes]", s[:cut], len(s)-cut)
}

// invisible: format characters (bidi controls and isolates, zero-width
// characters, the BOM) and the Unicode tag block, which can carry text a
// reader never sees.
func invisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || (r >= 0xE0000 && r <= 0xE007F)
}

// encode is json.Marshal without HTML escaping: a model reads this text, and
// \u0026 for every & in a URL costs tokens and reads worse.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// errorResult is an isError result the model reads.
func errorResult(msg string) *mcp.CallToolResult {
	r := &mcp.CallToolResult{}
	r.SetError(errors.New(msg))
	return r
}
