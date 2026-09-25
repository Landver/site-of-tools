package linktools

import (
	"encoding/base64"
	"html"
	"net/url"
	"strconv"
	"strings"
)

// A14 — the encode/decode scratchpad.
//
// Crowded and undifferentiated as a category: urldecoder.org owns it and a
// hundred SEO farms sit behind it. It is here anyway because every operation is
// already implemented for the decode ladder, so exposing them is a template and
// a route rather than new logic — and because it is the page people search for
// by name.
//
// The one thing done better than the incumbents: query and path encoding shown
// SIDE BY SIDE. url.QueryEscape("a b") is "a+b" and url.PathEscape("a b") is
// "a%20b", and no surveyed tool makes that difference visible even though it is
// the single most common URL bug.

// Encoding is one representation of the input value.
type Encoding struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
	Err   string `json:"error,omitempty"`
}

// EncodeResult is every reading of one value at once, rather than a dropdown.
// Seeing them together is the entire value of the page.
type EncodeResult struct {
	Input   string     `json:"input"`
	Encoded []Encoding `json:"encoded"`
	Decoded []Encoding `json:"decoded"`
	Layers  []Layer    `json:"layers,omitempty"`
	Kind    Kind       `json:"kind,omitempty"`
}

// EncodeAll computes every representation of v.
func EncodeAll(v string) *EncodeResult {
	r := &EncodeResult{Input: v, Kind: classify(v)}

	r.Encoded = []Encoding{
		{Name: "Percent (query)", Value: url.QueryEscape(v),
			Note: "Form rules: a space becomes '+'. Correct after '?' and wrong inside a path."},
		{Name: "Percent (path)", Value: url.PathEscape(v),
			Note: "A space becomes %20 and '+' stays a literal '+'. Correct inside a path segment."},
		{Name: "Base64", Value: base64.StdEncoding.EncodeToString([]byte(v))},
		{Name: "Base64 (URL-safe)", Value: base64.URLEncoding.EncodeToString([]byte(v)),
			Note: "Uses '-' and '_' instead of '+' and '/', so it survives being put in a URL."},
		{Name: "HTML entities", Value: html.EscapeString(v)},
		{Name: "Unicode escapes", Value: unicodeEscape(v)},
	}

	r.Decoded = []Encoding{
		decodeEntry("Percent (query)", v, func(s string) (string, error) { return url.QueryUnescape(s) },
			"'+' is read as a space here."),
		decodeEntry("Percent (path)", v, func(s string) (string, error) { return url.PathUnescape(s) },
			"'+' is left alone here. Use this reading for a path segment, or for a base64 value."),
		// Padded first, then the raw (unpadded) variant. Without the fallback
		// this table called a value "illegal base64" while the decode ladder
		// immediately below it — which does try the raw encodings — showed the
		// decoded text. One page, two contradictory answers about one value.
		decodeEntry("Base64", v, func(s string) (string, error) {
			return decodeBase64(s, base64.StdEncoding, base64.RawStdEncoding)
		}, ""),
		decodeEntry("Base64 (URL-safe)", v, func(s string) (string, error) {
			return decodeBase64(s, base64.URLEncoding, base64.RawURLEncoding)
		}, ""),
		decodeEntry("HTML entities", v, func(s string) (string, error) { return html.UnescapeString(s), nil }, ""),
	}

	// The same ladder the Inspect page runs per parameter, so a doubly-encoded
	// value peels here too rather than needing a second paste.
	r.Layers = decodeLadder(v)
	return r
}

func decodeEntry(name, v string, fn func(string) (string, error), note string) Encoding {
	out, err := fn(v)
	e := Encoding{Name: name, Note: note}
	if err != nil {
		// Say the decode failed rather than showing the empty string it returns:
		// url.QueryUnescape yields "" plus an error on a bad escape, and an
		// empty box reads as "this value is empty", which is a different claim.
		e.Err = err.Error()
		return e
	}
	if !printable(out) {
		e.Err = "decodes to bytes that are not printable text"
		return e
	}
	e.Value = out
	return e
}

// unicodeEscape renders non-ASCII runes as \uXXXX, the form that turns up in
// JSON and JavaScript source.
func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 {
			b.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			b.WriteString("\\U" + strings.ToUpper(pad(strconv.FormatInt(int64(r), 16), 8)))
			continue
		}
		b.WriteString("\\u" + strings.ToUpper(pad(strconv.FormatInt(int64(r), 16), 4)))
	}
	return b.String()
}

func pad(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

// decodeBase64 tries the padded encoding, then the unpadded one. Real-world
// base64 in URLs is unpadded about as often as not, because "=" has to be
// percent-encoded in a query.
func decodeBase64(s string, padded, raw *base64.Encoding) (string, error) {
	if b, err := padded.DecodeString(s); err == nil {
		return string(b), nil
	}
	b, err := raw.DecodeString(s)
	return string(b), err
}
