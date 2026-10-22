package linktools

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Query and path escaping sit side by side: "a+b" vs "a%20b" is the most common URL bug.

// Encoding is one representation of the input value.
type Encoding struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
	Err   string `json:"error,omitempty"`
}

// EncodeResult is every reading at once; Ladder is Layers minus a first rung already on screen.
type EncodeResult struct {
	Input          string     `json:"input"`
	Encoded        []Encoding `json:"encoded"`
	Decoded        []Encoding `json:"decoded"`
	Layers         []Layer    `json:"layers,omitempty"`
	Kind           Kind       `json:"kind,omitempty"`
	AlreadyEncoded bool       `json:"already_encoded,omitempty"`
	Reading        *Layer     `json:"reading,omitempty"`
	Notes          []Note     `json:"notes,omitempty"`
	Ladder         []Layer    `json:"-"`
}

var escapeRe = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// alreadyEncoded reports valid escapes that decode to something different.
func alreadyEncoded(v string) bool {
	if !escapeRe.MatchString(v) {
		return false
	}
	dec, err := url.PathUnescape(v)
	return err == nil && dec != v
}

func EncodeAll(v string) *EncodeResult {
	r := &EncodeResult{Input: v, Kind: classify(v), AlreadyEncoded: alreadyEncoded(v)}

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
		// The unpadded fallback keeps this table agreeing with the ladder below it.
		decodeEntry("Base64", v, func(s string) (string, error) {
			return decodeBase64(s, base64.StdEncoding, base64.RawStdEncoding)
		}, ""),
		decodeEntry("Base64 (URL-safe)", v, func(s string) (string, error) {
			return decodeBase64(s, base64.URLEncoding, base64.RawURLEncoding)
		}, ""),
		decodeEntry("HTML entities", v, func(s string) (string, error) { return html.UnescapeString(s), nil }, ""),
	}

	r.Layers = decodeLadder(v)

	if (r.Kind == KindBase64 || r.Kind == KindJWT) && len(r.Layers) > 0 {
		switch first := r.Layers[0]; first.Method {
		case "base64", "base64url", "jwt-payload":
			first.Value = strings.TrimSuffix(first.Value, jwtUnverified)
			r.Reading = &first
		}
	}
	r.Ladder = r.Layers
	if len(r.Ladder) > 0 && r.shown(strings.TrimSuffix(r.Ladder[0].Value, jwtUnverified)) {
		r.Ladder = r.Ladder[1:]
	}

	if t := strings.TrimSpace(v); t != v && t != "" {
		title := "Leading or trailing whitespace"
		if strings.HasSuffix(v, "\n") {
			title = "Ends in a line break"
		}
		r.Notes = append(r.Notes, Note{SevWarn, title,
			"It is part of the value, so every result below encodes it too. Delete it unless it belongs there."})
	}
	return r
}

// shown reports whether a decoded value is already on the page.
func (r *EncodeResult) shown(v string) bool {
	if r.Reading != nil && r.Reading.Value == v {
		return true
	}
	for _, d := range r.Decoded {
		if d.Err == "" && d.Value == v {
			return true
		}
	}
	return false
}

func decodeEntry(name, v string, fn func(string) (string, error), note string) Encoding {
	out, err := fn(v)
	e := Encoding{Name: name, Note: note}
	if err != nil {
		// The failed decode's "" would read as "this value is empty", a different claim.
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

// unicodeEscape writes non-ASCII as \uXXXX, the form JSON and JavaScript source use.
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

// decodeBase64 falls back to unpadded: URLs often drop "=" since it must be percent-encoded in a query.
func decodeBase64(s string, padded, raw *base64.Encoding) (string, error) {
	if b, err := padded.DecodeString(s); err == nil {
		return string(b), nil
	}
	b, err := raw.DecodeString(s)
	return string(b), err
}
