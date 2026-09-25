package linktools

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Ladder bounds. A value that is base64 of base64 of base64 is trivial to
// construct and each rung can be larger than the last, so the ladder stops and
// SAYS it stopped rather than truncating silently or running out of memory.
// This function is reachable unauthenticated on every parse.
const (
	maxLadderDepth = 5
	maxRungBytes   = 64 << 10
)

// decodeLadder peels a value until it stops changing, recording each rung.
//
// Returns nil when the value is already plain — the overwhelmingly common case,
// and the template renders nothing for it. urldecoder.org does this for whole
// strings with a cap of 16; the difference here is that it runs per parameter
// and the rungs are shown, so a double-encoded value is visible as such rather
// than silently flattened.
func decodeLadder(v string) []Layer {
	if v == "" || len(v) > maxRungBytes {
		return nil
	}
	var out []Layer
	cur := v
	for depth := 1; depth <= maxLadderDepth; depth++ {
		next, method := peel(cur)
		if method == "" || next == cur {
			break
		}
		if len(next) > maxRungBytes {
			out = append(out, Layer{Depth: depth, Method: method,
				Value: "(stopped: this rung exceeds " + strconv.Itoa(maxRungBytes>>10) + " KB)"})
			break
		}
		out = append(out, Layer{Depth: depth, Method: method, Value: next})
		cur = next
		if depth == maxLadderDepth {
			out = append(out, Layer{Depth: depth + 1, Method: "stopped",
				Value: "(depth limit reached; there may be more layers)"})
		}
	}
	return out
}

// peel applies the single most likely decoding to s, returning the result and
// the method used. Empty method means nothing applied.
//
// Order matters: percent first because it is cheapest and most common, then
// JWT (a specific base64 shape worth naming), then plain base64, then JSON.
func peel(s string) (string, string) {
	if strings.Contains(s, "%") {
		if dec, err := url.QueryUnescape(s); err == nil && dec != s && utf8.ValidString(dec) {
			return dec, "percent"
		}
	}
	if payload, ok := jwtPayload(s); ok {
		return payload, "jwt-payload"
	}
	if dec, enc, ok := tryBase64(s); ok {
		return dec, enc
	}
	if pretty, ok := prettyJSON(s); ok {
		return pretty, "json"
	}
	return "", ""
}

var (
	b64Std = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	b64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+={0,2}$`)
	jwtRe  = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^(?:0[xX])?[0-9a-fA-F]{8,}$`)
	mailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$`)
)

// looksBase64 reports whether s could be base64. Used for the '+' ambiguity
// warning, so it is deliberately permissive: a false positive costs a note, a
// false negative costs a destroyed value.
func looksBase64(s string) bool {
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	return b64Std.MatchString(s) || b64URL.MatchString(s)
}

// tryBase64 decodes s if it is base64 of something printable. The printable
// check is what stops every long hex id and random token being reported as
// base64 of binary noise.
func tryBase64(s string) (string, string, bool) {
	if len(s) < 8 || len(s) > maxRungBytes {
		return "", "", false
	}
	type attempt struct {
		enc  *base64.Encoding
		name string
		ok   bool
	}
	for _, a := range []attempt{
		{base64.StdEncoding, "base64", b64Std.MatchString(s)},
		{base64.RawStdEncoding, "base64", b64Std.MatchString(s)},
		{base64.URLEncoding, "base64url", b64URL.MatchString(s)},
		{base64.RawURLEncoding, "base64url", b64URL.MatchString(s)},
	} {
		if !a.ok {
			continue
		}
		dec, err := a.enc.DecodeString(s)
		if err != nil || len(dec) == 0 {
			continue
		}
		if out := string(dec); printable(out) {
			return out, a.name, true
		}
	}
	return "", "", false
}

// jwtPayload returns a JWT's payload, pretty-printed. Header and payload only:
// this never verifies a signature and the page must never imply that it did.
func jwtPayload(s string) (string, bool) {
	if !jwtRe.MatchString(s) {
		return "", false
	}
	parts := strings.Split(s, ".")
	hdr, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pay, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return "", false
	}
	var h, p any
	if json.Unmarshal(hdr, &h) != nil || json.Unmarshal(pay, &p) != nil {
		return "", false
	}
	out, err := json.MarshalIndent(map[string]any{"header": h, "payload": p}, "", "  ")
	if err != nil {
		return "", false
	}
	return string(out) + "\n\n(signature not verified — this tool only decodes)", true
}

// prettyJSON reformats s when it is a JSON object or array. Scalars are
// excluded: "1" is valid JSON and reporting a number as JSON is noise.
func prettyJSON(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 2 || (t[0] != '{' && t[0] != '[') {
		return "", false
	}
	var v any
	if err := json.Unmarshal([]byte(t), &v); err != nil {
		return "", false
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", false
	}
	return string(out), true
}

// classify types a value so the template can render it usefully. Best-effort and
// advisory; nothing downstream depends on getting it right.
func classify(v string) Kind {
	if v == "" {
		return ""
	}
	switch {
	case uuidRe.MatchString(v):
		return KindUUID
	case jwtRe.MatchString(v):
		return KindJWT
	case v == "true" || v == "false" || v == "1" || v == "0":
		if v == "1" || v == "0" {
			return KindNumber
		}
		return KindBool
	case mailRe.MatchString(v):
		return KindEmail
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		// Unix seconds or milliseconds within a plausible window read as a time.
		if isTimestamp(n) {
			return KindTimestamp
		}
		return KindNumber
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return KindNumber
	}
	if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
		return KindURL
	}
	if t := strings.TrimSpace(v); len(t) > 1 && (t[0] == '{' || t[0] == '[') {
		if json.Valid([]byte(t)) {
			return KindJSON
		}
	}
	if hexRe.MatchString(v) {
		return KindHex
	}
	if looksBase64(v) {
		return KindBase64
	}
	return ""
}

// isTimestamp reports whether n is plausibly a Unix time in seconds or
// milliseconds. Bounded to 2001-2286 so ordinary ids aren't mislabelled.
func isTimestamp(n int64) bool {
	const lo, hi = 1_000_000_000, 9_999_999_999 // seconds: 2001 .. 2286
	if n >= lo && n <= hi {
		return true
	}
	if n >= lo*1000 && n <= hi*1000 {
		return true
	}
	return false
}

// TimestampHint renders a timestamp parameter as a date, for the template.
// Returns empty when v is not one.
func TimestampHint(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || !isTimestamp(n) {
		return ""
	}
	if n > 9_999_999_999 {
		return time.UnixMilli(n).UTC().Format(time.RFC3339)
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

// printable reports whether s is text a human could read, used to reject base64
// that decodes to binary.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
