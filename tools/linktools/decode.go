package linktools

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Nested base64 is trivial to build and this runs unauthenticated, so the ladder stops and says so.
const (
	maxLadderDepth = 5
	maxRungBytes   = 64 << 10
)

// decodeLadder peels v until it stops changing; nil when v is already plain, the common case.
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

// peel applies the most likely single decoding (JWT before plain base64); empty method means none.
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

// looksBase64 is permissive on purpose: a false positive costs a note, a false negative a lost value.
func looksBase64(s string) bool {
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}
	return b64Std.MatchString(s) || b64URL.MatchString(s)
}

// tryBase64 accepts only printable output, so long hex ids and tokens aren't reported as base64.
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

// jwtPayload pretty-prints header and payload; it never verifies the signature and must not imply it did.
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
	return string(out) + jwtUnverified, true
}

// jwtUnverified ends every decoded JWT; Encode's reading trims it.
const jwtUnverified = "\n\n(signature not verified — this tool only decodes)"

// prettyJSON skips scalars: "1" is valid JSON, and calling a number JSON is noise.
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

// classify is best-effort and advisory; nothing downstream depends on getting it right.
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
	if looksBase64(v) && (decodesToText(v) || encodedLooking(v)) {
		return KindBase64
	}
	return ""
}

func decodesToText(v string) bool {
	_, _, ok := tryBase64(v)
	return ok
}

// encodedLooking tells real base64 from a plain word: "facebook" is valid base64 too.
func encodedLooking(v string) bool {
	if strings.ContainsAny(v, "+/=") {
		return true
	}
	var digit, lower, upper bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		}
	}
	return digit && lower && upper
}

// isTimestamp accepts Unix seconds or ms in 2001-2286 only, so ordinary ids aren't mislabelled.
func isTimestamp(n int64) bool {
	const lo, hi = 1_000_000_000, 9_999_999_999
	if n >= lo && n <= hi {
		return true
	}
	if n >= lo*1000 && n <= hi*1000 {
		return true
	}
	return false
}

// printable rejects control characters, which is how base64 of binary is refused.
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
