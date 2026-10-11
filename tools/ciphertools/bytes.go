package ciphertools

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Every byte-taking field names its encoding: a silent guess is why other tools' HMACs come out "wrong".
const (
	EncUTF8      = "utf8"
	EncHex       = "hex"
	EncBase64    = "base64"
	EncBase64URL = "base64url"
	EncBase32    = "base32"
)

var byteEncodings = []string{EncUTF8, EncHex, EncBase64, EncBase64URL, EncBase32}

// DecodeBytes reads s as enc: UTF-8 verbatim, the others ignoring whitespace, with offsets into s as pasted.
func DecodeBytes(s, enc string) ([]byte, error) {
	b, _, err := decodeInput(s, enc)
	return b, err
}

// decodeInput is DecodeBytes plus how the input was read, in the visitor's words.
func decodeInput(s, enc string) (b []byte, how string, err error) {
	switch enc {
	case "", EncUTF8:
		return []byte(s), "UTF-8 text", nil
	case EncHex:
		b, err = decodeHex(s)
	case EncBase64, EncBase64URL:
		return decodeBase64Any(s)
	case EncBase32:
		b, err = decodeBase32(s)
	default:
		err = fmt.Errorf("unknown encoding %q", enc)
	}
	return b, enc, err
}

// firstInvalidUTF8 is the offset of the first byte that can't start or continue a character, or -1.
func firstInvalidUTF8(b []byte) int {
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && n <= 1 {
			return i
		}
		i += n
	}
	return -1
}

// stripSpace drops whitespace and maps each kept byte back to its offset in s.
func stripSpace(s string) (string, []int) {
	var b strings.Builder
	pos := make([]int, 0, len(s))
	for i := range len(s) {
		if strings.IndexByte(" \t\n\r", s[i]) < 0 {
			b.WriteByte(s[i])
			pos = append(pos, i)
		}
	}
	return b.String(), pos
}

// decodeHex accepts a 0x prefix and ':' or '-' separators (openssl and fingerprints print colons).
func decodeHex(s string) ([]byte, error) {
	c, pos := stripSpace(s)
	c = strings.TrimPrefix(strings.TrimPrefix(c, "0x"), "0X")
	off := len(pos) - len(c)
	var h strings.Builder
	for i := 0; i < len(c); i++ {
		switch {
		case c[i] == ':' || c[i] == '-':
		case isHex(c[i]):
			h.WriteByte(c[i])
		default:
			return nil, fmt.Errorf("not hex: %q at offset %d", c[i], pos[i+off])
		}
	}
	if h.Len()%2 != 0 {
		return nil, fmt.Errorf("hex has an odd number of digits (%d); every byte is two", h.Len())
	}
	return hex.DecodeString(h.String())
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// Base64 variant names, as reported back to the visitor.
const (
	VariantStd    = "base64 (standard, padded)"
	VariantStdRaw = "base64 (standard, unpadded)"
	VariantURL    = "base64url (padded)"
	VariantURLRaw = "base64url (unpadded)"
)

// decodeBase64Any takes all four base64 flavours and names the one seen; with neither '+/' nor '-_' it is standard.
func decodeBase64Any(s string) ([]byte, string, error) {
	c, pos := stripSpace(s)
	url := strings.ContainsAny(c, "-_")
	if url && strings.ContainsAny(c, "+/") {
		i := min(strings.IndexAny(c, "+/"), strings.IndexAny(c, "-_"))
		return nil, "", fmt.Errorf("mixes the standard (+/) and URL-safe (-_) base64 alphabets, first at offset %d", pos[i])
	}
	padded := strings.HasSuffix(c, "=")
	enc, variant := base64.RawStdEncoding, VariantStdRaw
	switch {
	case url && padded:
		enc, variant = base64.URLEncoding, VariantURL
	case url:
		enc, variant = base64.RawURLEncoding, VariantURLRaw
	case padded:
		enc, variant = base64.StdEncoding, VariantStd
	}
	b, err := enc.DecodeString(c)
	if err == nil {
		return b, variant, nil
	}
	if at, _ := err.(base64.CorruptInputError); int(at) < len(c) {
		return nil, "", fmt.Errorf("not %s: %q at offset %d", variant, c[at], pos[at])
	}
	return nil, "", fmt.Errorf("not %s: truncated (%d characters is not a whole number of base64 groups)", variant, len(c))
}

// decodeBase32 accepts the lowercase, unpadded, space-grouped form TOTP secrets are usually printed in.
func decodeBase32(s string) ([]byte, error) {
	c, pos := stripSpace(s)
	c = strings.ToUpper(strings.TrimRight(c, "="))
	if i := strings.IndexFunc(c, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') }); i >= 0 {
		return nil, fmt.Errorf("not base32: %q at offset %d", c[i], pos[i])
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c)
	if err != nil {
		return nil, fmt.Errorf("not base32: %d characters is not a whole number of bytes", len(c))
	}
	return b, nil
}

// Text is bytes shown to a person: as text when valid, printable UTF-8, otherwise as hex, never mojibake.
type Text struct {
	Value  string `json:"value"`
	IsText bool   `json:"is_text"`
	Hex    string `json:"hex"`
	Bytes  int    `json:"bytes"`
}

func textOf(b []byte) Text {
	t := Text{Hex: hex.EncodeToString(b), Bytes: len(b)}
	if utf8.Valid(b) && printable(string(b)) {
		t.Value, t.IsText = string(b), true
	} else {
		t.Value = t.Hex
	}
	return t
}

// printable: no control characters except the whitespace people type.
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f {
			return false
		}
	}
	return true
}

// b64url is the JOSE encoding: URL-safe, no padding.
var b64url = base64.RawURLEncoding
