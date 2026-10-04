package ciphertools

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Byte encodings an input field can be read as. Every page that takes bytes
// (a hash input, an HMAC key, an AES key) takes one of these beside it, because
// "the secret is abc" means three different keys depending on which one applies,
// and a silent guess is exactly what makes the surveyed tools produce "wrong"
// HMACs nobody can explain (docs/00-landscape.md finding 3).
const (
	EncUTF8      = "utf8"
	EncHex       = "hex"
	EncBase64    = "base64"
	EncBase64URL = "base64url"
	EncBase32    = "base32"
)

// byteEncodings is every encoding DecodeBytes reads, as a field's Enum.
var byteEncodings = []string{EncUTF8, EncHex, EncBase64, EncBase64URL, EncBase32}

// DecodeBytes reads s as enc. UTF-8 is taken verbatim, whitespace included,
// because for a hash input the whitespace is the data. The other encodings
// ignore whitespace (pasted values wrap) and report the offset of the first
// character they couldn't use, counted in the ORIGINAL string, so the error
// points at something the visitor can see.
func DecodeBytes(s, enc string) ([]byte, error) {
	switch enc {
	case "", EncUTF8:
		return []byte(s), nil
	case EncHex:
		return decodeHex(s)
	case EncBase64, EncBase64URL:
		b, _, err := decodeBase64Any(s)
		return b, err
	case EncBase32:
		return decodeBase32(s)
	}
	return nil, fmt.Errorf("unknown encoding %q", enc)
}

// decodeInput is DecodeBytes plus how the input was read, in the visitor's
// words: "UTF-8 text", "hex", "base32", or the exact base64 variant seen.
func decodeInput(s, enc string) ([]byte, string, error) {
	switch enc {
	case EncBase64, EncBase64URL:
		return decodeBase64Any(s)
	}
	b, err := DecodeBytes(s, enc)
	return b, encName(enc), err
}

// firstInvalidUTF8 returns the offset of the first byte that can't start or
// continue a UTF-8 character, or -1 when b is valid UTF-8.
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

// stripSpace drops whitespace and keeps a map from each kept byte back to its
// offset in s.
func stripSpace(s string) (string, []int) {
	var b strings.Builder
	pos := make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			continue
		}
		b.WriteByte(s[i])
		pos = append(pos, i)
	}
	return b.String(), pos
}

func origin(pos []int, i int) int {
	if i < len(pos) {
		return pos[i]
	}
	if len(pos) == 0 {
		return 0
	}
	return pos[len(pos)-1] + 1
}

// decodeHex accepts "0x" prefixes and ":" or "-" separators (openssl and
// certificate fingerprints both print colons).
func decodeHex(s string) ([]byte, error) {
	c, pos := stripSpace(s)
	c = strings.TrimPrefix(strings.TrimPrefix(c, "0x"), "0X")
	off := len(pos) - len(c) // bytes eaten by the prefix
	var b strings.Builder
	kept := make([]int, 0, len(c))
	for i := 0; i < len(c); i++ {
		if c[i] == ':' || c[i] == '-' {
			continue
		}
		b.WriteByte(c[i])
		kept = append(kept, origin(pos, i+off))
	}
	h := b.String()
	for i := 0; i < len(h); i++ {
		if !isHex(h[i]) {
			return nil, fmt.Errorf("not hex: %q at offset %d", h[i], kept[i])
		}
	}
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("hex has an odd number of digits (%d); every byte is two", len(h))
	}
	return hex.DecodeString(h)
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

// decodeBase64Any accepts all four base64 flavours and says which one it saw.
// The alphabet decides standard vs URL-safe; a value using neither '+/' nor
// '-_' is valid in both and reported as standard.
func decodeBase64Any(s string) ([]byte, string, error) {
	c, pos := stripSpace(s)
	url := strings.ContainsAny(c, "-_")
	if url && strings.ContainsAny(c, "+/") {
		i := strings.IndexAny(c, "+/")
		if j := strings.IndexAny(c, "-_"); j < i {
			i = j
		}
		return nil, "", fmt.Errorf("mixes the standard (+/) and URL-safe (-_) base64 alphabets, first at offset %d", origin(pos, i))
	}
	padded := strings.HasSuffix(c, "=")
	var enc *base64.Encoding
	var variant string
	switch {
	case url && padded:
		enc, variant = base64.URLEncoding, VariantURL
	case url:
		enc, variant = base64.RawURLEncoding, VariantURLRaw
	case padded:
		enc, variant = base64.StdEncoding, VariantStd
	default:
		enc, variant = base64.RawStdEncoding, VariantStdRaw
	}
	b, err := enc.DecodeString(c)
	if err != nil {
		var ce base64.CorruptInputError
		if errors.As(err, &ce) {
			at := int(ce)
			if at < len(c) {
				return nil, "", fmt.Errorf("not %s: %q at offset %d", variant, c[at], origin(pos, at))
			}
			return nil, "", fmt.Errorf("not %s: truncated (%d characters is not a whole number of base64 groups)", variant, len(c))
		}
		return nil, "", err
	}
	return b, variant, nil
}

// decodeBase32 accepts the lowercase, unpadded, space-grouped form TOTP secrets
// are usually printed in (docs/03-correctness-traps.md, TOTP).
func decodeBase32(s string) ([]byte, error) {
	c, pos := stripSpace(s)
	c = strings.ToUpper(strings.TrimRight(c, "="))
	for i := 0; i < len(c); i++ {
		if !(c[i] >= 'A' && c[i] <= 'Z' || c[i] >= '2' && c[i] <= '7') {
			return nil, fmt.Errorf("not base32: %q at offset %d", c[i], origin(pos, i))
		}
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c)
	if err != nil {
		return nil, fmt.Errorf("not base32: %d characters is not a whole number of bytes", len(c))
	}
	return b, nil
}

// Text is a byte string shown to a person: as text when it is valid, printable
// UTF-8, otherwise as hex — never forced into mojibake.
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
