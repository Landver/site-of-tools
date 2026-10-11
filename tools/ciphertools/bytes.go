package ciphertools

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Every byte-taking field names its encoding: a silent guess is why other tools' HMACs come out "wrong".
const (
	EncUTF8      = "utf8"
	EncHex       = "hex"
	EncBase64    = "base64"
	EncBase64URL = "base64url"
	EncBase32    = "base32"
	// EncAuto lets the op pick the reading: each reading of a shared secret, or hex vs base64 data.
	EncAuto = "auto"
)

var byteEncodings = []string{EncUTF8, EncHex, EncBase64, EncBase64URL, EncBase32}

const (
	letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	alnum   = letters + "0123456789"
)

func allHex(s string) bool { return s != "" && strings.Trim(s, "0123456789abcdefABCDEF") == "" }

func allDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// bytesText: 32 MiB, 19 MiB, 64 KiB, 512 bytes.
func bytesText(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// decodeInput reads s as enc (UTF-8 verbatim, the rest ignoring whitespace, offsets into s as pasted) and says how.
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

// charAt quotes the character starting at s[i] as typed, a byte that isn't UTF-8 as '\xff'.
func charAt(s string, i int) string {
	if r, n := utf8.DecodeRuneInString(s[i:]); r != utf8.RuneError || n > 1 {
		return strconv.QuoteRune(r)
	}
	return fmt.Sprintf(`'\x%02x'`, s[i])
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
			return nil, fmt.Errorf("not hex: %s at offset %d", charAt(c, i), pos[i+off])
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
		return nil, "", fmt.Errorf("not %s: %s at offset %d", variant, charAt(c, int(at)), pos[at])
	}
	return nil, "", fmt.Errorf("not %s: truncated (%d characters is not a whole number of base64 groups)", variant, len(c))
}

// decodeBase32 accepts the lowercase, unpadded, space-grouped form TOTP secrets are usually printed in.
func decodeBase32(s string) ([]byte, error) {
	c, pos := stripSpace(s)
	c = strings.TrimRight(c, "=")
	var u strings.Builder
	for i, r := range c { // rune by rune, not strings.ToUpper, which can change byte lengths and so offsets
		if r = unicode.ToUpper(r); !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			return nil, fmt.Errorf("not base32: %s at offset %d", charAt(c, i), pos[i])
		}
		u.WriteRune(r)
	}
	b, err := b32raw.DecodeString(u.String())
	if err != nil {
		return nil, fmt.Errorf("not base32: %d characters is not a whole number of bytes", u.Len())
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

var b32raw = base32.StdEncoding.WithPadding(base32.NoPadding)
