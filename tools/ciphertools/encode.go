package ciphertools

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// C10 — the same bytes as text, hex, base64, base64url and base32, plus the
// HTTP Basic auth header. Percent-encoding and HTML entities live on Link
// Tools' encode page, which this page links to instead of repeating them.

func init() {
	register(Op{Name: "encode", Path: "/encode", Page: "encode", Fragment: "cipher/encode-result", Run: runEncode})
	register(Op{Name: "basic", Path: "/encode/basic", Page: "encode", Fragment: "cipher/basic-result", Run: runBasic})
}

// Encoded is one input shown in every encoding.
type Encoded struct {
	Bytes  int    `json:"bytes"`
	ReadAs string `json:"read_as"`
	// Text is set only when the bytes are valid, printable UTF-8; TextNote
	// says why it isn't when it isn't.
	Text      string    `json:"text,omitempty"`
	UTF8      bool      `json:"utf8"`
	TextNote  string    `json:"text_note,omitempty"`
	Hex       string    `json:"hex"`
	HexColons string    `json:"hex_colons"`
	Base64    string    `json:"base64"`
	Base64URL string    `json:"base64url"`
	Base32    string    `json:"base32"`
	Warnings  []Warning `json:"warnings,omitempty"`
}

func runEncode(in Input) (any, error) {
	s, from := in.Get("text"), in.Get("from")
	if s == "" {
		return nil, errors.New("nothing to convert: the input is empty")
	}
	b, how, err := decodeInput(s, from)
	if err != nil {
		return nil, fmt.Errorf("input: %w", err)
	}
	e := EncodeBytes(b, how)
	e.Warnings = append(e.Warnings, byteNotes(b, "")...)
	return e, nil
}

// EncodeBytes shows b in every encoding. readAs is how the input was read.
func EncodeBytes(b []byte, readAs string) *Encoded {
	e := &Encoded{
		Bytes: len(b), ReadAs: readAs,
		Hex:       hex.EncodeToString(b),
		HexColons: hexColons(b),
		Base64:    base64.StdEncoding.EncodeToString(b),
		Base64URL: base64.RawURLEncoding.EncodeToString(b),
		Base32:    base32.StdEncoding.EncodeToString(b),
	}
	switch at := firstInvalidUTF8(b); {
	case at >= 0:
		e.TextNote = fmt.Sprintf("Not valid UTF-8: byte 0x%02x at offset %d can't start or continue a character, so there is no text to show. The hex is exact.", b[at], at)
	case !printable(string(b)):
		e.UTF8 = true
		e.TextNote = "Valid UTF-8, but it holds control characters, so it is shown as hex rather than as text."
	default:
		e.UTF8, e.Text = true, string(b)
	}
	if len(b) == 0 {
		e.Warnings = append(e.Warnings, Warning{LevelInfo, "The input decodes to zero bytes."})
	}
	return e
}

func hexColons(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// BasicAuth is an HTTP Basic credential (RFC 7617), built or taken apart.
type BasicAuth struct {
	Mode     string `json:"mode"` // build | decode
	User     Text   `json:"user"`
	Password Text   `json:"password"`
	// Token is base64(user ":" password), standard alphabet, padded.
	Token  string `json:"token"`
	Header string `json:"header"`
	// ReadAs, on decode: the base64 variant the pasted value used.
	ReadAs   string    `json:"read_as,omitempty"`
	Warnings []Warning `json:"warnings,omitempty"`
}

func (a *BasicAuth) warn(level, text string) { a.Warnings = append(a.Warnings, Warning{level, text}) }

func runBasic(in Input) (any, error) {
	mode := strings.TrimSpace(in.Get("mode"))
	if mode == "" {
		mode = "build"
		if strings.TrimSpace(in.Get("header")) != "" {
			mode = "decode"
		}
	}
	switch mode {
	case "build":
		return BuildBasic(in.Get("user"), in.Get("password"))
	case "decode":
		return DecodeBasic(in.Get("header"))
	}
	return nil, fmt.Errorf("mode: want build or decode, got %q", mode)
}

// BuildBasic makes the header for user and password, UTF-8 encoded.
func BuildBasic(user, password string) (*BasicAuth, error) {
	if user == "" && password == "" {
		return nil, errors.New("no user name or password given")
	}
	if i := strings.IndexByte(user, ':'); i >= 0 {
		return nil, fmt.Errorf("the user name has a ':' at offset %d, and Basic auth can't carry one: the server splits at the first colon, so the rest would become the password (RFC 7617 §2)", i)
	}
	cred := []byte(user + ":" + password)
	a := &BasicAuth{Mode: "build", User: textOf([]byte(user)), Password: textOf([]byte(password))}
	a.Token = base64.StdEncoding.EncodeToString(cred)
	a.Header = "Authorization: Basic " + a.Token
	if password == "" {
		a.warn(LevelInfo, "Empty password. Some APIs take a key as the user name and no password, which is fine.")
	}
	a.credentialWarnings(user, password)
	return a, nil
}

func (a *BasicAuth) credentialWarnings(user, password string) {
	for _, f := range []struct{ name, v string }{{"user name", user}, {"password", password}} {
		if strings.IndexFunc(f.v, unicode.IsControl) >= 0 {
			a.warn(LevelWarn, fmt.Sprintf("The %s holds control characters, which RFC 7617 doesn't allow; servers may reject it.", f.name))
		}
		if strings.TrimSpace(f.v) != f.v {
			a.warn(LevelWarn, fmt.Sprintf("The %s starts or ends with whitespace, and that whitespace is sent.", f.name))
		}
	}
	for _, r := range user + password {
		if r > unicode.MaxASCII {
			a.warn(LevelInfo, "Non-ASCII characters are sent as UTF-8 (RFC 7617). A few old servers expect Latin-1 and will see something else.")
			break
		}
	}
}

// DecodeBasic reads a pasted "Authorization: Basic …" line, a "Basic …" value,
// or the bare base64. Error offsets count from the start of what was pasted.
func DecodeBasic(s string) (*BasicAuth, error) {
	const junk = " \t\r\n\"'"
	at := 0
	skip := func() {
		for at < len(s) && strings.IndexByte(junk, s[at]) >= 0 {
			at++
		}
	}
	skip()
	if hasPrefixFold(s[at:], "authorization:") {
		at += len("authorization:")
		skip()
	}
	if hasPrefixFold(s[at:], "bearer ") {
		return nil, errors.New("that is a Bearer token, not Basic credentials; the JWT page reads those")
	}
	if hasPrefixFold(s[at:], "basic ") || hasPrefixFold(s[at:], "basic\t") {
		at += len("basic ")
		skip()
	}
	end := len(strings.TrimRight(s, junk))
	if end <= at {
		return nil, errors.New("no credentials given: paste the header, or the base64 after Basic")
	}
	// Blank out the prefix rather than cutting it, so decodeBase64Any's offsets
	// still point into the pasted text.
	b, variant, err := decodeBase64Any(strings.Repeat(" ", at) + s[at:end])
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	i := strings.IndexByte(string(b), ':')
	if i < 0 {
		return nil, fmt.Errorf("the credentials decode to %d bytes with no ':' in them, so there is no user:password pair (decoded: %s)", len(b), textOf(b).Value)
	}
	a := &BasicAuth{Mode: "decode", User: textOf(b[:i]), Password: textOf(b[i+1:]), ReadAs: variant}
	a.Token = base64.StdEncoding.EncodeToString(b)
	a.Header = "Authorization: Basic " + a.Token
	a.warn(LevelInfo, "Basic auth is an encoding, not encryption: anyone who sees this header has the password. Send it over HTTPS only.")
	if variant != VariantStd {
		a.warn(LevelWarn, fmt.Sprintf("The credentials were %s. RFC 7617 uses standard padded base64, which is what the header below uses; a strict server may reject the original.", variant))
	}
	if !a.User.IsText || !a.Password.IsText {
		a.warn(LevelInfo, "The user name or password isn't printable UTF-8 (Latin-1, perhaps), so it is shown as hex.")
	}
	if utf8.Valid(b) {
		a.credentialWarnings(string(b[:i]), string(b[i+1:]))
	}
	return a, nil
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
