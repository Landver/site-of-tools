package ciphertools

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	xsha3 "golang.org/x/crypto/sha3"
)

// C2 — hash text or a file with every common algorithm at once, and name the
// algorithm a pasted checksum matches. The traps here are all about bytes, not
// algorithms: a trailing newline, CRLF line endings or a byte order mark is
// where "your MD5 is wrong" comes from (docs/03-correctness-traps.md), so the
// result says out loud when the input carries any of them.

func init() {
	register(Op{Name: "hash", Path: "/hash", Page: "hash", Fragment: "cipher/hash-result", Run: runHash,
		Fields: []Field{
			{Name: "text", Kind: KindString,
				Description: "The input to hash, read per enc; whitespace and a trailing newline are part of it, and empty input hashes zero bytes."},
			{Name: "enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
				Description: "How text is written: utf8 hashes it as typed; hex, base64, base64url or base32 decode it first, which is how to hash binary data."},
			{Name: "file", Kind: KindFile,
				Description: "A file to hash instead of text, up to the 8 MiB request limit."},
			{Name: "trim_newline", Kind: KindBool, Default: "false",
				Description: `Strip one trailing newline (\n or \r\n) before hashing.`},
			{Name: "expected", Kind: KindString,
				Description: "A checksum to compare with every digest, as hex or base64, bare or labelled (a sha256sum line, sha256=…, SRI's sha384-…); the result names the algorithm it matches."},
		}})
}

// MaxHashInput bounds what one hash run reads. Every algorithm passes over the
// input, and in the browser that is Go compiled to wasm, so a big file takes
// seconds per few MiB; past this the local sha256sum is the better tool. The
// server's body limit (8 MiB) is lower still.
const MaxHashInput = 64 << 20

// hashAlg is one row of the hash table.
type hashAlg struct {
	id, name string
	new      func() hash.Hash
	note     string
	weak     bool
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

const checksumNote = "checksum, not a cryptographic hash: catches accidents, not tampering"

// hashAlgs, in display order. The ids are the JSON API's names for them.
var hashAlgs = []hashAlg{
	{id: "md5", name: "MD5", new: md5.New, note: "not collision-resistant", weak: true},
	{id: "sha1", name: "SHA-1", new: sha1.New, note: "not collision-resistant", weak: true},
	{id: "sha224", name: "SHA-224", new: sha256.New224},
	{id: "sha256", name: "SHA-256", new: sha256.New},
	{id: "sha384", name: "SHA-384", new: sha512.New384},
	{id: "sha512", name: "SHA-512", new: sha512.New},
	{id: "sha512_256", name: "SHA-512/256", new: sha512.New512_256},
	{id: "sha3_256", name: "SHA3-256", new: func() hash.Hash { return sha3.New256() }},
	{id: "sha3_512", name: "SHA3-512", new: func() hash.Hash { return sha3.New512() }},
	{id: "blake2b_256", name: "BLAKE2b-256", new: func() hash.Hash { h, _ := blake2b.New256(nil); return h }},
	{id: "blake2b_512", name: "BLAKE2b-512", new: func() hash.Hash { h, _ := blake2b.New512(nil); return h }},
	{id: "blake2s_256", name: "BLAKE2s-256", new: func() hash.Hash { h, _ := blake2s.New256(nil); return h }},
	// Keccak-256 is what Ethereum calls SHA3: the sponge before NIST changed
	// the padding, so the two give different output for every input.
	{id: "keccak256", name: "Keccak-256 (Ethereum)", new: xsha3.NewLegacyKeccak256,
		note: "the original Keccak padding, as Ethereum uses; differs from SHA3-256"},
	{id: "crc32", name: "CRC32 (IEEE)", new: func() hash.Hash { return crc32.NewIEEE() }, note: checksumNote},
	{id: "crc32c", name: "CRC32C (Castagnoli)", new: func() hash.Hash { return crc32.New(castagnoli) }, note: checksumNote},
	{id: "adler32", name: "Adler-32", new: func() hash.Hash { return adler32.New() }, note: checksumNote},
}

func hashAlgByID(id string) hashAlg {
	for _, a := range hashAlgs {
		if a.id == id {
			return a
		}
	}
	panic("ciphertools: no hash " + id)
}

// Digest is one algorithm's output. Shared by the hash and HMAC pages.
type Digest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
	Bytes  int    `json:"bytes"`
	Note   string `json:"note,omitempty"`
	// Weak: MD5 and SHA-1, where collisions can be made on purpose.
	Weak  bool `json:"weak,omitempty"`
	Match bool `json:"match,omitempty"`

	sum []byte
}

func newDigest(id, name, note string, weak bool, sum []byte) Digest {
	return Digest{ID: id, Name: name, Hex: hex.EncodeToString(sum), Base64: base64.StdEncoding.EncodeToString(sum),
		Bytes: len(sum), Note: note, Weak: weak, sum: sum}
}

// HashResult is the hash op's answer.
type HashResult struct {
	// Source says what was hashed: "file", "UTF-8 text", "hex", a base64 variant.
	Source         string    `json:"source"`
	Bytes          int       `json:"bytes"`
	TrimmedNewline bool      `json:"trimmed_newline"`
	Digests        []Digest  `json:"digests"`
	Compare        *Compare  `json:"compare,omitempty"`
	Warnings       []Warning `json:"warnings,omitempty"`
}

func runHash(in Input) (any, error) {
	var data []byte
	var source string
	var warnings []Warning
	if f := in.Files["file"]; len(f) > 0 {
		data, source = f, "file"
		if in.Get("text") != "" {
			warnings = append(warnings, Warning{LevelInfo, "Hashed the file; the text box was ignored. Clear the file to hash the text."})
		}
	} else {
		b, how, err := decodeInput(in.Get("text"), in.Get("enc"))
		if err != nil {
			return nil, fmt.Errorf("text: %w", err)
		}
		data, source = b, how
	}
	if len(data) > MaxHashInput {
		// No size in the message: in the browser a bigger file arrives cut to
		// MaxFile+1 bytes (op.go), so len(data) is not the file's size.
		return nil, fmt.Errorf("%s is larger than %s, the most this page hashes. For bigger files, sha256sum (Linux), shasum -a 256 (macOS) or certutil -hashfile (Windows) do it locally",
			source, mib(MaxHashInput))
	}

	r := &HashResult{Source: source}
	if checked(in.Get("trim_newline")) {
		var cut string
		data, cut = trimOneNewline(data)
		switch {
		case cut != "":
			r.TrimmedNewline = true
			warnings = append(warnings, Warning{LevelInfo, fmt.Sprintf("Stripped one trailing %s before hashing.", cut)})
		default:
			warnings = append(warnings, Warning{LevelInfo, "There was no trailing newline to strip."})
		}
	}
	r.Bytes = len(data)
	if len(data) == 0 {
		warnings = append(warnings, Warning{LevelInfo, "Empty input: these are the hashes of zero bytes."})
	}
	hint := ""
	if !r.TrimmedNewline {
		hint = ` Tick "Strip one trailing newline" to hash without it.`
	}
	r.Warnings = append(warnings, byteNotes(data, hint)...)

	for _, a := range hashAlgs {
		h := a.new()
		h.Write(data)
		r.Digests = append(r.Digests, newDigest(a.id, a.name, a.note, a.weak, h.Sum(nil)))
	}
	if e := in.Get("expected"); strings.TrimSpace(e) != "" {
		r.Compare = compareDigests(e, r.Digests,
			"The usual cause is the input, not the algorithm: a trailing newline, CRLF line endings, or text where the checksum was of a file.")
	}
	return r, nil
}

// checked reads a checkbox: "on" from a form, "true" from a JSON body.
func checked(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "off", "no":
		return false
	}
	return true
}

// trimOneNewline drops exactly one trailing \r\n or \n, and says which.
func trimOneNewline(b []byte) ([]byte, string) {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return b[:len(b)-2], `\r\n`
	case bytes.HasSuffix(b, []byte("\n")):
		return b[:len(b)-1], `\n`
	}
	return b, ""
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// byteNotes flags the invisible bytes that make two "identical" inputs hash
// differently. hint is appended to the trailing-newline note.
func byteNotes(b []byte, hint string) []Warning {
	var w []Warning
	body, end := trimOneNewline(b)
	if end != "" {
		w = append(w, Warning{LevelInfo, fmt.Sprintf("Ends in a newline (%s), and it is part of the data: echo foo gives 4 bytes, not 3.%s", end, hint)})
	}
	if bytes.Contains(body, []byte("\r\n")) {
		w = append(w, Warning{LevelInfo, `Contains CRLF (\r\n) line endings. The same text with Unix (\n) endings gives different hashes.`})
	}
	if bytes.HasPrefix(b, utf8BOM) {
		w = append(w, Warning{LevelInfo, "Starts with a UTF-8 byte order mark (EF BB BF). Some Windows editors add it; it is part of the data and changes every hash."})
	}
	return w
}

func mib(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d bytes", n)
}

// Compare is the answer to "which of these is the checksum I was given".
type Compare struct {
	// Given is the value compared, after cleaning (whitespace, prefixes).
	Given  string `json:"given"`
	ReadAs string `json:"read_as,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	Match  bool   `json:"match"`
	// Matches names the algorithm(s) whose output equals Given.
	Matches []string `json:"matches,omitempty"`
	// SameSize, on no match: the algorithms whose output is as long as Given.
	SameSize []string `json:"same_size,omitempty"`
	Detail   string   `json:"detail"`
	Note     string   `json:"note,omitempty"`
}

// compareDigests decodes expected as hex or base64 and checks it against every
// digest, in constant time. Hex is tried first: "deadbeef" is valid base64 as
// well, but nobody means it that way. hint follows a "no match".
func compareDigests(expected string, ds []Digest, hint string) *Compare {
	clean, note := cleanExpected(expected)
	c := &Compare{Given: clean, Note: note}
	if clean == "" {
		c.Detail = "Nothing left to compare once the prefix was removed."
		return c
	}
	type reading struct {
		as string
		b  []byte
	}
	var readings []reading
	hexB, hexErr := decodeHex(clean)
	if hexErr == nil {
		readings = append(readings, reading{"hex", hexB})
	}
	b64, variant, b64Err := decodeBase64Any(clean)
	if b64Err == nil {
		readings = append(readings, reading{variant, b64})
	}
	if len(readings) == 0 {
		err := hexErr
		if strings.ContainsAny(clean, "+/=_") || !looksHexish(clean) {
			err = b64Err
		}
		c.Detail = "The expected value is neither hex nor base64: " + err.Error() + "."
		return c
	}
	for _, r := range readings {
		for i := range ds {
			if hmac.Equal(ds[i].sum, r.b) {
				ds[i].Match = true
				c.Matches = append(c.Matches, ds[i].Name)
			}
		}
		if len(c.Matches) > 0 {
			c.Match, c.ReadAs, c.Bytes = true, r.as, len(r.b)
			c.Detail = fmt.Sprintf("Matches %s (read as %s).", strings.Join(c.Matches, " and "), r.as)
			return c
		}
	}
	r := readings[0]
	c.ReadAs, c.Bytes = r.as, len(r.b)
	for _, d := range ds {
		if d.Bytes == len(r.b) {
			c.SameSize = append(c.SameSize, d.Name)
		}
	}
	if len(c.SameSize) == 0 {
		c.Detail = fmt.Sprintf("No algorithm here outputs %d bytes, the length of the expected value read as %s.", len(r.b), r.as)
		return c
	}
	c.Detail = fmt.Sprintf("Read as %s it is %d bytes, the output length of %s. %s",
		r.as, len(r.b), strings.Join(c.SameSize, ", "), hint)
	return c
}

// looksHexish: mostly hex digits, so a hex error is the more useful one.
func looksHexish(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		if isHex(s[i]) || s[i] == ':' || s[i] == '-' {
			n++
		}
	}
	return n*10 >= len(s)*9
}

// cleanExpected turns what people paste as "the checksum" into the value
// itself: a sha256sum line ("<hex>  file"), a BSD one ("SHA256 (file) = <hex>"),
// a labelled value ("sha256=<hex>" from GitHub, "SHA256:<hex>", SRI's
// "sha384-<base64>"), a Stripe-Signature header, or hex wrapped over lines.
// Case and ':' separators are left to decodeHex. note says what was removed.
func cleanExpected(s string) (string, string) {
	t := strings.TrimSpace(s)
	var notes []string
	if strings.HasPrefix(t, "t=") && strings.Contains(t, ",v1=") {
		for _, part := range strings.Split(t, ",") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(part), "v1="); ok {
				t = v
				notes = append(notes, `Read v1 from a Stripe-Signature header. Stripe signs "<t>.<raw body>", so the message must be the timestamp, a dot, then the body.`)
				break
			}
		}
	}
	if i := strings.LastIndex(t, " = "); i >= 0 {
		t = strings.TrimSpace(t[i+3:])
		notes = append(notes, `Read the value after " = " (BSD checksum format).`)
	}
	if f := strings.Fields(t); len(f) > 1 && len(f[0]) >= 8 && allHex(f[0]) && !allHex(strings.Join(f, "")) {
		t = f[0]
		notes = append(notes, "Read the first field (sha256sum format); the rest is the file name.")
	}
	t = strings.Join(strings.Fields(t), "")
	if label, rest, ok := cutLabel(t); ok {
		t = rest
		notes = append(notes, fmt.Sprintf("Ignored the %q prefix.", label))
	}
	return t, strings.Join(notes, " ")
}

// cutLabel removes an algorithm label from the front of a digest. "=" always
// separates a label (base64 only pads at the end); ":" only when the label
// can't be a hex byte ("ab:cd" is a colon-separated digest); "-" only for SRI's
// three names, because "-" is also base64url.
func cutLabel(t string) (label, rest string, ok bool) {
	if i := strings.IndexAny(t, "=:"); i > 0 && i <= 16 {
		label, rest = t[:i], t[i+1:]
		if strings.Trim(rest, "=") != "" && isLabel(label) && (t[i] == '=' || !allHex(label)) {
			return label, rest, true
		}
	}
	for _, p := range []string{"sha256-", "sha384-", "sha512-"} {
		if len(t) > len(p) && strings.EqualFold(t[:len(p)], p) {
			return t[:len(p)-1], t[len(p):], true
		}
	}
	return "", t, false
}

func isLabel(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '/') {
			return false
		}
	}
	return true
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return s != ""
}
