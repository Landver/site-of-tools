package ciphertools

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	xsha3 "golang.org/x/crypto/sha3"
)

// "Your MD5 is wrong" is nearly always the bytes: a trailing newline, CRLF or a BOM, so the result names them.

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

// MaxHashInput bounds one run: wasm hashes a few MiB a second, so past this a local sha256sum is better.
const MaxHashInput = 64 << 20

type hashAlg struct {
	id, name, note string
	new            func() hash.Hash
	weak           bool
	mac            bool // also offered as an HMAC
}

const checksumNote = "checksum, not a cryptographic hash: catches accidents, not tampering"

// hashAlgs, in display order; the ids are the JSON API's names.
var hashAlgs = []hashAlg{
	{id: "md5", name: "MD5", new: md5.New, note: "not collision-resistant", weak: true, mac: true},
	{id: "sha1", name: "SHA-1", new: sha1.New, note: "not collision-resistant", weak: true, mac: true},
	{id: "sha224", name: "SHA-224", new: sha256.New224, mac: true},
	{id: "sha256", name: "SHA-256", new: sha256.New, mac: true},
	{id: "sha384", name: "SHA-384", new: sha512.New384, mac: true},
	{id: "sha512", name: "SHA-512", new: sha512.New, mac: true},
	{id: "sha512_256", name: "SHA-512/256", new: sha512.New512_256},
	{id: "sha3_256", name: "SHA3-256", new: func() hash.Hash { return sha3.New256() }, mac: true},
	{id: "sha3_512", name: "SHA3-512", new: func() hash.Hash { return sha3.New512() }, mac: true},
	{id: "blake2b_256", name: "BLAKE2b-256", new: func() hash.Hash { h, _ := blake2b.New256(nil); return h }},
	{id: "blake2b_512", name: "BLAKE2b-512", new: func() hash.Hash { h, _ := blake2b.New512(nil); return h }},
	{id: "blake2s_256", name: "BLAKE2s-256", new: func() hash.Hash { h, _ := blake2s.New256(nil); return h }},
	// Ethereum's "SHA3" is Keccak-256, the sponge before NIST changed its padding.
	{id: "keccak256", name: "Keccak-256 (Ethereum)", new: xsha3.NewLegacyKeccak256,
		note: "the original Keccak padding, as Ethereum uses; differs from SHA3-256"},
	{id: "crc32", name: "CRC32 (IEEE)", new: func() hash.Hash { return crc32.NewIEEE() }, note: checksumNote},
	{id: "crc32c", name: "CRC32C (Castagnoli)", new: func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }, note: checksumNote},
	{id: "adler32", name: "Adler-32", new: func() hash.Hash { return adler32.New() }, note: checksumNote},
}

// Digest is one algorithm's output, on the hash and HMAC pages.
type Digest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Blob
	Note  string `json:"note,omitempty"`
	Weak  bool   `json:"weak,omitempty"` // MD5 and SHA-1: collisions can be made on purpose
	Match bool   `json:"match,omitempty"`

	sum []byte
}

// hashDigests is data's digest under every algorithm, or with mac its HMAC under key where offered.
func hashDigests(data, key []byte, mac bool) []Digest {
	var out []Digest
	for _, a := range hashAlgs {
		h, d := a.new(), Digest{ID: a.id, Name: a.name, Note: a.note, Weak: a.weak}
		if mac {
			if !a.mac {
				continue
			}
			h, d = hmac.New(a.new, key), Digest{ID: a.id, Name: "HMAC-" + a.name}
			if a.weak { // collisions don't break HMAC, so this is advice, not an alarm
				d.Note = "legacy; still sound as a MAC, but use SHA-256 for anything new"
			}
		}
		h.Write(data)
		d.sum = h.Sum(nil)
		d.Blob = blobOf(d.sum)
		out = append(out, d)
	}
	return out
}

type HashResult struct {
	Source         string   `json:"source"` // "file", "UTF-8 text", "hex", a base64 variant
	Bytes          int      `json:"bytes"`
	TrimmedNewline bool     `json:"trimmed_newline"`
	Digests        []Digest `json:"digests"`
	Compare        *Compare `json:"compare,omitempty"`
	Warnings       Warnings `json:"warnings,omitempty"`
}

func runHash(in Input) (any, error) {
	r := &HashResult{Source: "file"}
	data := in.Files["file"]
	switch {
	case len(data) == 0:
		var err error
		if data, r.Source, err = decodeInput(in.Get("text"), in.Get("enc")); err != nil {
			return nil, fmt.Errorf("text: %w", err)
		}
	case in.Get("text") != "":
		r.Warnings.add(LevelInfo, "Hashed the file; the text box was ignored. Clear the file to hash the text.")
	}
	if len(data) > MaxHashInput {
		// No size: in the browser a bigger file arrives cut to MaxFile+1 bytes (op.go).
		return nil, fmt.Errorf("%s is larger than %.1f MiB, the most this page hashes. For bigger files, sha256sum (Linux), shasum -a 256 (macOS) or certutil -hashfile (Windows) do it locally",
			r.Source, float64(MaxHashInput)/(1<<20))
	}
	hint := ` Tick "Strip one trailing newline" to hash without it.`
	if checked(in.Get("trim_newline")) {
		var cut string
		data, cut = trimOneNewline(data)
		r.TrimmedNewline = cut != ""
		msg := "There was no trailing newline to strip."
		if r.TrimmedNewline {
			msg, hint = fmt.Sprintf("Stripped one trailing %s before hashing.", cut), ""
		}
		r.Warnings.add(LevelInfo, msg)
	}
	r.Bytes = len(data)
	if len(data) == 0 {
		r.Warnings.add(LevelInfo, "Empty input: these are the hashes of zero bytes.")
	}
	byteNotes(&r.Warnings, data, hint)
	r.Digests = hashDigests(data, nil, false)
	if e := in.Get("expected"); strings.TrimSpace(e) != "" {
		r.Compare = compareDigests(e, r.Digests,
			"The usual cause is the input, not the algorithm: a trailing newline, CRLF line endings, or text where the checksum was of a file.")
	}
	return r, nil
}

func trimOneNewline(b []byte) ([]byte, string) {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return b[:len(b)-2], `\r\n`
	case bytes.HasSuffix(b, []byte("\n")):
		return b[:len(b)-1], `\n`
	}
	return b, ""
}

// byteNotes flags the invisible bytes that make two "identical" inputs hash differently; hint follows the newline note.
func byteNotes(w *Warnings, b []byte, hint string) {
	body, end := trimOneNewline(b)
	if end != "" {
		w.add(LevelInfo, fmt.Sprintf("Ends in a newline (%s), and it is part of the data: echo foo gives 4 bytes, not 3.%s", end, hint))
	}
	if bytes.Contains(body, []byte("\r\n")) {
		w.add(LevelInfo, `Contains CRLF (\r\n) line endings. The same text with Unix (\n) endings gives different hashes.`)
	}
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		w.add(LevelInfo, "Starts with a UTF-8 byte order mark (EF BB BF). Some Windows editors add it; it is part of the data and changes every hash.")
	}
}

// Compare is the answer to "which of these is the checksum I was given".
type Compare struct {
	Given    string   `json:"given"` // after cleaning: whitespace, prefixes
	ReadAs   string   `json:"read_as,omitempty"`
	Bytes    int      `json:"bytes,omitempty"`
	Match    bool     `json:"match"`
	Matches  []string `json:"matches,omitempty"`
	SameSize []string `json:"same_size,omitempty"` // on no match: the algorithms whose output is as long as Given
	Detail   string   `json:"detail"`
	Note     string   `json:"note,omitempty"`
}

// compareDigests marks the digests equal to expected, in constant time; hex goes first, as "deadbeef" is base64 too.
func compareDigests(expected string, ds []Digest, hint string) *Compare {
	clean, note := cleanExpected(expected)
	c := &Compare{Given: clean, Note: note}
	if clean == "" {
		c.Detail = "Nothing left to compare once the prefix was removed."
		return c
	}
	type reading struct {
		as  string
		b   []byte
		err error
	}
	hexB, hexErr := decodeHex(clean)
	b64, variant, b64Err := decodeBase64Any(clean)
	readings := slices.DeleteFunc([]reading{{"hex", hexB, hexErr}, {variant, b64, b64Err}}, func(r reading) bool { return r.err != nil })
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
	c.Detail = fmt.Sprintf("Read as %s it is %d bytes, the output length of %s. %s", r.as, len(r.b), strings.Join(c.SameSize, ", "), hint)
	if len(c.SameSize) == 0 {
		c.Detail = fmt.Sprintf("No algorithm here outputs %d bytes, the length of the expected value read as %s.", len(r.b), r.as)
	}
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

// cleanExpected cuts the value from a sha256sum or BSD ("SHA256 (file) = <hex>") line, a label (sha256=,
// SRI's sha384-), a Stripe-Signature header or wrapped hex; note says what was removed.
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

// cutLabel: "=" always ends a label (base64 pads only at the end), ":" only after a non-hex label ("ab:cd"
// is a digest), and "-" only after SRI's three names, because "-" is base64url too.
func cutLabel(t string) (label, rest string, ok bool) {
	if i := strings.IndexAny(t, "=:"); i > 0 && i <= 16 {
		label, rest = t[:i], t[i+1:]
		isLabel := strings.IndexByte(letters, t[0]) >= 0 && strings.Trim(label, alnum+"-_/") == ""
		if strings.Trim(rest, "=") != "" && isLabel && (t[i] == '=' || !allHex(label)) {
			return label, rest, true
		}
	}
	if len(t) > 7 && slices.Contains([]string{"sha256-", "sha384-", "sha512-"}, strings.ToLower(t[:7])) {
		return t[:6], t[7:], true
	}
	return "", t, false
}
