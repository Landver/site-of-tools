package ciphertools

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"time"
)

// C9 — random tokens, passwords and UUIDs. Every value comes from crypto/rand,
// and characters are drawn by rejection sampling: mapping a random byte b to
// b % n over-represents the first 256 % n characters, so a byte at or above
// the largest multiple of n is thrown away and another drawn
// (docs/03-correctness-traps.md). The results are secrets, so the form is not
// live, and the JSON API answers with no-store like every op.

func init() {
	register(Op{Name: "random", Path: "/random", Page: "random", Fragment: "cipher/random-result", Run: runRandom,
		Fields: []Field{
			{Name: "kind", Kind: KindEnum, Enum: []string{RandomToken, RandomPassword, RandomUUID}, Default: RandomToken,
				Description: "What to generate: token (random bytes, encoded), password (characters from chosen sets) or uuid."},
			tokenBytesField,
			{Name: "format", Kind: KindEnum, Enum: []string{"hex", "base64url", "base64", "alnum"}, Default: "hex",
				Description: "How a token is written (kind token): hex, base64url (URL-safe, unpadded), base64 (padded) or alnum (A-Z, a-z and 0-9)."},
			passwordLengthField,
			{Name: "sets", Kind: KindList, Enum: []string{"lower", "upper", "digits", "symbols"}, Default: "lower,upper,digits,symbols",
				Description: "The character sets a password draws from (kind password), any of lower, upper, digits and symbols; each chosen set appears at least once."},
			{Name: "exclude_ambiguous", Kind: KindBool, Default: "false",
				Description: "Leave out characters easily misread when copied by hand, 0 O 1 l I | and ` (kind password)."},
			uuidVersionField,
			randomCountField,
		}})
}

// maxBatch caps count for tokens and passwords; randomCountField's Max is the UUIDs'.
const maxBatch = 20

var (
	tokenBytesField = Field{Name: "bytes", Kind: KindInt, Default: "32", Min: ptr(1), Max: ptr(1024),
		Description: "Random bytes per token (kind token), e.g. 32 for 256 bits; an alnum token gets enough characters to carry as much entropy."}
	passwordLengthField = Field{Name: "length", Kind: KindInt, Default: "20", Min: ptr(4), Max: ptr(256),
		Description: "Characters per password (kind password)."}
	uuidVersionField = Field{Name: "version", Kind: KindInt, Enum: []string{"4", "7"}, Default: "4", Min: ptr(4), Max: ptr(7),
		Description: "The UUID version (kind uuid): 4 is random; 7 starts with its creation time in milliseconds, readable by anyone who sees it."}
	randomCountField = Field{Name: "count", Kind: KindInt, Default: "1", Min: ptr(1), Max: ptr(100),
		Description: "How many values to generate: up to 20 tokens or passwords, or up to 100 UUIDs."}
)

// Kinds of random value.
const (
	RandomToken    = "token"
	RandomPassword = "password"
	RandomUUID     = "uuid"
)

// RandomResult is the random op's answer: count values of one kind.
type RandomResult struct {
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
	// EntropyBits is per value: how many bits an attacker has to guess.
	EntropyBits float64 `json:"entropy_bits"`
	Detail      string  `json:"detail"`
	// Alphabet is the characters a password was drawn from.
	Alphabet string `json:"alphabet,omitempty"`
	// Created is the time embedded in UUID v7s, the same for the whole batch.
	Created  string    `json:"created,omitempty"`
	Warnings []Warning `json:"warnings,omitempty"`

	Entropy string `json:"-"`
	All     string `json:"-"`
}

func (r *RandomResult) warn(level, text string) {
	r.Warnings = append(r.Warnings, Warning{level, text})
}

func runRandom(in Input) (any, error) {
	var r *RandomResult
	var err error
	switch kind := strings.ToLower(strings.TrimSpace(in.Get("kind"))); kind {
	case "", RandomToken:
		r, err = randomTokens(in)
	case RandomPassword:
		r, err = randomPasswords(in)
	case RandomUUID:
		r, err = randomUUIDs(in)
	default:
		return nil, fmt.Errorf("kind: want token, password or uuid, got %q", kind)
	}
	if err != nil {
		return nil, err
	}
	r.EntropyBits = math.Round(r.EntropyBits*100) / 100
	r.Entropy = bitsText(r.EntropyBits)
	r.All = strings.Join(r.Values, "\n")
	return r, nil
}

// picker hands out uniform indices, reading crypto/rand a block at a time.
type picker struct{ buf []byte }

func (p *picker) byte() byte {
	if len(p.buf) == 0 {
		p.buf = make([]byte, 256)
		// Since Go 1.24 Read never fails; it crashes the program instead.
		_, _ = rand.Read(p.buf)
	}
	b := p.buf[0]
	p.buf = p.buf[1:]
	return b
}

// index returns a uniform integer in [0, n), for 1 <= n <= 256, by rejection.
func (p *picker) index(n int) int {
	limit := 256 - 256%n // the largest multiple of n that fits in a byte
	for {
		if b := int(p.byte()); b < limit {
			return b % n
		}
	}
}

func (p *picker) pick(alphabet string, length int) string {
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[p.index(len(alphabet))]
	}
	return string(out)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomTokens(in Input) (*RandomResult, error) {
	n, err := intField(in, tokenBytesField)
	if err != nil {
		return nil, err
	}
	count, err := intField(in, randomCountField.withMax(maxBatch))
	if err != nil {
		return nil, err
	}
	format := strings.ToLower(strings.TrimSpace(in.Get("format")))
	if format == "" {
		format = "hex"
	}
	r := &RandomResult{Kind: RandomToken, EntropyBits: float64(8 * n)}
	var p picker
	// An alphanumeric token gets as many characters as it takes to carry at
	// least the entropy of n bytes.
	alnumLen := int(math.Ceil(float64(8*n) / math.Log2(float64(len(alnum)))))
	for range count {
		var v string
		switch format {
		case "hex":
			v = hex.EncodeToString(randomBytes(n))
		case "base64url":
			v = base64.RawURLEncoding.EncodeToString(randomBytes(n))
		case "base64":
			v = base64.StdEncoding.EncodeToString(randomBytes(n))
		case "alnum":
			v = p.pick(alnum, alnumLen)
		default:
			return nil, fmt.Errorf("format: want hex, base64url, base64 or alnum, got %q", format)
		}
		r.Values = append(r.Values, v)
	}
	chars := len(r.Values[0])
	switch format {
	case "hex":
		r.Detail = fmt.Sprintf("%d random bytes as hex, %d characters each.", n, chars)
	case "base64url":
		r.Detail = fmt.Sprintf("%d random bytes as base64url (URL-safe, unpadded), %d characters each.", n, chars)
	case "base64":
		r.Detail = fmt.Sprintf("%d random bytes as base64 (standard, padded), %d characters each.", n, chars)
	case "alnum":
		r.EntropyBits = float64(alnumLen) * math.Log2(float64(len(alnum)))
		r.Detail = fmt.Sprintf("%d characters each from A-Z, a-z and 0-9: at least the entropy of %d random bytes.", alnumLen, n)
	}
	if n < 16 {
		r.warn(LevelWarn, "Fewer than 16 bytes (128 bits). Session tokens, API keys and signing secrets should have at least 16; 32 is the usual choice.")
	}
	return r, nil
}

// charSet is one group a password can draw from.
type charSet struct{ id, name, chars string }

var charSets = []charSet{
	{"lower", "lowercase", "abcdefghijklmnopqrstuvwxyz"},
	{"upper", "uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	{"digits", "digits", "0123456789"},
	{"symbols", "symbols", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
}

// ambiguous characters are the ones people misread when copying by hand.
const ambiguous = "0O1lI|`"

// chosenSets reads the sets field: repeated (a form's checkboxes) or comma
// separated (a JSON body). Absent means all four. Present but empty, which is
// what a form with every box unticked sends, is an error rather than a guess.
// The result is a copy: the caller trims ambiguous characters out of it.
func chosenSets(in Input) ([]charSet, error) {
	vals, given := in.Fields["sets"]
	if !given {
		return append([]charSet(nil), charSets...), nil
	}
	want := map[string]bool{}
	for _, v := range vals {
		for _, id := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			known := false
			for _, s := range charSets {
				if s.id == id {
					known = true
				}
			}
			if !known {
				return nil, fmt.Errorf("sets: unknown set %q; want lower, upper, digits or symbols", id)
			}
			want[id] = true
		}
	}
	var out []charSet
	for _, s := range charSets {
		if want[s.id] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("sets: pick at least one of lower, upper, digits and symbols")
	}
	return out, nil
}

func randomPasswords(in Input) (*RandomResult, error) {
	length, err := intField(in, passwordLengthField)
	if err != nil {
		return nil, err
	}
	count, err := intField(in, randomCountField.withMax(maxBatch))
	if err != nil {
		return nil, err
	}
	sets, err := chosenSets(in)
	if err != nil {
		return nil, err
	}
	excl := checked(in.Get("exclude_ambiguous"))
	var alphabet strings.Builder
	var sizes []int
	var names []string
	for i := range sets {
		if excl {
			sets[i].chars = strings.Map(func(r rune) rune {
				if strings.ContainsRune(ambiguous, r) {
					return -1
				}
				return r
			}, sets[i].chars)
		}
		alphabet.WriteString(sets[i].chars)
		sizes = append(sizes, len(sets[i].chars))
		names = append(names, sets[i].name)
	}
	abc := alphabet.String()

	r := &RandomResult{Kind: RandomPassword, Alphabet: abc, EntropyBits: passwordEntropy(sizes, length)}
	var p picker
	for range count {
		// Draw whole passwords and keep the first that has every chosen set:
		// uniform over the passwords allowed, unlike forcing one character
		// of each into fixed places.
		for attempt := 0; ; attempt++ {
			if attempt == 10000 {
				return nil, fmt.Errorf("could not draw a password with every set in %d tries; make it longer", attempt)
			}
			v := p.pick(abc, length)
			if hasEachSet(v, sets) {
				r.Values = append(r.Values, v)
				break
			}
		}
	}
	each := ""
	if len(sets) > 1 {
		each = ", with at least one of each"
	}
	left := ""
	if excl {
		left = fmt.Sprintf(" Left out as easy to misread: %s.", strings.Join(strings.Split(ambiguous, ""), " "))
	}
	r.Detail = fmt.Sprintf("%d characters each from %d possible (%s)%s.%s", length, len(abc), joinAnd(names), each, left)
	if r.EntropyBits < 64 {
		r.warn(LevelWarn, fmt.Sprintf("About %.0f bits. Enough behind a login that limits attempts, too few for anything that can be guessed offline, like a leaked hash or an encryption passphrase.", r.EntropyBits))
	}
	for _, s := range sets {
		if s.id == "symbols" {
			r.warn(LevelInfo, "Symbols are the ASCII punctuation characters, quotes and backslash included, which shells and some config files need escaped.")
		}
	}
	return r, nil
}

func hasEachSet(v string, sets []charSet) bool {
	for _, s := range sets {
		if !strings.ContainsAny(v, s.chars) {
			return false
		}
	}
	return true
}

// passwordEntropy is log2 of how many passwords the generator can produce:
// every string of length characters over the alphabet, less (by
// inclusion–exclusion) those missing one of the required sets. For a single
// set that is exactly length × log2(size).
func passwordEntropy(sizes []int, length int) float64 {
	total := 0
	for _, s := range sizes {
		total += s
	}
	count := new(big.Int)
	l := big.NewInt(int64(length))
	for mask := 0; mask < 1<<len(sizes); mask++ {
		missing := 0
		for i, s := range sizes {
			if mask&(1<<i) != 0 {
				missing += s
			}
		}
		term := new(big.Int).Exp(big.NewInt(int64(total-missing)), l, nil)
		if bits.OnesCount(uint(mask))%2 == 1 {
			count.Sub(count, term)
		} else {
			count.Add(count, term)
		}
	}
	if count.Sign() <= 0 {
		return 0
	}
	var mant big.Float
	exp := new(big.Float).SetInt(count).MantExp(&mant) // count = mant × 2^exp, mant in [0.5, 1)
	m, _ := mant.Float64()
	return float64(exp) + math.Log2(m)
}

func randomUUIDs(in Input) (*RandomResult, error) {
	version, err := intField(in, uuidVersionField)
	if err != nil {
		return nil, err
	}
	if version != 4 && version != 7 {
		return nil, fmt.Errorf("version: want 4 or 7, got %d", version)
	}
	count, err := intField(in, randomCountField)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	r := &RandomResult{Kind: RandomUUID}
	for range count {
		r.Values = append(r.Values, newUUID(version, now))
	}
	switch version {
	case 4:
		r.EntropyBits = 122
		r.Detail = "Version 4: 122 random bits each."
	case 7:
		// Same millisecond, random tails: sorting makes the batch list in
		// the order a database index would keep them.
		sort.Strings(r.Values)
		r.EntropyBits = 74
		r.Created = now.UTC().Format("2006-01-02T15:04:05.000Z")
		r.Detail = "Version 7: a 48-bit millisecond timestamp, then 74 random bits each."
		r.warn(LevelWarn, "Version 7 starts with its creation time, to the millisecond, readable by anyone who sees the ID: these say "+r.Created+
			". Use version 4 where that would leak something, such as when an account was made.")
	}
	return r, nil
}

// newUUID builds an RFC 9562 UUID: random bits, the version in the top nibble
// of byte 6, the variant (10) in the top bits of byte 8, and for v7 the unix
// time in milliseconds in the first 48 bits.
func newUUID(version int, now time.Time) string {
	b := randomBytes(16)
	if version == 7 {
		ms := uint64(now.UnixMilli())
		for i := 0; i < 6; i++ {
			b[i] = byte(ms >> (40 - 8*i))
		}
	}
	b[6] = b[6]&0x0f | byte(version)<<4
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func bitsText(b float64) string {
	s := strings.TrimSuffix(fmt.Sprintf("%.1f", b), ".0")
	return s + " bits"
}

func joinAnd(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
