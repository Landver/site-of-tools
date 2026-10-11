package ciphertools

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"strings"
	"time"
)

// Everything comes from crypto/rand. The results are secrets, so the form is not live.

func init() {
	register(Op{Name: "random", Path: "/random", Page: "random", Fragment: "cipher/random-result", Run: runRandom,
		Fields: []Field{
			randomKindField,
			tokenBytesField,
			randomFormatField,
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
	randomKindField = Field{Name: "kind", Kind: KindEnum, Enum: []string{RandomToken, RandomPassword, RandomUUID}, Default: RandomToken,
		Description: "What to generate: token (random bytes, encoded), password (characters from chosen sets) or uuid."}
	tokenBytesField = Field{Name: "bytes", Kind: KindInt, Default: "32", Min: ptr(1), Max: ptr(1024),
		Description: "Random bytes per token (kind token), e.g. 32 for 256 bits; an alnum token gets enough characters to carry as much entropy."}
	randomFormatField = Field{Name: "format", Kind: KindEnum, Enum: []string{"hex", "base64url", "base64", "alnum"}, Default: "hex",
		Description: "How a token is written (kind token): hex, base64url (URL-safe, unpadded), base64 (padded) or alnum (A-Z, a-z and 0-9)."}
	passwordLengthField = Field{Name: "length", Kind: KindInt, Default: "20", Min: ptr(4), Max: ptr(256),
		Description: "Characters per password (kind password)."}
	uuidVersionField = Field{Name: "version", Kind: KindInt, Enum: []string{"4", "7"}, Default: "4", Min: ptr(4), Max: ptr(7),
		Description: "The UUID version (kind uuid): 4 is random; 7 starts with its creation time in milliseconds, readable by anyone who sees it."}
	randomCountField = Field{Name: "count", Kind: KindInt, Default: "1", Min: ptr(1), Max: ptr(100),
		Description: "How many values to generate: up to 20 tokens or passwords, or up to 100 UUIDs."}
)

const (
	RandomToken    = "token"
	RandomPassword = "password"
	RandomUUID     = "uuid"
)

type RandomResult struct {
	Kind        string   `json:"kind"`
	Values      []string `json:"values"`
	EntropyBits float64  `json:"entropy_bits"` // per value
	Detail      string   `json:"detail"`
	Alphabet    string   `json:"alphabet,omitempty"` // a password's characters
	Created     string   `json:"created,omitempty"`  // in a v7 UUID batch
	Warnings    Warnings `json:"warnings,omitempty"`

	Entropy string `json:"-"`
	All     string `json:"-"`
}

var randomKinds = map[string]func(Input) (*RandomResult, error){RandomToken: randomTokens, RandomPassword: randomPasswords, RandomUUID: randomUUIDs}

func runRandom(in Input) (any, error) {
	kind, err := enumField(in.Get("kind"), randomKindField)
	if err != nil {
		return nil, err
	}
	r, err := randomKinds[kind](in)
	if err != nil {
		return nil, err
	}
	r.EntropyBits = math.Round(r.EntropyBits*100) / 100
	r.Entropy = strings.TrimSuffix(fmt.Sprintf("%.1f", r.EntropyBits), ".0") + " bits"
	r.All = strings.Join(r.Values, "\n")
	return r, nil
}

// randomPick uses rejection sampling: b % n alone would favour the first 256 % n characters.
func randomPick(alphabet string, length int) string {
	n := len(alphabet)
	out := make([]byte, 0, length)
	for len(out) < length {
		for _, b := range randomBytes(length - len(out)) {
			if int(b) < 256-256%n {
				out = append(out, alphabet[int(b)%n])
			}
		}
	}
	return string(out)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // since Go 1.24 it never fails; it crashes the program instead
	return b
}

var randomTokenEncodings = map[string]struct {
	encode func([]byte) string
	name   string
}{
	"hex":       {hex.EncodeToString, "hex"},
	"base64url": {base64.RawURLEncoding.EncodeToString, "base64url (URL-safe, unpadded)"},
	"base64":    {base64.StdEncoding.EncodeToString, "base64 (standard, padded)"},
}

func randomTokens(in Input) (*RandomResult, error) {
	n, err := intField(in, tokenBytesField)
	if err != nil {
		return nil, err
	}
	count, err := intField(in, randomCountField.withMax(maxBatch))
	if err != nil {
		return nil, err
	}
	format, err := enumField(in.Get("format"), randomFormatField)
	if err != nil {
		return nil, err
	}
	r := &RandomResult{Kind: RandomToken, EntropyBits: float64(8 * n)}
	if n < 16 {
		r.Warnings.add(LevelWarn, "Fewer than 16 bytes (128 bits). Session tokens, API keys and signing secrets should have at least 16; 32 is the usual choice.")
	}
	enc, ok := randomTokenEncodings[format]
	if !ok { // alnum: as many characters as carry at least the entropy of n bytes
		chars := int(math.Ceil(float64(8*n) / math.Log2(float64(len(alnum)))))
		for range count {
			r.Values = append(r.Values, randomPick(alnum, chars))
		}
		r.EntropyBits = float64(chars) * math.Log2(float64(len(alnum)))
		r.Detail = fmt.Sprintf("%d characters each from A-Z, a-z and 0-9: at least the entropy of %d random bytes.", chars, n)
		return r, nil
	}
	for range count {
		r.Values = append(r.Values, enc.encode(randomBytes(n)))
	}
	r.Detail = fmt.Sprintf("%d random bytes as %s, %d characters each.", n, enc.name, len(r.Values[0]))
	return r, nil
}

type charSet struct{ id, name, chars string }

var charSets = []charSet{
	{"lower", "lowercase", "abcdefghijklmnopqrstuvwxyz"},
	{"upper", "uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
	{"digits", "digits", "0123456789"},
	{"symbols", "symbols", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
}

const ambiguous = "0O1lI|`"

// chosenSets: absent means all four sets; present but empty (no box ticked) is refused.
func chosenSets(in Input) ([]charSet, error) {
	vals, given := in.Fields["sets"]
	if !given {
		return slices.Clone(charSets), nil
	}
	ids := strings.FieldsFunc(strings.Join(vals, ","), func(r rune) bool { return r == ',' || r == ' ' })
	for _, id := range ids {
		if !slices.ContainsFunc(charSets, func(s charSet) bool { return s.id == id }) {
			return nil, fmt.Errorf("sets: unknown set %q; want lower, upper, digits or symbols", id)
		}
	}
	out := slices.DeleteFunc(slices.Clone(charSets), func(s charSet) bool { return !slices.Contains(ids, s.id) })
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
	sets, err := chosenSets(in) // a copy, so trimming it below is safe
	if err != nil {
		return nil, err
	}
	excl := checked(in.Get("exclude_ambiguous"))
	var abc string
	var names []string
	for i := range sets {
		if excl {
			for _, c := range ambiguous {
				sets[i].chars = strings.ReplaceAll(sets[i].chars, string(c), "")
			}
		}
		abc += sets[i].chars
		names = append(names, sets[i].name)
	}

	r := &RandomResult{Kind: RandomPassword, Alphabet: abc, EntropyBits: passwordEntropy(sets, len(abc), length)}
	for range count {
		// Redraw whole passwords until none lacks a set: uniform over the passwords
		// allowed, unlike forcing one of each into fixed places.
		v := ""
		for tries := 0; slices.ContainsFunc(sets, func(s charSet) bool { return !strings.ContainsAny(v, s.chars) }); tries++ {
			if tries == 10000 {
				return nil, fmt.Errorf("could not draw a password with every set in %d tries; make it longer", tries)
			}
			v = randomPick(abc, length)
		}
		r.Values = append(r.Values, v)
	}
	each, left := "", ""
	if len(sets) > 1 {
		each = ", with at least one of each"
	}
	if excl {
		left = fmt.Sprintf(" Left out as easy to misread: %s.", strings.Join(strings.Split(ambiguous, ""), " "))
	}
	r.Detail = fmt.Sprintf("%d characters each from %d possible (%s)%s.%s", length, len(abc), joinAnd(names), each, left)
	if r.EntropyBits < 64 {
		r.Warnings.add(LevelWarn, fmt.Sprintf("About %.0f bits. Enough behind a login that limits attempts, too few for anything that can be guessed offline, like a leaked hash or an encryption passphrase.", r.EntropyBits))
	}
	if slices.Contains(names, "symbols") {
		r.Warnings.add(LevelInfo, "Symbols are the ASCII punctuation characters, quotes and backslash included, which shells and some config files need escaped.")
	}
	return r, nil
}

// passwordEntropy is log2(size^length × the share of passwords lacking no set), by inclusion–exclusion.
func passwordEntropy(sets []charSet, size, length int) float64 {
	share := 0.0
	for mask := 0; mask < 1<<len(sets); mask++ {
		left := size
		for i, s := range sets {
			if mask&(1<<i) != 0 {
				left -= len(s.chars)
			}
		}
		share += math.Pow(-1, float64(bits.OnesCount(uint(mask)))) * math.Pow(float64(left)/float64(size), float64(length))
	}
	return float64(length)*math.Log2(float64(size)) + math.Log2(share)
}

func randomUUIDs(in Input) (*RandomResult, error) {
	version, err := intField(in, uuidVersionField)
	if err == nil && version != 4 && version != 7 {
		err = fmt.Errorf("version: want 4 or 7, got %d", version)
	}
	if err != nil {
		return nil, err
	}
	count, err := intField(in, randomCountField)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	r := &RandomResult{Kind: RandomUUID, EntropyBits: 122, Detail: "Version 4: 122 random bits each."}
	for range count {
		// RFC 9562: v7 opens with 48 bits of unix ms; version in byte 6's top nibble, variant 10 in byte 8's.
		b := randomBytes(16)
		if version == 7 {
			copy(b, binary.BigEndian.AppendUint64(nil, uint64(now.UnixMilli()))[2:])
		}
		b[6] = b[6]&0x0f | byte(version)<<4
		b[8] = b[8]&0x3f | 0x80
		h := hex.EncodeToString(b)
		r.Values = append(r.Values, h[:8]+"-"+h[8:12]+"-"+h[12:16]+"-"+h[16:20]+"-"+h[20:])
	}
	if version == 7 {
		slices.Sort(r.Values) // one millisecond, so this is the order a database index keeps them in
		r.EntropyBits = 74
		r.Created = now.UTC().Format("2006-01-02T15:04:05.000Z")
		r.Detail = "Version 7: a 48-bit millisecond timestamp, then 74 random bits each."
		r.Warnings.add(LevelWarn, "Version 7 starts with its creation time, to the millisecond, readable by anyone who sees the ID: these say "+r.Created+
			". Use version 4 where that would leak something, such as when an account was made.")
	}
	return r, nil
}

func joinAnd(xs []string) string {
	if len(xs) < 2 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
