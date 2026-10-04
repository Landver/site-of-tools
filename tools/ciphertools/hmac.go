package ciphertools

import (
	"crypto/hmac"
	"fmt"
	"strings"
)

// C3 — HMAC with every common hash at once, and verify a pasted MAC. The
// everyday use is "why doesn't my webhook signature match": GitHub, Stripe and
// Slack all sign the raw request body with HMAC-SHA256, and the answer is
// nearly always the key's encoding or a body that was re-serialised on the way
// (docs/01-feature-inventory.md, C3).

func init() {
	register(Op{Name: "hmac", Path: "/hmac", Page: "hmac", Fragment: "cipher/hmac-result", Run: runHMAC,
		Fields: []Field{
			{Name: "text", Kind: KindString,
				Description: "The message, read per enc; for a webhook, the raw request body byte for byte, since re-serialised JSON won't match."},
			{Name: "enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
				Description: "How text is written: utf8 takes it as typed; hex, base64, base64url or base32 decode it first."},
			{Name: "key", Kind: KindString,
				Description: "The HMAC key, read per key_enc, e.g. a webhook signing secret."},
			{Name: "key_enc", Kind: KindEnum, Enum: append([]string{EncAuto}, byteEncodings...), Default: EncAuto,
				Description: "How key is written: auto reads it as UTF-8 text and, when expected doesn't match that way, tries base64 and hex too and says which reading matched."},
			{Name: "expected", Kind: KindString,
				Description: "A MAC to check in constant time against every algorithm, as hex or base64, bare or labelled (GitHub's sha256=…, a Stripe-Signature header)."},
		}})
}

// hmacAlgs are the hashAlgs ids offered as HMACs, in display order.
var hmacAlgs = []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"}

// HMACResult is the hmac op's answer.
type HMACResult struct {
	MessageBytes  int       `json:"message_bytes"`
	MessageReadAs string    `json:"message_read_as"`
	KeyBytes      int       `json:"key_bytes"`
	KeyReadAs     string    `json:"key_read_as"`
	MACs          []Digest  `json:"macs"`
	Compare       *Compare  `json:"compare,omitempty"`
	Warnings      []Warning `json:"warnings,omitempty"`
}

func runHMAC(in Input) (any, error) {
	msg, msgHow, err := decodeInput(in.Get("text"), in.Get("enc"))
	if err != nil {
		return nil, fmt.Errorf("message: %w", err)
	}
	keyInput, keyEnc := in.Get("key"), in.Get("key_enc")
	// Detect (the default) reads the key as text until there is an expected MAC
	// to test the other readings against; see detectKey below.
	auto := keyEnc == "" || keyEnc == EncAuto
	readEnc := keyEnc
	if auto {
		readEnc = EncUTF8
	}
	key, keyHow, err := decodeInput(keyInput, readEnc)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	r := &HMACResult{MessageBytes: len(msg), MessageReadAs: msgHow, KeyBytes: len(key), KeyReadAs: keyHow,
		MACs: macsOf(msg, key)}

	expected := in.Get("expected")
	if strings.TrimSpace(expected) != "" {
		r.Compare = compareDigests(expected, r.MACs,
			"Check the key's encoding (a secret handed out as base64 or hex is not the same key as that text read as UTF-8), and that the message is the raw body byte for byte: parsed and re-serialised JSON won't match.")
		if !r.Compare.Match {
			if k, how, c := detectKey(msg, keyInput, key, expected); c != nil {
				if auto {
					// The reading that matches IS the key: show its MACs.
					key, r.KeyBytes, r.KeyReadAs, r.MACs, r.Compare = k, len(k), how+" (detected: the reading that matches)", macsOf(msg, k), c
					r.Compare.Detail += " Matched with the key read as " + how + "."
				} else {
					r.Compare.Detail = fmt.Sprintf("No match with the key read as %s, but it DOES match %s with the key read as %s. Set \"Key is\" to match.",
						keyHow, strings.Join(c.Matches, ", "), how)
				}
			}
		}
	}

	r.keyWarnings(key, keyInput)
	if len(msg) == 0 {
		r.warn(LevelInfo, "The message is empty: these are the MACs of zero bytes.")
	}
	r.Warnings = append(r.Warnings, byteNotes(msg, " Webhook bodies usually don't end in one; a copy from a terminal or an editor often does.")...)
	return r, nil
}

// macsOf is msg's HMAC under key for every algorithm, in display order.
func macsOf(msg, key []byte) []Digest {
	var out []Digest
	for _, id := range hmacAlgs {
		a := hashAlgByID(id)
		m := hmac.New(a.new, key)
		m.Write(msg)
		note := ""
		if a.weak {
			// MD5 and SHA-1 collisions don't break HMAC, so this is advice, not an alarm.
			note = "legacy; still sound as a MAC, but use SHA-256 for anything new"
		}
		out = append(out, newDigest(a.id, "HMAC-"+a.name, note, false, m.Sum(nil)))
	}
	return out
}

// detectKey tries the other readings of the key (base64, hex) against the
// expected MAC: the same trap as a JWT secret (EncAuto in jwt.go), where a key
// handed out as base64 looks like text and read as text is a different key.
// Returns the first reading that matches, or a nil Compare.
func detectKey(msg []byte, keyInput string, tried []byte, expected string) ([]byte, string, *Compare) {
	for _, enc := range []string{EncBase64, EncHex} {
		k, how, err := decodeInput(keyInput, enc)
		if err != nil || string(k) == string(tried) {
			continue
		}
		if c := compareDigests(expected, macsOf(msg, k), ""); c.Match {
			return k, how, c
		}
	}
	return nil, "", nil
}

func (r *HMACResult) warn(level, text string) { r.Warnings = append(r.Warnings, Warning{level, text}) }

func (r *HMACResult) keyWarnings(key []byte, keyInput string) {
	if len(key) == 0 {
		r.warn(LevelWarn, "The key is empty. That is valid HMAC, but anyone can compute the same MAC, so it proves nothing.")
		return
	}
	var short []string
	for _, d := range r.MACs {
		if len(key) < d.Bytes {
			short = append(short, fmt.Sprintf("%s (%d)", d.Name, d.Bytes))
		}
	}
	switch {
	case len(short) == len(r.MACs):
		r.warn(LevelWarn, fmt.Sprintf("The key is %d bytes, shorter than every hash output here. RFC 2104 recommends a key at least as long as the output: 32 random bytes for HMAC-SHA-256.", len(key)))
	case len(short) > 0:
		r.warn(LevelWarn, fmt.Sprintf("The key is %d bytes, shorter than the output of %s. RFC 2104 recommends a key at least as long as the output.", len(key), strings.Join(short, ", ")))
	}
	// The smallest block size here is 64 bytes (MD5 through SHA-256).
	if len(key) > 64 {
		r.warn(LevelInfo, fmt.Sprintf("The key is %d bytes, longer than some of these hashes' block size (64 bytes for SHA-256, 128 for SHA-512), so HMAC hashes it first. That is RFC 2104, not a bug.", len(key)))
	}
	if strings.HasPrefix(r.KeyReadAs, "UTF-8") && strings.TrimSpace(keyInput) != keyInput {
		r.warn(LevelWarn, "The key starts or ends with whitespace, and as UTF-8 text that whitespace is part of the key.")
	}
}
