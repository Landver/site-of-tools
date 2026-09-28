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
	register(Op{Name: "hmac", Path: "/hmac", Page: "hmac", Fragment: "cipher/hmac-result", Run: runHMAC})
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
	key, keyHow, err := decodeInput(keyInput, keyEnc)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	r := &HMACResult{MessageBytes: len(msg), MessageReadAs: msgHow, KeyBytes: len(key), KeyReadAs: keyHow}

	for _, id := range hmacAlgs {
		a := hashAlgByID(id)
		m := hmac.New(a.new, key)
		m.Write(msg)
		note := ""
		if a.weak {
			// MD5 and SHA-1 collisions don't break HMAC, so this is advice, not an alarm.
			note = "legacy; still sound as a MAC, but use SHA-256 for anything new"
		}
		r.MACs = append(r.MACs, newDigest(a.id, "HMAC-"+a.name, note, false, m.Sum(nil)))
	}

	r.keyWarnings(key, keyInput, keyEnc)
	if len(msg) == 0 {
		r.warn(LevelInfo, "The message is empty: these are the MACs of zero bytes.")
	}
	r.Warnings = append(r.Warnings, byteNotes(msg, " Webhook bodies usually don't end in one; a copy from a terminal or an editor often does.")...)

	if e := in.Get("expected"); strings.TrimSpace(e) != "" {
		r.Compare = compareDigests(e, r.MACs,
			"Check the key's encoding (a secret handed out as base64 or hex is not the same key as that text read as UTF-8), and that the message is the raw body byte for byte: parsed and re-serialised JSON won't match.")
	}
	return r, nil
}

func (r *HMACResult) warn(level, text string) { r.Warnings = append(r.Warnings, Warning{level, text}) }

func (r *HMACResult) keyWarnings(key []byte, keyInput, keyEnc string) {
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
	if (keyEnc == "" || keyEnc == EncUTF8) && strings.TrimSpace(keyInput) != keyInput {
		r.warn(LevelWarn, "The key starts or ends with whitespace, and as UTF-8 text that whitespace is part of the key.")
	}
}
