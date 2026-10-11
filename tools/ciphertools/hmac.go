package ciphertools

import (
	"fmt"
	"strings"
)

// The everyday use is a webhook signature that won't match: nearly always the key's encoding or a re-serialised body.

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

type HMACResult struct {
	MessageBytes  int      `json:"message_bytes"`
	MessageReadAs string   `json:"message_read_as"`
	KeyBytes      int      `json:"key_bytes"`
	KeyReadAs     string   `json:"key_read_as"`
	MACs          []Digest `json:"macs"`
	Compare       *Compare `json:"compare,omitempty"`
	Warnings      Warnings `json:"warnings,omitempty"`
}

func runHMAC(in Input) (any, error) {
	msg, msgHow, err := decodeInput(in.Get("text"), in.Get("enc"))
	if err != nil {
		return nil, fmt.Errorf("message: %w", err)
	}
	keyInput, keyEnc := in.Get("key"), in.Get("key_enc")
	// auto reads the key as text until an expected MAC can test its other readings.
	auto := keyEnc == "" || keyEnc == EncAuto
	if auto {
		keyEnc = EncUTF8
	}
	key, keyHow, err := decodeInput(keyInput, keyEnc)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	r := &HMACResult{MessageBytes: len(msg), MessageReadAs: msgHow, KeyBytes: len(key), KeyReadAs: keyHow, MACs: hashDigests(msg, key, true)}
	if e := in.Get("expected"); strings.TrimSpace(e) != "" {
		r.Compare = compareDigests(e, r.MACs,
			"Check the key's encoding (a secret handed out as base64 or hex is not the same key as that text read as UTF-8), and that the message is the raw body byte for byte: parsed and re-serialised JSON won't match.")
		// The JWT secret trap (EncAuto): a key handed out as base64 looks like text, and as text is another key.
		for _, enc := range []string{EncBase64, EncHex} {
			k, how, err := decodeInput(keyInput, enc)
			if r.Compare.Match || err != nil || string(k) == string(key) {
				continue
			}
			macs := hashDigests(msg, k, true)
			c := compareDigests(e, macs, "")
			if !c.Match {
				continue
			}
			if auto {
				key, r.KeyBytes, r.KeyReadAs, r.MACs, r.Compare = k, len(k), how+" (detected: the reading that matches)", macs, c
				r.Compare.Detail += " Matched with the key read as " + how + "."
			} else {
				r.Compare.Detail = fmt.Sprintf("No match with the key read as %s, but it DOES match %s with the key read as %s. Set \"Key is\" to match.",
					keyHow, strings.Join(c.Matches, ", "), how)
			}
			break
		}
	}

	var short []string
	for _, d := range r.MACs {
		if len(key) < d.Bytes {
			short = append(short, fmt.Sprintf("%s (%d)", d.Name, d.Bytes))
		}
	}
	switch {
	case len(key) == 0:
		r.Warnings.add(LevelWarn, "The key is empty. That is valid HMAC, but anyone can compute the same MAC, so it proves nothing.")
	case len(short) == len(r.MACs):
		r.Warnings.add(LevelWarn, fmt.Sprintf("The key is %d bytes, shorter than every hash output here. RFC 2104 recommends a key at least as long as the output: 32 random bytes for HMAC-SHA-256.", len(key)))
	case len(short) > 0:
		r.Warnings.add(LevelWarn, fmt.Sprintf("The key is %d bytes, shorter than the output of %s. RFC 2104 recommends a key at least as long as the output.", len(key), strings.Join(short, ", ")))
	}
	// 64 bytes is the smallest block size here (MD5 through SHA-256).
	if len(key) > 64 {
		r.Warnings.add(LevelInfo, fmt.Sprintf("The key is %d bytes, longer than some of these hashes' block size (64 bytes for SHA-256, 128 for SHA-512), so HMAC hashes it first. That is RFC 2104, not a bug.", len(key)))
	}
	if strings.HasPrefix(r.KeyReadAs, "UTF-8") && strings.TrimSpace(keyInput) != keyInput {
		r.Warnings.add(LevelWarn, "The key starts or ends with whitespace, and as UTF-8 text that whitespace is part of the key.")
	}
	if len(msg) == 0 {
		r.Warnings.add(LevelInfo, "The message is empty: these are the MACs of zero bytes.")
	}
	byteNotes(&r.Warnings, msg, " Webhook bodies usually don't end in one; a copy from a terminal or an editor often does.")
	return r, nil
}
