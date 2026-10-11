package ciphertools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// No passphrase mode: that is an MD5 KDF, and the honest version is "derive a key on /password, encrypt here".

func init() {
	register(Op{Name: "encrypt", Path: "/encrypt", Page: "encrypt", Fragment: "cipher/encrypt-result", Run: runEncrypt,
		Fields: []Field{
			{Name: "mode", Kind: KindEnum, Enum: []string{"encrypt", "decrypt"}, Default: "encrypt",
				Description: "encrypt text, or decrypt data."},
			encryptAlgoField,
			{Name: "key", Kind: KindString,
				Description: "The key, read per key_enc: exactly 16, 24 or 32 bytes for AES, 32 for ChaCha20-Poly1305; required to decrypt, while encrypting without one makes a random 32-byte key and returns it as generated_key."},
			{Name: "key_enc", Kind: KindEnum, Enum: []string{EncHex, EncBase64, EncBase64URL}, Default: EncHex,
				Description: "How key is written; utf8 is refused, because a passphrase is not a key."},
			{Name: "nonce", Kind: KindString,
				Description: "The nonce (the IV for aes-cbc) as hex, 12 bytes or 16 for aes-cbc; omit it to encrypt with a random one, or to decrypt data that starts with it."},
			{Name: "aad", Kind: KindString,
				Description: "Associated data for aes-gcm and chacha20-poly1305, read per aad_enc: authenticated but not encrypted, so decrypting needs the same."},
			{Name: "aad_enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
				Description: "How aad is written: utf8 takes it as typed; hex, base64, base64url or base32 decode it first."},
			{Name: "text", Kind: KindString,
				Description: "The plaintext to encrypt (mode encrypt), read per enc."},
			{Name: "enc", Kind: KindEnum, Enum: byteEncodings, Default: EncUTF8,
				Description: "How text is written: utf8 takes it as typed; hex, base64, base64url or base32 decode it first."},
			{Name: "data", Kind: KindString,
				Description: "The ciphertext to decrypt (mode decrypt), as base64 or hex: an encrypt's combined output, nonce ‖ ciphertext ‖ tag, or iv ‖ ciphertext for aes-cbc."},
			{Name: "data_enc", Kind: KindEnum, Enum: []string{EncAuto, EncBase64, EncBase64URL, EncHex}, Default: EncAuto,
				Description: "How data is written; auto reads all-hex data as hex and anything else as base64."},
		}})
}

var encryptAlgoField = Field{Name: "algo", Kind: KindEnum, Enum: []string{"aes-gcm", "chacha20-poly1305", "aes-cbc"}, Default: "aes-gcm",
	Description: "The cipher: aes-gcm or chacha20-poly1305 (authenticated: 12-byte nonce, 16-byte tag), or aes-cbc (unauthenticated: 16-byte IV, PKCS#7 padding) for systems that require it."}

// cipherSpec is one algo. Key lengths are checked against keys first, so its constructors can't fail.
type cipherSpec struct {
	name      string                            // %d becomes the key size in bits
	aead      func([]byte) (cipher.AEAD, error) // nil for CBC
	nonce     int
	nonceName string
	keys      []int
	keyText   string
}

const (
	aeadTagBytes   = 16
	encryptAESKeys = "AES takes exactly 16, 24 or 32 bytes (AES-128, AES-192, AES-256)"
)

var cipherSpecs = map[string]cipherSpec{
	"aes-gcm": {name: "AES-%d-GCM", nonce: 12, nonceName: "nonce", keys: []int{16, 24, 32}, keyText: encryptAESKeys,
		aead: func(key []byte) (cipher.AEAD, error) { b, _ := aes.NewCipher(key); return cipher.NewGCM(b) }},
	"chacha20-poly1305": {name: "ChaCha20-Poly1305", aead: chacha20poly1305.New, nonce: 12, nonceName: "nonce", keys: []int{32}, keyText: "ChaCha20-Poly1305 takes exactly 32 bytes"},
	"aes-cbc":           {name: "AES-%d-CBC", nonce: aes.BlockSize, nonceName: "IV", keys: []int{16, 24, 32}, keyText: encryptAESKeys},
}

type Blob struct {
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
	Bytes  int    `json:"bytes"`
}

func blobOf(b []byte) Blob {
	return Blob{Hex: hex.EncodeToString(b), Base64: base64.StdEncoding.EncodeToString(b), Bytes: len(b)}
}

type EncryptResult struct {
	Mode            string   `json:"mode"`
	Algorithm       string   `json:"algorithm"`
	Layout          string   `json:"layout"`
	KeyBytes        int      `json:"key_bytes"`
	NonceName       string   `json:"nonce_name"`
	NonceFrom       string   `json:"nonce_from"` // random, supplied (encrypt); blob, field (decrypt)
	Nonce           Blob     `json:"nonce"`
	Ciphertext      Blob     `json:"ciphertext"`
	Tag             *Blob    `json:"tag,omitempty"`
	Combined        Blob     `json:"combined"`
	Plaintext       Text     `json:"plaintext"`
	PlaintextReadAs string   `json:"plaintext_read_as,omitempty"`
	DataReadAs      string   `json:"data_read_as,omitempty"`
	AADBytes        int      `json:"aad_bytes,omitempty"`
	GeneratedKey    *Blob    `json:"generated_key,omitempty"`
	Warnings        Warnings `json:"warnings,omitempty"`
}

func runEncrypt(in Input) (any, error) {
	algo, err := enumField(in.Get("algo"), encryptAlgoField)
	if err != nil {
		return nil, err
	}
	spec := cipherSpecs[algo]
	r := &EncryptResult{Mode: choice(in.Get("mode"), "encrypt"), NonceName: spec.nonceName}
	var key, nonce, aad, body []byte
	// Without the generated key nothing decrypts, so the result shows it; 32 bytes fit every algo.
	if r.Mode != "decrypt" && strings.TrimSpace(in.Get("key")) == "" {
		key = randomBytes(32)
		r.GeneratedKey = ptr(blobOf(key))
	} else if key, err = encryptKey(in, spec); err != nil {
		return nil, err
	}
	r.Algorithm, r.KeyBytes = strings.Replace(spec.name, "%d", fmt.Sprint(8*len(key)), 1), len(key)
	if v := strings.TrimSpace(in.Get("nonce")); v != "" {
		if nonce, err = decodeHex(v); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.nonceName, err)
		}
		if len(nonce) != spec.nonce {
			return nil, fmt.Errorf("%s: %d bytes; %s takes a %d-byte %s", spec.nonceName, len(nonce), r.Algorithm, spec.nonce, spec.nonceName)
		}
	}
	if v := in.Get("aad"); v != "" {
		if spec.aead == nil {
			return nil, errors.New("aad: AES-CBC has no associated data. AAD is for AES-GCM and ChaCha20-Poly1305")
		}
		if aad, _, err = decodeInput(v, in.Get("aad_enc")); err != nil {
			return nil, fmt.Errorf("aad: %w", err)
		}
	}
	r.AADBytes = len(aad)
	switch r.Mode {
	case "encrypt":
		nonce, body, err = r.encrypt(in, spec, key, nonce, aad)
	case "decrypt":
		nonce, body, err = r.decrypt(in, spec, key, nonce, aad)
	default:
		return nil, fmt.Errorf("mode: want encrypt or decrypt, got %q", r.Mode)
	}
	if err != nil {
		return nil, err
	}
	r.Nonce, r.Ciphertext, r.Combined = blobOf(nonce), blobOf(body), blobOf(slices.Concat(nonce, body))
	if spec.aead != nil {
		n := len(body) - aeadTagBytes
		r.Ciphertext, r.Tag = blobOf(body[:n]), ptr(blobOf(body[n:]))
		r.Layout = fmt.Sprintf("nonce (%d bytes) ‖ ciphertext (%d bytes) ‖ tag (%d bytes)", len(nonce), n, aeadTagBytes)
	} else {
		r.Layout = fmt.Sprintf("IV (%d bytes) ‖ ciphertext (%d bytes, PKCS#7 padded)", len(nonce), len(body))
		r.Warnings.add(LevelWarn, "AES-CBC is unauthenticated and malleable: anyone can flip bits of the ciphertext to change the plaintext in predictable places, and nothing detects it. Use it only to talk to a system that requires it, with an HMAC over iv ‖ ciphertext, or use AES-GCM.")
	}
	if bytes.Equal(key, make([]byte, len(key))) {
		r.Warnings.add(LevelWarn, "The key is all zero bytes: fine for a test vector, never for real data.")
	}
	return r, nil
}

// encryptKey takes exact bytes only: padding or cutting a passphrase to fit is what makes two tools disagree.
func encryptKey(in Input, spec cipherSpec) ([]byte, error) {
	enc := choice(in.Get("key_enc"), EncHex)
	switch enc {
	case EncHex, EncBase64, EncBase64URL:
	case EncUTF8:
		return nil, errors.New("key: read as hex or base64 only. A passphrase is not a key: derive one from it with PBKDF2 or Argon2 on the Passwords page, or make a random one on the Random page")
	default:
		return nil, fmt.Errorf("key_enc: want hex or base64, got %q", enc)
	}
	raw := in.Get("key")
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("no key given: paste the key as hex or base64. " + spec.keyText + ".")
	}
	key, _, err := decodeInput(raw, enc)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if slices.Contains(spec.keys, len(key)) {
		return key, nil
	}
	msg := fmt.Sprintf("key: %d bytes. %s; keys are never padded or truncated here", len(key), spec.keyText)
	// The commonest cause: 64 hex digits read as base64, or the reverse.
	other := map[string]string{EncHex: EncBase64, EncBase64: EncHex, EncBase64URL: EncHex}[enc]
	if alt, _, err := decodeInput(raw, other); err == nil && slices.Contains(spec.keys, len(alt)) {
		msg += fmt.Sprintf(". Read as %s it is %d bytes: is the key %s?", other, len(alt), other)
	}
	return nil, errors.New(msg)
}

// encrypt returns the nonce it used and the sealed body that follows it.
func (r *EncryptResult) encrypt(in Input, spec cipherSpec, key, nonce, aad []byte) ([]byte, []byte, error) {
	pt, how, err := decodeInput(in.Get("text"), in.Get("enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("plaintext: %w", err)
	}
	r.Plaintext, r.PlaintextReadAs, r.NonceFrom = textOf(pt), how, "supplied"
	switch {
	case nonce == nil:
		nonce, r.NonceFrom = randomBytes(spec.nonce), "random"
	case spec.aead != nil:
		r.Warnings.add(LevelDanger, fmt.Sprintf("You supplied the nonce. Encrypting two messages with the same key and nonce under %s leaks the XOR of the plaintexts and lets anyone forge messages. Leave it blank for a random one unless you are reproducing a test vector.", r.Algorithm))
	default:
		r.Warnings.add(LevelWarn, "You supplied the IV. A CBC IV must be unpredictable: a fixed or guessable one shows when two messages start with the same block. Leave it blank for a random one unless you are reproducing a test vector.")
	}
	var body []byte
	if spec.aead != nil {
		a, _ := spec.aead(key)
		body = a.Seal(nil, nonce, pt, aad)
	} else {
		// PKCS#7 always adds 1 to 16 bytes, each holding the count, so unpadding never guesses.
		n := aes.BlockSize - len(pt)%aes.BlockSize
		body = slices.Concat(pt, bytes.Repeat([]byte{byte(n)}, n))
		b, _ := aes.NewCipher(key)
		cipher.NewCBCEncrypter(b, nonce).CryptBlocks(body, body)
	}
	if len(pt) == 0 {
		r.Warnings.add(LevelInfo, "The plaintext is empty: the output is only the "+spec.nonceName+" and "+map[bool]string{true: "the tag.", false: "one block of padding."}[spec.aead != nil])
	}
	return nonce, body, nil
}

// decrypt returns the nonce it used and the body after it.
func (r *EncryptResult) decrypt(in Input, spec cipherSpec, key, nonce, aad []byte) ([]byte, []byte, error) {
	raw := in.Get("data")
	if strings.TrimSpace(raw) == "" {
		return nil, nil, errors.New("no ciphertext given: paste the output of an encrypt, as base64 or hex")
	}
	enc := choice(in.Get("data_enc"), EncAuto)
	switch enc {
	case EncAuto:
		// Hex is valid base64 too, but base64 of 28+ random bytes (the shortest AEAD output) is all hex once in 10^18.
		enc = EncBase64
		if c, _ := stripSpace(raw); len(c)%2 == 0 && allHex(c) {
			enc = EncHex
		}
	case EncBase64, EncBase64URL, EncHex:
	default:
		return nil, nil, fmt.Errorf("data_enc: want auto, base64 or hex, got %q", enc)
	}
	body, how, err := decodeInput(raw, enc)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext: %w", err)
	}
	r.DataReadAs, r.NonceFrom = how, "blob"
	after := fmt.Sprintf("after the %d-byte %s there are", spec.nonce, spec.nonceName)
	switch {
	case nonce == nil && len(body) < spec.nonce:
		return nil, nil, fmt.Errorf("the ciphertext is %d bytes, shorter than the %d-byte %s it should start with", len(body), spec.nonce, spec.nonceName)
	case nonce == nil:
		nonce, body = body[:spec.nonce], body[spec.nonce:]
	case bytes.HasPrefix(body, nonce):
		// A whole encrypt output pasted back with its nonce still in the field; a chance prefix is 2^-96.
		body = body[spec.nonce:]
		r.Warnings.add(LevelInfo, fmt.Sprintf("The data starts with the %[1]s in the %[1]s field, so it was read as %[1]s ‖ the rest.", spec.nonceName))
	default:
		r.NonceFrom, after = "field", "the data is"
	}
	var pt []byte
	if spec.aead != nil {
		if len(body) < aeadTagBytes {
			return nil, nil, fmt.Errorf("%s %d bytes, fewer than the 16-byte tag alone. Is part of it missing?", after, len(body))
		}
		a, _ := spec.aead(key)
		if pt, err = a.Open(nil, nonce, body, aad); err != nil {
			nonceCause := ""
			if r.NonceFrom == "field" {
				nonceCause = "wrong nonce, "
			}
			return nil, nil, fmt.Errorf("decryption failed: wrong key, %swrong AAD, or corrupted data. The tag checks all of them at once, so it can't say which", nonceCause)
		}
	} else {
		if len(body) == 0 || len(body)%aes.BlockSize != 0 {
			return nil, nil, fmt.Errorf("%s %d bytes, not a whole number of 16-byte blocks: the data is truncated, or it has no IV in front", after, len(body))
		}
		b, _ := aes.NewCipher(key)
		pt = make([]byte, len(body))
		cipher.NewCBCDecrypter(b, nonce).CryptBlocks(pt, body)
		n := int(pt[len(pt)-1])
		if n == 0 || n > aes.BlockSize || !bytes.Equal(pt[len(pt)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
			return nil, nil, errors.New("decryption failed: wrong key or corrupted data. The PKCS#7 padding at the end is invalid, which is all CBC can report, as it has no authentication")
		}
		pt = pt[:len(pt)-n]
		r.Warnings.add(LevelInfo, "CBC can't tell a wrong key from the right one: about one wrong key in 256 still ends in valid padding and decrypts to noise. If the plaintext looks random, the key or the IV is wrong.")
	}
	r.Plaintext = textOf(pt)
	return nonce, body, nil
}
