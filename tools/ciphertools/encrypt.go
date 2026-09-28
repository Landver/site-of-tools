package ciphertools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// C5 — symmetric encryption with an explicit key: AES-GCM, ChaCha20-Poly1305,
// and AES-CBC for systems that still need it. The output layout is fixed and
// stated on every result, because an encrypt tool whose output only it can
// read is no use (docs/01-feature-inventory.md, C5):
//
//	AEAD: nonce ‖ ciphertext ‖ tag
//	CBC:  iv ‖ ciphertext (PKCS#7)
//
// The key is bytes, given as hex or base64, and its length must already be
// right. Text is never padded or truncated into a key, and there is no
// passphrase mode: that means an MD5 KDF (docs/01, cut), and the honest
// version is "derive a key on /password, encrypt here". Not live: each run
// draws a fresh random nonce.

func init() {
	register(Op{Name: "encrypt", Path: "/encrypt", Page: "encrypt", Fragment: "cipher/encrypt-result", Run: runEncrypt})
}

// Cipher ids: the algo field's values.
const (
	CipherAESGCM   = "aes-gcm"
	CipherChaCha20 = "chacha20-poly1305"
	CipherAESCBC   = "aes-cbc"
)

const (
	aeadNonceBytes = 12
	aeadTagBytes   = 16
	cbcIVBytes     = aes.BlockSize
)

type cipherSpec struct {
	id    string
	aead  bool
	nonce int
	// keys are the accepted key lengths; keyText says so in words.
	keys    []int
	keyText string
}

var cipherSpecs = map[string]cipherSpec{
	CipherAESGCM:   {id: CipherAESGCM, aead: true, nonce: aeadNonceBytes, keys: []int{16, 24, 32}, keyText: "AES takes exactly 16, 24 or 32 bytes (AES-128, AES-192, AES-256)"},
	CipherChaCha20: {id: CipherChaCha20, aead: true, nonce: aeadNonceBytes, keys: []int{32}, keyText: "ChaCha20-Poly1305 takes exactly 32 bytes"},
	CipherAESCBC:   {id: CipherAESCBC, nonce: cbcIVBytes, keys: []int{16, 24, 32}, keyText: "AES takes exactly 16, 24 or 32 bytes (AES-128, AES-192, AES-256)"},
}

func (c cipherSpec) name(keyLen int) string {
	switch c.id {
	case CipherAESGCM:
		return fmt.Sprintf("AES-%d-GCM", keyLen*8)
	case CipherAESCBC:
		return fmt.Sprintf("AES-%d-CBC", keyLen*8)
	}
	return "ChaCha20-Poly1305"
}

func (c cipherSpec) nonceName() string {
	if c.aead {
		return "nonce"
	}
	return "IV"
}

// Blob is one byte string of the output, in both encodings people paste.
type Blob struct {
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
	Bytes  int    `json:"bytes"`
}

func blobOf(b []byte) Blob {
	return Blob{Hex: hex.EncodeToString(b), Base64: base64.StdEncoding.EncodeToString(b), Bytes: len(b)}
}

// EncryptResult is the encrypt op's answer, for either direction.
type EncryptResult struct {
	Mode      string `json:"mode"` // encrypt | decrypt
	Algorithm string `json:"algorithm"`
	// Layout is the byte layout of Combined, with each part's length.
	Layout    string `json:"layout"`
	KeyBytes  int    `json:"key_bytes"`
	NonceName string `json:"nonce_name"` // nonce | IV
	// NonceFrom: random, supplied (encrypt), blob or field (decrypt).
	NonceFrom  string `json:"nonce_from"`
	Nonce      Blob   `json:"nonce"`
	Ciphertext Blob   `json:"ciphertext"`
	Tag        *Blob  `json:"tag,omitempty"`
	// Combined is nonce ‖ ciphertext ‖ tag, or iv ‖ ciphertext.
	Combined  Blob `json:"combined"`
	Plaintext Text `json:"plaintext"`
	// PlaintextReadAs: how the encrypt input was read.
	PlaintextReadAs string `json:"plaintext_read_as,omitempty"`
	// DataReadAs: how the decrypt input was read (base64 variant, or hex).
	DataReadAs string    `json:"data_read_as,omitempty"`
	AADBytes   int       `json:"aad_bytes,omitempty"`
	Warnings   []Warning `json:"warnings,omitempty"`
}

func (r *EncryptResult) warn(level, text string) {
	r.Warnings = append(r.Warnings, Warning{level, text})
}

// errAuth is the whole of what an AEAD can say about a failed open.
var errAuth = errors.New("decryption failed: wrong key, wrong AAD, or corrupted data. The tag checks all of them at once, so it can't say which")

func runEncrypt(in Input) (any, error) {
	algo := strings.ToLower(strings.TrimSpace(in.Get("algo")))
	if algo == "" {
		algo = CipherAESGCM
	}
	spec, ok := cipherSpecs[algo]
	if !ok {
		return nil, fmt.Errorf("algo: want aes-gcm, chacha20-poly1305 or aes-cbc, got %q", algo)
	}
	key, err := encryptKey(in, spec)
	if err != nil {
		return nil, err
	}
	var nonce []byte
	if v := strings.TrimSpace(in.Get("nonce")); v != "" {
		if nonce, err = DecodeBytes(v, EncHex); err != nil {
			return nil, fmt.Errorf("%s: %w", spec.nonceName(), err)
		}
		if len(nonce) != spec.nonce {
			return nil, fmt.Errorf("%s: %d bytes; %s takes a %d-byte %s", spec.nonceName(), len(nonce), spec.name(len(key)), spec.nonce, spec.nonceName())
		}
	}
	var aad []byte
	if v := in.Get("aad"); v != "" {
		if !spec.aead {
			return nil, errors.New("aad: AES-CBC has no associated data. AAD is for AES-GCM and ChaCha20-Poly1305")
		}
		if aad, err = DecodeBytes(v, in.Get("aad_enc")); err != nil {
			return nil, fmt.Errorf("aad: %w", err)
		}
	}
	r := &EncryptResult{Algorithm: spec.name(len(key)), KeyBytes: len(key), NonceName: spec.nonceName(), AADBytes: len(aad)}
	switch mode := strings.ToLower(strings.TrimSpace(in.Get("mode"))); mode {
	case "", "encrypt":
		r.Mode = "encrypt"
		err = r.encrypt(in, spec, key, nonce, aad)
	case "decrypt":
		r.Mode = "decrypt"
		err = r.decrypt(in, spec, key, nonce, aad)
	default:
		return nil, fmt.Errorf("mode: want encrypt or decrypt, got %q", mode)
	}
	if err != nil {
		return nil, err
	}
	r.layout(spec)
	r.commonWarnings(spec, key)
	return r, nil
}

// encryptKey decodes the key and insists on its exact length. A UTF-8 key is
// refused outright: a passphrase is not a key, and stretching or cutting one
// to fit is the bug that makes two tools disagree.
func encryptKey(in Input, spec cipherSpec) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(in.Get("key_enc")))
	switch enc {
	case "":
		enc = EncHex
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
	key, err := DecodeBytes(raw, enc)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	for _, n := range spec.keys {
		if len(key) == n {
			return key, nil
		}
	}
	msg := fmt.Sprintf("key: %d bytes. %s; keys are never padded or truncated here", len(key), spec.keyText)
	// The commonest cause: 64 hex digits read as base64, or the reverse.
	other := map[string]string{EncHex: EncBase64, EncBase64: EncHex, EncBase64URL: EncHex}[enc]
	if alt, err := DecodeBytes(raw, other); err == nil {
		for _, n := range spec.keys {
			if len(alt) == n {
				msg += fmt.Sprintf(". Read as %s it is %d bytes: is the key %s?", encName(other), n, encName(other))
				break
			}
		}
	}
	return nil, errors.New(msg)
}

func (r *EncryptResult) encrypt(in Input, spec cipherSpec, key, nonce, aad []byte) error {
	pt, how, err := decodeInput(in.Get("text"), in.Get("enc"))
	if err != nil {
		return fmt.Errorf("plaintext: %w", err)
	}
	r.Plaintext, r.PlaintextReadAs = textOf(pt), how
	r.NonceFrom = "supplied"
	if nonce == nil {
		nonce, r.NonceFrom = randomBytes(spec.nonce), "random"
	}
	r.Nonce = blobOf(nonce)
	if spec.aead {
		a, err := newAEAD(spec, key)
		if err != nil {
			return err
		}
		sealed := a.Seal(nil, nonce, pt, aad)
		ct, tag := sealed[:len(sealed)-aeadTagBytes], sealed[len(sealed)-aeadTagBytes:]
		r.Ciphertext, r.Tag = blobOf(ct), ptr(blobOf(tag))
		r.Combined = blobOf(concat(nonce, sealed))
		if r.NonceFrom == "supplied" {
			r.warn(LevelDanger, fmt.Sprintf("You supplied the nonce. Encrypting two messages with the same key and nonce under %s leaks the XOR of the plaintexts and lets anyone forge messages. Leave it blank for a random one unless you are reproducing a test vector.", r.Algorithm))
		}
	} else {
		b, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("key: %w", err)
		}
		padded := pkcs7Pad(pt)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(b, nonce).CryptBlocks(ct, padded)
		r.Ciphertext = blobOf(ct)
		r.Combined = blobOf(concat(nonce, ct))
		if r.NonceFrom == "supplied" {
			r.warn(LevelWarn, "You supplied the IV. A CBC IV must be unpredictable: a fixed or guessable one shows when two messages start with the same block. Leave it blank for a random one unless you are reproducing a test vector.")
		}
	}
	if len(pt) == 0 {
		r.warn(LevelInfo, "The plaintext is empty: the output is only the "+spec.nonceName()+" and "+map[bool]string{true: "the tag.", false: "one block of padding."}[spec.aead])
	}
	return nil
}

func (r *EncryptResult) decrypt(in Input, spec cipherSpec, key, nonce, aad []byte) error {
	raw := in.Get("data")
	if strings.TrimSpace(raw) == "" {
		return errors.New("no ciphertext given: paste the output of an encrypt, as base64 or hex")
	}
	enc := strings.ToLower(strings.TrimSpace(in.Get("data_enc")))
	switch enc {
	case "", "auto":
		// Hex digits are valid base64 too, but base64 of 28 or more random
		// bytes (the shortest AEAD output) is all hex digits about once in
		// 10^18 tries, so all-hex means hex.
		enc = EncBase64
		if c, _ := stripSpace(raw); len(c)%2 == 0 && allHex(c) {
			enc = EncHex
		}
	case EncBase64, EncBase64URL, EncHex:
	default:
		return fmt.Errorf("data_enc: want auto, base64 or hex, got %q", enc)
	}
	blob, how, err := decodeInput(raw, enc)
	if err != nil {
		return fmt.Errorf("ciphertext: %w", err)
	}
	r.DataReadAs = how
	body := blob
	r.NonceFrom = "field"
	switch {
	case nonce == nil:
		// The layout this page writes: the nonce or IV comes first.
		if len(blob) < spec.nonce {
			return fmt.Errorf("the ciphertext is %d bytes, shorter than the %d-byte %s it should start with", len(blob), spec.nonce, spec.nonceName())
		}
		nonce, body, r.NonceFrom = blob[:spec.nonce], blob[spec.nonce:], "blob"
	case bytes.HasPrefix(blob, nonce):
		// The whole output of an encrypt run with this nonce, pasted back with
		// the nonce still in its field. A ciphertext that merely starts with the
		// same 12 or 16 bytes is a 2^-96 chance.
		body, r.NonceFrom = blob[len(nonce):], "blob"
		r.warn(LevelInfo, fmt.Sprintf("The data starts with the %s in the %s field, so it was read as %s ‖ the rest.", spec.nonceName(), spec.nonceName(), spec.nonceName()))
	}
	r.Nonce = blobOf(nonce)
	r.Combined = blobOf(concat(nonce, body))
	var pt []byte
	if spec.aead {
		if len(body) < aeadTagBytes {
			return fmt.Errorf("%s %d bytes, fewer than the 16-byte tag alone. Is part of it missing?", r.afterNonce(spec), len(body))
		}
		a, err := newAEAD(spec, key)
		if err != nil {
			return err
		}
		r.Ciphertext, r.Tag = blobOf(body[:len(body)-aeadTagBytes]), ptr(blobOf(body[len(body)-aeadTagBytes:]))
		if pt, err = a.Open(nil, nonce, body, aad); err != nil {
			if r.NonceFrom == "field" {
				return errors.New("decryption failed: wrong key, wrong nonce, wrong AAD, or corrupted data. The tag checks all of them at once, so it can't say which")
			}
			return errAuth
		}
	} else {
		if len(body) == 0 || len(body)%aes.BlockSize != 0 {
			return fmt.Errorf("%s %d bytes, not a whole number of 16-byte blocks: the data is truncated, or it has no IV in front", r.afterNonce(spec), len(body))
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("key: %w", err)
		}
		r.Ciphertext = blobOf(body)
		padded := make([]byte, len(body))
		cipher.NewCBCDecrypter(b, nonce).CryptBlocks(padded, body)
		if pt, err = pkcs7Unpad(padded); err != nil {
			return err
		}
		r.warn(LevelInfo, "CBC can't tell a wrong key from the right one: about one wrong key in 256 still ends in valid padding and decrypts to noise. If the plaintext looks random, the key or the IV is wrong.")
	}
	r.Plaintext = textOf(pt)
	return nil
}

// afterNonce starts a length error: the body follows the nonce in the data,
// or is all of it when the nonce came from its own field.
func (r *EncryptResult) afterNonce(spec cipherSpec) string {
	if r.NonceFrom == "field" {
		return "the data is"
	}
	return fmt.Sprintf("after the %d-byte %s there are", spec.nonce, spec.nonceName())
}

func newAEAD(spec cipherSpec, key []byte) (cipher.AEAD, error) {
	if spec.id == CipherChaCha20 {
		a, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		return a, nil
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return cipher.NewGCM(b)
}

// pkcs7Pad always adds 1 to 16 bytes, each holding the count, so the unpadder
// never has to guess.
func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

var errPadding = errors.New("decryption failed: wrong key or corrupted data. The PKCS#7 padding at the end is invalid, which is all CBC can report, as it has no authentication")

func pkcs7Unpad(b []byte) ([]byte, error) {
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, errPadding
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errPadding
		}
	}
	return b[:len(b)-n], nil
}

func (r *EncryptResult) layout(spec cipherSpec) {
	if spec.aead {
		r.Layout = fmt.Sprintf("nonce (%d bytes) ‖ ciphertext (%d bytes) ‖ tag (%d bytes)", r.Nonce.Bytes, r.Ciphertext.Bytes, aeadTagBytes)
		return
	}
	r.Layout = fmt.Sprintf("IV (%d bytes) ‖ ciphertext (%d bytes, PKCS#7 padded)", r.Nonce.Bytes, r.Ciphertext.Bytes)
}

func (r *EncryptResult) commonWarnings(spec cipherSpec, key []byte) {
	if !spec.aead {
		r.warn(LevelWarn, "AES-CBC is unauthenticated and malleable: anyone can flip bits of the ciphertext to change the plaintext in predictable places, and nothing detects it. Use it only to talk to a system that requires it, with an HMAC over iv ‖ ciphertext, or use AES-GCM.")
	}
	if allZero(key) {
		r.warn(LevelWarn, "The key is all zero bytes: fine for a test vector, never for real data.")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func concat(a, b []byte) []byte { return append(append(make([]byte, 0, len(a)+len(b)), a...), b...) }

func ptr[T any](v T) *T { return &v }
