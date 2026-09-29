package tests

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func encryptOf(t *testing.T, fields url.Values) *ciphertools.EncryptResult {
	t.Helper()
	res, err := runOp(t, "encrypt", fields, nil)
	if err != nil {
		t.Fatalf("encrypt %v: %v", fields, err)
	}
	return res.(*ciphertools.EncryptResult)
}

func encryptErr(t *testing.T, fields url.Values) error {
	t.Helper()
	_, err := runOp(t, "encrypt", fields, nil)
	if err == nil {
		t.Fatalf("encrypt %v: no error", fields)
	}
	return err
}

// The GCM spec's test cases 1 and 2 (McGrew and Viega): AES-128, key and IV
// all zero.
func TestEncryptAESGCMKnownVectors(t *testing.T) {
	zeroKey, zeroIV := strings.Repeat("00", 16), strings.Repeat("00", 12)
	r := encryptOf(t, url.Values{"algo": {"aes-gcm"}, "key": {zeroKey}, "nonce": {zeroIV}, "text": {""}})
	if r.Algorithm != "AES-128-GCM" || r.Tag == nil || r.Tag.Hex != "58e2fccefa7e3061367f1d57a4e7455a" || r.Ciphertext.Bytes != 0 {
		t.Errorf("empty plaintext: %+v", r)
	}
	if r.Combined.Hex != zeroIV+"58e2fccefa7e3061367f1d57a4e7455a" {
		t.Errorf("combined %s", r.Combined.Hex)
	}

	r = encryptOf(t, url.Values{"key": {zeroKey}, "nonce": {zeroIV}, "text": {strings.Repeat("00", 16)}, "enc": {"hex"}})
	if r.Ciphertext.Hex != "0388dace60b6a392f328c2b971b2fe78" || r.Tag.Hex != "ab6e47d42cec13bdf53a67b21257bddf" {
		t.Errorf("zero block: ciphertext %s tag %s", r.Ciphertext.Hex, r.Tag.Hex)
	}
	if r.Combined.Hex != zeroIV+"0388dace60b6a392f328c2b971b2fe78"+"ab6e47d42cec13bdf53a67b21257bddf" {
		t.Errorf("layout is not nonce ‖ ciphertext ‖ tag: %s", r.Combined.Hex)
	}
	if b, _ := base64.StdEncoding.DecodeString(r.Combined.Base64); hex.EncodeToString(b) != r.Combined.Hex {
		t.Error("combined base64 and hex disagree")
	}
	if r.Layout != "nonce (12 bytes) ‖ ciphertext (16 bytes) ‖ tag (16 bytes)" {
		t.Errorf("layout %q", r.Layout)
	}
	// A supplied nonce is a danger warning; an all-zero key is flagged too.
	if !hasLevel(r.Warnings, ciphertools.LevelDanger, "same key and nonce") || !noted(r.Warnings, "all zero bytes") {
		t.Errorf("warnings %+v", r.Warnings)
	}

	// The same vector decrypts from the combined form, in hex and in base64.
	for _, data := range []string{r.Combined.Hex, r.Combined.Base64} {
		d := encryptOf(t, url.Values{"mode": {"decrypt"}, "key": {zeroKey}, "data": {data}})
		if d.Plaintext.Hex != strings.Repeat("00", 16) || d.NonceFrom != "blob" {
			t.Errorf("decrypt %s: %+v", data, d)
		}
	}
}

// RFC 8439 §2.8.2, the AEAD_CHACHA20_POLY1305 example.
func TestEncryptChaCha20Poly1305RFC8439(t *testing.T) {
	r := encryptOf(t, url.Values{
		"algo":    {"chacha20-poly1305"},
		"key":     {"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"},
		"nonce":   {"070000004041424344454647"},
		"aad":     {"50515253c0c1c2c3c4c5c6c7"},
		"aad_enc": {"hex"},
		"text":    {"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."},
	})
	if r.Tag.Hex != "1ae10b594f09e26a7e902ecbd0600691" || !strings.HasPrefix(r.Ciphertext.Hex, "d31a8d34648e60db7b86afbc53ef7ec2") {
		t.Errorf("ciphertext %s tag %s", r.Ciphertext.Hex, r.Tag.Hex)
	}
	if r.Algorithm != "ChaCha20-Poly1305" || r.AADBytes != 12 {
		t.Errorf("%+v", r)
	}
}

// NIST SP 800-38A F.2.1, CBC-AES128.Encrypt, first block. PKCS#7 adds a
// whole block of padding to the 16-byte message.
func TestEncryptAESCBCKnownVector(t *testing.T) {
	r := encryptOf(t, url.Values{
		"algo": {"aes-cbc"}, "key": {"2b7e151628aed2a6abf7158809cf4f3c"}, "nonce": {"000102030405060708090a0b0c0d0e0f"},
		"text": {"6bc1bee22e409f96e93d7e117393172a"}, "enc": {"hex"},
	})
	if !strings.HasPrefix(r.Ciphertext.Hex, "7649abac8119b246cee98e9b12e9197d") || r.Ciphertext.Bytes != 32 || r.Tag != nil {
		t.Errorf("ciphertext %s (%d bytes)", r.Ciphertext.Hex, r.Ciphertext.Bytes)
	}
	if !strings.HasPrefix(r.Combined.Hex, "000102030405060708090a0b0c0d0e0f7649abac") {
		t.Errorf("layout is not iv ‖ ciphertext: %s", r.Combined.Hex)
	}
	if !noted(r.Warnings, "unauthenticated and malleable") || !noted(r.Warnings, "You supplied the IV") {
		t.Errorf("warnings %+v", r.Warnings)
	}
}

// Every algorithm and key size, random nonce, round-tripped through both
// output encodings, with and without AAD, the key as hex or base64.
func TestEncryptRoundTrips(t *testing.T) {
	plaintexts := []struct{ text, enc string }{
		{"", "utf8"}, {"hello", "utf8"}, {"naïve ☃ — 16 bytes?", "utf8"},
		{strings.Repeat("ab", 16), "hex"}, {"AAEC/f7/", "base64"}, {strings.Repeat("x", 33), "utf8"},
	}
	for _, c := range []struct {
		algo string
		keys []int
	}{
		{"aes-gcm", []int{16, 24, 32}}, {"chacha20-poly1305", []int{32}}, {"aes-cbc", []int{16, 24, 32}},
	} {
		for _, n := range c.keys {
			key := randomHex(t, n)
			for _, p := range plaintexts {
				for _, aad := range []string{"", "header v1"} {
					if aad != "" && c.algo == "aes-cbc" {
						continue
					}
					kenc, k := "hex", key
					if len(p.text)%2 == 1 {
						b, _ := hex.DecodeString(key)
						kenc, k = "base64", base64.StdEncoding.EncodeToString(b)
					}
					fields := url.Values{"algo": {c.algo}, "key": {k}, "key_enc": {kenc}, "text": {p.text}, "enc": {p.enc}, "aad": {aad}}
					e := encryptOf(t, fields)
					if e.NonceFrom != "random" || e.KeyBytes != n {
						t.Errorf("%s/%d: %+v", c.algo, n, e)
					}
					for _, data := range []string{e.Combined.Base64, e.Combined.Hex} {
						d := encryptOf(t, url.Values{"mode": {"decrypt"}, "algo": {c.algo}, "key": {k}, "key_enc": {kenc}, "data": {data}, "aad": {aad}})
						if d.Plaintext.Hex != e.Plaintext.Hex {
							t.Errorf("%s/%d %q aad %q: got %s, want %s", c.algo, n, p.text, aad, d.Plaintext.Hex, e.Plaintext.Hex)
						}
					}
				}
			}
		}
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Each encrypt draws a new nonce, so the same input never gives the same output.
func TestEncryptNonceIsFreshEachRun(t *testing.T) {
	f := url.Values{"key": {strings.Repeat("11", 32)}, "text": {"same"}}
	a, b := encryptOf(t, f), encryptOf(t, f)
	if a.Nonce.Hex == b.Nonce.Hex || a.Combined.Hex == b.Combined.Hex || a.Nonce.Bytes != 12 {
		t.Errorf("nonces %s and %s", a.Nonce.Hex, b.Nonce.Hex)
	}
	if strings.Trim(a.Nonce.Hex, "0") == "" {
		t.Error("nonce defaulted to zeros")
	}
	c := encryptOf(t, url.Values{"algo": {"aes-cbc"}, "key": {strings.Repeat("11", 16)}, "text": {"x"}})
	if c.Nonce.Bytes != 16 || c.NonceName != "IV" || noted(c.Warnings, "You supplied") {
		t.Errorf("CBC IV: %+v", c)
	}
}

// A tampered byte, a wrong key or wrong AAD all fail the same way, with the
// three causes named and no Go error text.
func TestEncryptAuthFailures(t *testing.T) {
	key := strings.Repeat("42", 32)
	for _, algo := range []string{"aes-gcm", "chacha20-poly1305"} {
		e := encryptOf(t, url.Values{"algo": {algo}, "key": {key}, "text": {"attack at dawn"}, "aad": {"v1"}})
		blob, _ := hex.DecodeString(e.Combined.Hex)
		for name, f := range map[string]url.Values{
			"tampered ciphertext": {"data": {flip(blob, 12)}, "key": {key}, "aad": {"v1"}},
			"tampered tag":        {"data": {flip(blob, len(blob)-1)}, "key": {key}, "aad": {"v1"}},
			"tampered nonce":      {"data": {flip(blob, 0)}, "key": {key}, "aad": {"v1"}},
			"wrong key":           {"data": {e.Combined.Hex}, "key": {strings.Repeat("43", 32)}, "aad": {"v1"}},
			"wrong AAD":           {"data": {e.Combined.Hex}, "key": {key}, "aad": {"v2"}},
			"missing AAD":         {"data": {e.Combined.Hex}, "key": {key}},
		} {
			f.Set("mode", "decrypt")
			f.Set("algo", algo)
			err := encryptErr(t, f)
			if !strings.Contains(err.Error(), "wrong key, wrong AAD, or corrupted data") || strings.Contains(err.Error(), "cipher:") ||
				strings.Contains(err.Error(), "chacha20poly1305:") {
				t.Errorf("%s %s: %v", algo, name, err)
			}
		}
		// Truncated below the tag: said as such.
		if err := encryptErr(t, url.Values{"mode": {"decrypt"}, "algo": {algo}, "key": {key}, "data": {hex.EncodeToString(blob[:20])}}); !strings.Contains(err.Error(), "fewer than the 16-byte tag") {
			t.Errorf("%s truncated: %v", algo, err)
		}
	}
}

func flip(b []byte, i int) string {
	c := append([]byte{}, b...)
	c[i] ^= 0x01
	return hex.EncodeToString(c)
}

// CBC has no tag, so a bad key shows up as bad padding, reported as "wrong
// key or corrupted data", never as a Go error.
func TestEncryptCBCPaddingError(t *testing.T) {
	key, _ := hex.DecodeString(strings.Repeat("24", 16))
	b, _ := aes.NewCipher(key)
	// One block that decrypts (IV zero) to 16 zero bytes: a pad byte of 0 is invalid.
	ct := make([]byte, 16)
	b.Encrypt(ct, make([]byte, 16))
	data := strings.Repeat("00", 16) + hex.EncodeToString(ct)
	err := encryptErr(t, url.Values{"mode": {"decrypt"}, "algo": {"aes-cbc"}, "key": {hex.EncodeToString(key)}, "data": {data}})
	if !strings.Contains(err.Error(), "wrong key or corrupted data") || !strings.Contains(err.Error(), "padding") {
		t.Errorf("padding: %v", err)
	}
	// Last byte 0x05 but the four before it aren't 0x05: also invalid.
	pt := make([]byte, 16)
	pt[15] = 5
	b.Encrypt(ct, pt)
	err = encryptErr(t, url.Values{"mode": {"decrypt"}, "algo": {"aes-cbc"}, "key": {hex.EncodeToString(key)}, "data": {strings.Repeat("00", 16) + hex.EncodeToString(ct)}})
	if !strings.Contains(err.Error(), "wrong key or corrupted data") {
		t.Errorf("inconsistent padding: %v", err)
	}
	// Not a whole number of blocks, and AAD offered to CBC.
	if err := encryptErr(t, url.Values{"mode": {"decrypt"}, "algo": {"aes-cbc"}, "key": {hex.EncodeToString(key)}, "data": {strings.Repeat("00", 16+17)}}); !strings.Contains(err.Error(), "not a whole number of 16-byte blocks") {
		t.Errorf("partial block: %v", err)
	}
	if err := encryptErr(t, url.Values{"algo": {"aes-cbc"}, "key": {hex.EncodeToString(key)}, "text": {"x"}, "aad": {"y"}}); !strings.Contains(err.Error(), "no associated data") {
		t.Errorf("CBC AAD: %v", err)
	}
}

// Keys are exactly 16/24/32 bytes (32 for ChaCha20), never padded or cut, and
// never text.
func TestEncryptKeyLengthRefused(t *testing.T) {
	for _, c := range []struct {
		algo, key, enc, want string
	}{
		{"aes-gcm", strings.Repeat("00", 15), "hex", "key: 15 bytes. AES takes exactly 16, 24 or 32 bytes"},
		{"aes-gcm", strings.Repeat("00", 33), "hex", "key: 33 bytes"},
		{"aes-cbc", strings.Repeat("00", 20), "hex", "never padded or truncated"},
		{"chacha20-poly1305", strings.Repeat("00", 16), "hex", "ChaCha20-Poly1305 takes exactly 32 bytes"},
		{"aes-gcm", "correct horse battery staple", "utf8", "A passphrase is not a key"},
		{"aes-gcm", "00112g", "hex", "at offset 5"},
		{"aes-gcm", strings.Repeat("00", 16), "base32", "key_enc: want hex or base64"},
		// 64 hex digits read as base64 are 48 bytes; the error says hex fits.
		{"aes-gcm", strings.Repeat("ab", 32), "base64", "Read as hex it is 32 bytes"},
	} {
		err := encryptErr(t, url.Values{"algo": {c.algo}, "key": {c.key}, "key_enc": {c.enc}, "text": {"x"}})
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s key %q (%s): %v, want %q", c.algo, c.key, c.enc, err, c.want)
		}
	}
}

func TestEncryptInputErrors(t *testing.T) {
	key := strings.Repeat("00", 16)
	for _, c := range []struct {
		fields url.Values
		want   string
	}{
		{url.Values{"algo": {"aes-ecb"}, "key": {key}}, "want aes-gcm, chacha20-poly1305 or aes-cbc"},
		{url.Values{"algo": {"des"}, "key": {key}}, "want aes-gcm"},
		{url.Values{"mode": {"sign"}, "key": {key}}, "mode: want encrypt or decrypt"},
		{url.Values{"key": {key}, "nonce": {"0011"}}, "nonce: 2 bytes; AES-128-GCM takes a 12-byte nonce"},
		{url.Values{"algo": {"aes-cbc"}, "key": {key}, "nonce": {strings.Repeat("00", 12)}}, "IV: 12 bytes"},
		{url.Values{"key": {key}, "text": {"zz"}, "enc": {"hex"}}, "plaintext: not hex"},
		{url.Values{"mode": {"decrypt"}, "key": {key}}, "no ciphertext given"},
		{url.Values{"mode": {"decrypt"}, "key": {key}, "data": {"00112233"}}, "shorter than the 12-byte nonce"},
		{url.Values{"mode": {"decrypt"}, "key": {key}, "data": {"AAAA*AAA"}}, "at offset 4"},
		{url.Values{"mode": {"decrypt"}, "key": {key}, "data": {"00"}, "data_enc": {"utf8"}}, "data_enc: want auto, base64 or hex"},
	} {
		_, err := runOp(t, "encrypt", c.fields, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.fields, err, c.want)
		}
	}
}

// A nonce in its own field: the data is then ciphertext ‖ tag. The whole
// output pasted back with the nonce still in its field also decrypts.
func TestEncryptDecryptWithNonceField(t *testing.T) {
	key, nonce := strings.Repeat("07", 32), "cafebabefacedbaddecaf888"
	e := encryptOf(t, url.Values{"key": {key}, "nonce": {nonce}, "text": {"hello"}})
	body := strings.TrimPrefix(e.Combined.Hex, nonce)
	d := encryptOf(t, url.Values{"mode": {"decrypt"}, "key": {key}, "nonce": {nonce}, "data": {body}})
	if d.Plaintext.Value != "hello" || d.NonceFrom != "field" || d.DataReadAs != "hex" {
		t.Errorf("body only: %+v", d)
	}
	d = encryptOf(t, url.Values{"mode": {"decrypt"}, "key": {key}, "nonce": {nonce}, "data": {e.Combined.Base64}})
	if d.Plaintext.Value != "hello" || d.NonceFrom != "blob" || !noted(d.Warnings, "starts with the nonce") {
		t.Errorf("combined with nonce field: %+v", d)
	}
	// With the nonce in its field and the wrong one, the error adds it to the causes.
	err := encryptErr(t, url.Values{"mode": {"decrypt"}, "key": {key}, "nonce": {strings.Repeat("00", 12)}, "data": {body}})
	if !strings.Contains(err.Error(), "wrong nonce") {
		t.Errorf("wrong nonce: %v", err)
	}
	// Explicit data_enc overrides detection.
	if err := encryptErr(t, url.Values{"mode": {"decrypt"}, "key": {key}, "data": {e.Combined.Hex}, "data_enc": {"base64"}}); !strings.Contains(err.Error(), "corrupted data") {
		t.Errorf("hex read as base64: %v", err)
	}
}

func TestRenderEncrypt(t *testing.T) {
	key := strings.Repeat("00", 16)
	html := render(t, "encrypt", url.Values{"key": {key}, "text": {"<script>alert(1)</script>"}})
	for _, want := range []string{"Encrypted, combined", "nonce (12 bytes) ‖ ciphertext (25 bytes) ‖ tag (16 bytes)", "Copy base64", "Parts"} {
		if !strings.Contains(html, want) {
			t.Errorf("encrypt fragment lacks %q", want)
		}
	}
	e := encryptOf(t, url.Values{"key": {key}, "text": {"<script>alert(1)</script>"}})
	html = render(t, "encrypt", url.Values{"mode": {"decrypt"}, "key": {key}, "data": {e.Combined.Base64}})
	if strings.Contains(html, "<script>alert") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("decrypted plaintext not escaped, or missing")
	}
}

func TestEncryptPageAndAPI(t *testing.T) {
	e := newCipherApp(t)
	page := do(t, e, http.MethodGet, "/encrypt", "", "", asBrowser).Body.String()
	for _, want := range []string{`data-cipher="encrypt"`, `href="/password"`, `href="/random"`, "nonce ‖ ciphertext ‖ tag", "iv ‖ ciphertext"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, `data-cipher="encrypt" data-live`) || strings.Contains(page, "ECB") {
		t.Error("encrypt form is live, or offers ECB")
	}
	body := url.Values{"key": {strings.Repeat("00", 16)}, "nonce": {strings.Repeat("00", 12)}, "text": {""}}.Encode()
	rec := do(t, e, http.MethodPost, "/encrypt", body, form, asAPI)
	var got struct {
		Combined struct{ Hex string } `json:"combined"`
		Layout   string               `json:"layout"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Combined.Hex != strings.Repeat("00", 12)+"58e2fccefa7e3061367f1d57a4e7455a" {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	rec = do(t, e, http.MethodPost, "/encrypt", body, form, asBrowser)
	if html := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(html, "58e2fccefa7e3061367f1d57a4e7455a") || !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("no-JS page: code %d", rec.Code)
	}
}

func hasLevel(ws []ciphertools.Warning, level, sub string) bool {
	for _, w := range ws {
		if w.Level == level && strings.Contains(w.Text, sub) {
			return true
		}
	}
	return false
}

// Encrypt with no key makes a 32-byte one and hands it back, so "encrypt this"
// needs no detour to the Random page; that key then decrypts the output.
// Decrypt with no key can't guess one and says so.
func TestEncryptBlankKeyIsGenerated(t *testing.T) {
	for _, algo := range []string{"aes-gcm", "chacha20-poly1305", "aes-cbc"} {
		res, err := runOp(t, "encrypt", url.Values{"algo": {algo}, "text": {"hello"}}, nil)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		r := res.(*ciphertools.EncryptResult)
		if r.GeneratedKey == nil || r.GeneratedKey.Bytes != 32 || r.KeyBytes != 32 {
			t.Fatalf("%s: generated key %+v", algo, r.GeneratedKey)
		}
		back, err := runOp(t, "encrypt", url.Values{"mode": {"decrypt"}, "algo": {algo}, "key": {r.GeneratedKey.Hex},
			"key_enc": {"hex"}, "data": {r.Combined.Base64}}, nil)
		if err != nil || back.(*ciphertools.EncryptResult).Plaintext.Value != "hello" {
			t.Fatalf("%s: decrypt with the generated key: %v", algo, err)
		}
	}
	err := encryptErr(t, url.Values{"mode": {"decrypt"}, "data": {"AAAA"}})
	if !strings.Contains(err.Error(), "no key given") {
		t.Fatalf("decrypt without a key: %v", err)
	}
}
