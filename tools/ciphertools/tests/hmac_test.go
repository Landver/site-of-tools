package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func hmacOf(t *testing.T, fields url.Values) *ciphertools.HMACResult {
	t.Helper()
	res, err := runOp(t, "hmac", fields, nil)
	if err != nil {
		t.Fatalf("hmac: %v", err)
	}
	return res.(*ciphertools.HMACResult)
}

// RFC 4231 test cases 1, 2 and 6 (SHA-2) and RFC 2202 test cases 1 and 2
// (MD5, SHA-1). HMAC-SHA3 for case 2 is cross-checked against Python's hmac.
func TestHMACPublishedVectors(t *testing.T) {
	cases := []struct {
		name, text, key, keyEnc string
		want                    map[string]string
	}{
		{"RFC 4231 TC1", "Hi There", strings.Repeat("0b", 20), "hex", map[string]string{
			"sha224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
			"sha256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			"sha384": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
			"sha512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
			"sha1":   "b617318655057264e28bc0b6fb378c8ef146be00", // RFC 2202 SHA-1 TC1 uses the same 20-byte key
		}},
		{"RFC 2202 MD5 TC1", "Hi There", strings.Repeat("0b", 16), "hex", map[string]string{
			"md5": "9294727a3638bb1c13f48ef8158bfc9d",
		}},
		{"RFC 4231 / 2202 TC2", "what do ya want for nothing?", "Jefe", "utf8", map[string]string{
			"md5":      "750c783e6ab0b503eaa86e310a5db738",
			"sha1":     "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
			"sha224":   "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
			"sha256":   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			"sha384":   "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
			"sha512":   "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
			"sha3_256": "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5",
			"sha3_512": "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024",
		}},
		// A key longer than the block size is hashed first (RFC 2104); that's
		// correct and must not be "fixed".
		{"RFC 4231 TC6", "Test Using Larger Than Block-Size Key - Hash Key First", strings.Repeat("aa", 131), "hex", map[string]string{
			"sha256": "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hmacOf(t, url.Values{"text": {c.text}, "key": {c.key}, "key_enc": {c.keyEnc}})
			if len(r.MACs) != 8 {
				t.Errorf("%d MACs, want 8", len(r.MACs))
			}
			for id, want := range c.want {
				if d := digestByID(t, r.MACs, id); d.Hex != want {
					t.Errorf("%s = %s, want %s", d.Name, d.Hex, want)
				}
			}
		})
	}
}

// The same four key bytes, however they are written, give the same MACs.
func TestHMACKeyEncodings(t *testing.T) {
	msg := "what do ya want for nothing?"
	want := hmacOf(t, url.Values{"text": {msg}, "key": {"Jefe"}}).MACs
	for enc, key := range map[string]string{"hex": "4a656665", "base64": "SmVmZQ==", "base64url": "SmVmZQ"} {
		r := hmacOf(t, url.Values{"text": {msg}, "key": {key}, "key_enc": {enc}})
		if r.KeyBytes != 4 {
			t.Errorf("%s: key is %d bytes", enc, r.KeyBytes)
		}
		for i := range want {
			if r.MACs[i].Hex != want[i].Hex {
				t.Errorf("%s: %s differs", enc, want[i].Name)
			}
		}
	}
	// Read as UTF-8, "4a656665" is eight different bytes.
	if r := hmacOf(t, url.Values{"text": {msg}, "key": {"4a656665"}}); r.MACs[3].Hex == want[3].Hex {
		t.Error("hex key text read as hex without being asked")
	}
	_, err := runOp(t, "hmac", url.Values{"text": {msg}, "key": {"4a65zz"}, "key_enc": {"hex"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "key") || !strings.Contains(err.Error(), "offset 4") {
		t.Errorf("bad hex key: %v", err)
	}
}

func TestHMACVerifyExpected(t *testing.T) {
	const tc2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	raw, _ := hex.DecodeString(tc2)
	fields := func(expected string) url.Values {
		return url.Values{"text": {"what do ya want for nothing?"}, "key": {"Jefe"}, "expected": {expected}}
	}
	for name, expected := range map[string]string{
		"hex":                tc2,
		"uppercase":          strings.ToUpper(tc2),
		"GitHub sha256=":     "sha256=" + tc2,
		"Slack v0=":          "v0=" + tc2,
		"base64":             base64.StdEncoding.EncodeToString(raw),
		"Stripe-Signature":   "t=1492774577,v1=" + tc2 + ",v0=deadbeef",
		"surrounding spaces": "  " + tc2 + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := hmacOf(t, fields(expected))
			if r.Compare == nil || !r.Compare.Match || !slices.Equal(r.Compare.Matches, []string{"HMAC-SHA-256"}) {
				t.Fatalf("compare = %+v", r.Compare)
			}
			if !digestByID(t, r.MACs, "sha256").Match {
				t.Error("row not marked")
			}
		})
	}
	r := hmacOf(t, fields("t=1,v1="+tc2))
	if !strings.Contains(r.Compare.Note, "Stripe") {
		t.Errorf("Stripe header not explained: %q", r.Compare.Note)
	}
	r = hmacOf(t, fields("sha1=effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"))
	if !slices.Equal(r.Compare.Matches, []string{"HMAC-SHA-1"}) || !strings.Contains(r.Compare.Note, "sha1") {
		t.Errorf("sha1= prefix: %+v", r.Compare)
	}

	// Wrong MAC: no match, and the 32-byte algorithms are named.
	r = hmacOf(t, fields("sha256="+strings.Repeat("00", 32)))
	c := r.Compare
	if c.Match || !slices.Contains(c.SameSize, "HMAC-SHA-256") || !slices.Contains(c.SameSize, "HMAC-SHA3-256") {
		t.Fatalf("mismatch = %+v", c)
	}
	if !strings.Contains(c.Detail, "raw body") {
		t.Errorf("no webhook hint: %q", c.Detail)
	}
}

func TestHMACKeyWarnings(t *testing.T) {
	r := hmacOf(t, url.Values{"text": {"x"}, "key": {""}})
	if !noted(r.Warnings, "key is empty") {
		t.Errorf("empty key: %+v", r.Warnings)
	}
	if len(r.MACs) != 8 || r.MACs[3].Hex == "" {
		t.Error("an empty key is valid HMAC and must still compute")
	}
	r = hmacOf(t, url.Values{"text": {"x"}, "key": {"Jefe"}})
	if !noted(r.Warnings, "shorter than every hash output") {
		t.Errorf("4-byte key: %+v", r.Warnings)
	}
	r = hmacOf(t, url.Values{"text": {"x"}, "key": {strings.Repeat("k", 20)}})
	if !noted(r.Warnings, "HMAC-SHA-256 (32)") || noted(r.Warnings, "HMAC-MD5 (16)") {
		t.Errorf("20-byte key: %+v", r.Warnings)
	}
	r = hmacOf(t, url.Values{"text": {"x"}, "key": {strings.Repeat("k", 64)}})
	if noted(r.Warnings, "shorter") {
		t.Errorf("64-byte key called short: %+v", r.Warnings)
	}
	r = hmacOf(t, url.Values{"text": {"x"}, "key": {strings.Repeat("k", 100)}})
	if !noted(r.Warnings, "hashes it first") {
		t.Errorf("long key not explained: %+v", r.Warnings)
	}
	r = hmacOf(t, url.Values{"text": {"x"}, "key": {"secret "}})
	if !noted(r.Warnings, "whitespace") {
		t.Errorf("trailing space in key: %+v", r.Warnings)
	}
	r = hmacOf(t, url.Values{"text": {"{\"a\":1}\n"}, "key": {strings.Repeat("k", 32)}})
	if !noted(r.Warnings, "Ends in a newline") {
		t.Errorf("message newline: %+v", r.Warnings)
	}
}

// The webhook trap, same as the JWT one: a secret handed out as base64 looks
// like text, and read as text it is a different key. With an expected MAC to
// compare against, "detect" tries each reading of the key and uses the one that
// matches; an explicit reading that fails says which one would have.
func TestHMACKeyEncodingDetected(t *testing.T) {
	const pasted, body = "hkjlhlkjhjklhkljhlkjhlkhlk", `{"event":"ping"}`
	meant, _ := base64.RawStdEncoding.DecodeString(pasted)
	want := hmacHex(meant, body)

	for _, enc := range []string{"", "auto"} {
		r := hmacOf(t, url.Values{"text": {body}, "key": {pasted}, "key_enc": {enc}, "expected": {"sha256=" + want}})
		if r.Compare == nil || !r.Compare.Match || !strings.Contains(r.KeyReadAs, "base64") || r.KeyBytes != len(meant) {
			t.Fatalf("enc %q: compare %+v, key read as %q (%d bytes)", enc, r.Compare, r.KeyReadAs, r.KeyBytes)
		}
	}

	r := hmacOf(t, url.Values{"text": {body}, "key": {pasted}, "key_enc": {"utf8"}, "expected": {want}})
	if r.Compare.Match || !strings.Contains(r.Compare.Detail, "read as base64") {
		t.Fatalf("explicit utf8: %+v", r.Compare)
	}

	// No expected MAC: nothing to detect against, so the key is text.
	r = hmacOf(t, url.Values{"text": {body}, "key": {pasted}})
	if r.KeyBytes != len(pasted) {
		t.Fatalf("no expected: key read as %q, %d bytes", r.KeyReadAs, r.KeyBytes)
	}
}

func hmacHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
