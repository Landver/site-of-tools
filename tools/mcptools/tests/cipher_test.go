package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/ciphertools"
)

const (
	jwtioToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	signKey    = "0123456789abcdef0123456789abcdef"
	// signedToken is json-post.golden.json's: signKey, sub 42, iat and a 1h exp at 1700000000.
	signedToken     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpXVCJ9.eyJzdWIiOiI0MiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.1Xl5k5oT2imtE3gNTlvZk5YE2vhTXknQNPMsKzR8xdg"
	rfcEdKey        = `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	rfcEdThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" // RFC 8037 A.3
	hunter2Hash     = "$2a$04$SOLJv1ZlNjqBz9G3p6VIAu13AISetd4XMilfZg/nsCwSqIj1ty/7i"
	sha256abc       = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	zeroKey, zeroIV = "00000000000000000000000000000000", "000000000000000000000000"
)

var testCert = sync.OnceValues(func() (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "mcp-test.example"},
		DNSNames: []string{"mcp-test.example"}, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1800000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = fmt.Sprintf("%02X", b)
	}
	return "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END CERTIFICATE-----\n", strings.Join(pairs, ":")
})

type cipherCase struct {
	tool string
	args map[string]any
	want map[string]any // values at dotted paths of the result
	// random results are compared by shape; varies names single values left out.
	random bool
	varies []string
}

func cipherCases() []cipherCase {
	pem, fingerprint := testCert()
	return []cipherCase{
		{tool: "cipher_jwt_decode", args: map[string]any{"token": jwtioToken, "key": "your-256-bit-secret", "now": 1700000000},
			want: map[string]any{"alg": "HS256", "verification.state": "valid", "payload.name": "John Doe"}},
		{tool: "cipher_jwt_sign", args: map[string]any{"key": signKey, "payload": `{"sub":"42"}`, "header": `{"cty":"JWT"}`,
			"now": 1700000000, "iat": true, "exp": "1h"},
			want: map[string]any{"token": signedToken, "decoded.verification.state": "valid"}},
		{tool: "cipher_hash", args: map[string]any{"text": "abc", "expected": sha256abc},
			want: map[string]any{"bytes": num(3), "compare.match": true, "compare.matches.0": "SHA-256"}},
		// RFC 4231 test case 2.
		{tool: "cipher_hmac", args: map[string]any{"text": "what do ya want for nothing?", "key": "Jefe",
			"expected": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
			want: map[string]any{"compare.match": true, "compare.matches.0": "HMAC-SHA-256"}},
		{tool: "cipher_password_hash", args: map[string]any{"password": "hunter2", "bcrypt_cost": 4},
			want: map[string]any{"parsed.algorithm": "bcrypt", "password_bytes": num(7)}, random: true},
		{tool: "cipher_password_verify", args: map[string]any{"hash": hunter2Hash, "password": "hunter2"},
			want: map[string]any{"state": "match", "parsed.algorithm": "bcrypt"}},
		// The GCM spec's test case 2.
		{tool: "cipher_encrypt", args: map[string]any{"key": zeroKey, "nonce": zeroIV, "text": zeroKey, "enc": "hex"},
			want: map[string]any{"algorithm": "AES-128-GCM", "ciphertext.hex": "0388dace60b6a392f328c2b971b2fe78", "tag.hex": "ab6e47d42cec13bdf53a67b21257bddf"}},
		{tool: "cipher_keys_generate", args: map[string]any{"type": "ed25519", "comment": "mcp-test"},
			want: map[string]any{"key.kind": "ed25519", "key.private": true}, random: true},
		{tool: "cipher_keys_inspect", args: map[string]any{"key": rfcEdKey},
			want:   map[string]any{"keys.0.kind": "ed25519", "keys.0.private": true, "keys.0.jwk_thumbprint": rfcEdThumbprint},
			varies: []string{"keys.0.openssh_private"}}, // its check integer is random
		{tool: "cipher_cert", args: map[string]any{"cert": pem, "now": 1750000000},
			want: map[string]any{"certificates.0.subject": "CN=mcp-test.example", "certificates.0.sha256_fingerprint": fingerprint,
				"certificates.0.validity.state": "valid"}},
		// RFC 6238 Appendix B, T=59, SHA1.
		{tool: "cipher_totp", args: map[string]any{"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits": 8, "now": 59, "code": "94287082"},
			want: map[string]any{"code": "94287082", "check.match": true, "check.step": "current"}},
		{tool: "cipher_random", args: map[string]any{"kind": "password", "length": 24, "sets": []any{"digits"}, "count": 2},
			want: map[string]any{"kind": "password", "alphabet": "0123456789"}, random: true},
		{tool: "cipher_encode", args: map[string]any{"text": "aGVsbG8=", "from": "base64"},
			want: map[string]any{"text": "hello", "hex": "68656c6c6f", "base32": "NBSWY3DP"}},
		// RFC 7617 §2.
		{tool: "cipher_basic_auth", args: map[string]any{"user": "Aladdin", "password": "open sesame"},
			want: map[string]any{"mode": "build", "token": "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="}},
		{tool: "cipher_identify", args: map[string]any{"text": "5d41402abc4b2a76b9719d911017c592"},
			want: map[string]any{"candidates.0.name": "MD5 digest", "candidates.0.hashcat": "0"}},
	}
}

func dig(v any, path string) any {
	for _, k := range strings.Split(path, ".") {
		switch c := v.(type) {
		case map[string]any:
			v = c[k]
		case []any:
			i, err := strconv.Atoi(k)
			if err != nil || i >= len(c) {
				return nil
			}
			v = c[i]
		default:
			return nil
		}
	}
	return v
}

func TestCipherToolsKnownVectors(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/cipher", nil, nil)
	cases := cipherCases()
	if len(cases) != len(ciphertools.Ops()) {
		t.Fatalf("%d cases for %d ops", len(cases), len(ciphertools.Ops()))
	}
	for _, tc := range cases {
		got := object(t, call(t, cs, tc.tool, tc.args))
		for path, want := range tc.want {
			if v := dig(got, path); !cmp.Equal(v, want) {
				t.Errorf("%s: %s = %v, want %v", tc.tool, path, v, want)
			}
		}
	}

	pw := object(t, call(t, cs, "cipher_password_hash", map[string]any{"password": "hunter2", "algo": "argon2id",
		"argon2_m": 8, "argon2_t": 1, "argon2_p": 1}))
	for password, state := range map[string]string{"hunter2": "match", "hunter3": "no-match"} {
		v := object(t, call(t, cs, "cipher_password_verify", map[string]any{"hash": pw["encoded"], "password": password}))
		if v["state"] != state {
			t.Errorf("verify %s against its own argon2id hash = %v, want %s", password, v["state"], state)
		}
	}
	rnd := object(t, call(t, cs, "cipher_random", map[string]any{"kind": "password", "length": 24, "sets": []any{"digits"}, "count": 2}))
	for _, v := range rnd["values"].([]any) {
		if !regexp.MustCompile(`^[0-9]{24}$`).MatchString(v.(string)) {
			t.Errorf("sets [digits] gave %q", v)
		}
	}
	// A bad key_enc is reported where the signature check would be.
	jwt := object(t, call(t, cs, "cipher_jwt_decode", map[string]any{"token": jwtioToken, "key": "zz", "key_enc": "hex"}))
	if dig(jwt, "verification.state") != ciphertools.VerifyError {
		t.Errorf("unreadable key = %v, want verification.state %s", jwt["verification"], ciphertools.VerifyError)
	}
}

// TestCipherJSONFieldKeepsItsOrder: payload is signed as written, so an object is refused.
func TestCipherJSONFieldKeepsItsOrder(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/cipher", nil, nil)
	const payload = `{"sub":"42","name":"Ada","admin":true}`
	got := object(t, call(t, cs, "cipher_jwt_sign", map[string]any{"key": signKey, "payload": payload}))
	seg, err := base64.RawURLEncoding.DecodeString(strings.Split(got["token"].(string), ".")[1])
	if err != nil || string(seg) != payload {
		t.Errorf("signed payload = %s %v, want %s byte for byte", seg, err, payload)
	}
	failsWith(t, call(t, cs, "cipher_jwt_sign", map[string]any{"key": signKey, "payload": map[string]any{"sub": "42"}}), "payload")
}

func TestCipherBadInput(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/cipher", nil, nil)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"cipher_hash", map[string]any{"text": "abc", "enc": "rot13"}, "enc"},
		{"cipher_identify", map[string]any{"text": "abc", "nope": 1}, "nope"},
		{"cipher_random", map[string]any{"kind": "password", "sets": []any{"emoji"}}, "sets"},
		{"cipher_random", map[string]any{"kind": "password", "sets": []any{}}, "pick at least one"},
		{"cipher_random", map[string]any{"kind": "uuid", "version": 5}, "version"},
		{"cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "digits": 9}, "digits"},
		{"cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "mode": "hotp", "counter": 1 << 53}, "counter"},
		{"cipher_jwt_decode", map[string]any{"token": "a.b"}, "only two parts"},
		{"cipher_jwt_sign", map[string]any{"key": signKey, "alg": "hs256"}, "alg"},
		{"cipher_jwt_decode", map[string]any{}, "token"},
		{"cipher_cert", map[string]any{"cert": "x"}, "not PEM"},
	} {
		failsWith(t, call(t, cs, tc.tool, tc.args), tc.want)
	}
	// The largest counter every JSON parser reads exactly is accepted.
	object(t, call(t, cs, "cipher_totp", map[string]any{"secret": "JBSWY3DPEHPK3PXP", "mode": "hotp", "counter": 1<<53 - 1}))
}

func TestCipherWholeStrings(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/cipher", nil, nil)
	text := strings.Repeat("0123456789abcdef", 200)
	got := object(t, call(t, cs, "cipher_encode", map[string]any{"text": text}))
	if b64 := got["base64"].(string); b64 != base64.StdEncoding.EncodeToString([]byte(text)) {
		t.Errorf("base64 of 3200 bytes came back as %d bytes, cut", len(b64))
	}
}

// TestHeavyCipherOps: a heavy op holds its memory cost of the budget REST shares.
func TestHeavyCipherOps(t *testing.T) {
	var log syncBuffer
	lim := roomyCipher()
	s := newStack(t, stackOpts{cipherLim: lim, log: &log})
	cs := s.client(t, "/mcp/cipher", nil, nil)
	const budget = 256 << 20
	if !lim.HeavyCap.TryAcquire(otherClient, budget) {
		t.Fatal("a fresh heavy budget is not 256 MiB")
	}
	bcrypt := map[string]any{"password": "pw", "bcrypt_cost": 4}
	if res := call(t, cs, "cipher_password_hash", bcrypt); !res.IsError || text(t, res) != platform.BusyMessage {
		t.Errorf("full budget = %q, want %q", text(t, res), platform.BusyMessage)
	}
	rec := s.do(http.MethodPost, "/password/hash", `{"password":"pw","bcrypt_cost":4}`,
		map[string]string{"Host": cipherHost, "Accept": "application/json", "Content-Type": "application/json"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("REST with the budget full = %d, want 503: one budget for both doors", rec.Code)
	}
	object(t, call(t, cs, "cipher_hash", map[string]any{"text": "abc"}))
	if !strings.Contains(log.String(), `"outcome":"busy"`) || !strings.Contains(log.String(), "#cipher_password_hash") {
		t.Errorf("log lacks the busy outcome:\n%s", log.String())
	}
	lim.HeavyCap.Release(otherClient, budget)

	// 20 MiB left: bcrypt's flat 16 MiB fits, a 64 MiB Argon2id does not.
	lim.HeavyCap.TryAcquire(otherClient, budget-20<<20)
	defer lim.HeavyCap.Release(otherClient, budget-20<<20)
	object(t, call(t, cs, "cipher_password_hash", bcrypt))
	argon := map[string]any{"password": "pw", "algo": "argon2id", "argon2_m": 65536, "argon2_t": 1, "argon2_p": 1}
	if res := call(t, cs, "cipher_password_hash", argon); !res.IsError || text(t, res) != platform.BusyMessage {
		t.Errorf("64 MiB Argon2id with 20 MiB left = %q, want busy", text(t, res))
	}
}

func del(m map[string]any, path string) {
	if i := strings.LastIndex(path, "."); i >= 0 {
		m, _ = dig(m, path[:i]).(map[string]any)
		path = path[i+1:]
	}
	delete(m, path)
}

func shape(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range t {
			out[k] = shape(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = shape(e)
		}
		return out
	}
	return fmt.Sprintf("%T", v)
}

func TestCipherParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil, nil)
	paths := map[string]string{}
	for _, op := range ciphertools.Ops() {
		paths["cipher_"+strings.ReplaceAll(op.Name, "-", "_")] = op.Path
	}
	paths["cipher_basic_auth"] = "/encode/basic"
	for _, tc := range cipherCases() {
		form := map[string]any{}
		for k, v := range tc.args {
			if list, ok := v.([]any); ok {
				parts := make([]string, len(list))
				for i, e := range list {
					parts[i] = e.(string)
				}
				v = strings.Join(parts, ",")
			}
			form[k] = v
		}
		body, _ := json.Marshal(form)
		rec := s.do(http.MethodPost, paths[tc.tool], string(body),
			map[string]string{"Host": cipherHost, "Accept": "application/json", "Content-Type": "application/json"})
		if rec.Code != http.StatusOK {
			t.Fatalf("REST %s = %d %s", paths[tc.tool], rec.Code, rec.Body)
		}
		want, got := decode(t, rec.Body.Bytes()), object(t, call(t, cs, tc.tool, tc.args))
		for _, path := range append(tc.varies, "took_ms") {
			del(want, path)
			del(got, path)
		}
		if tc.random {
			want, got = shape(want).(map[string]any), shape(got).(map[string]any)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s vs REST %s (-rest +mcp):\n%s", tc.tool, paths[tc.tool], diff)
		}
	}
}
