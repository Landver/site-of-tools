package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
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
	jwtioToken  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	signKey     = "0123456789abcdef0123456789abcdef"
	rfcEdKey    = `{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	hunter2Hash = "$2a$04$SOLJv1ZlNjqBz9G3p6VIAu13AISetd4XMilfZg/nsCwSqIj1ty/7i"
)

var testCert = sync.OnceValue(func() string {
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
	return "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END CERTIFICATE-----\n"
})

func TestCipherParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil)
	paths, covered := map[string]string{}, map[string]bool{}
	for _, op := range ciphertools.Ops() {
		name := "cipher_" + strings.ReplaceAll(op.Name, "-", "_")
		if op.Name == "basic" {
			name = "cipher_basic_auth"
		}
		paths[name] = op.Path
	}
	zero := strings.Repeat("0", 32)
	for _, tc := range []struct {
		tool string
		args map[string]any
		want map[string]any // values at dotted paths of the result
		// random results are compared by shape; varies names values that differ call to call.
		random bool
		varies []string
	}{
		{tool: "cipher_jwt_decode", args: map[string]any{"token": jwtioToken, "key": "your-256-bit-secret", "now": 1700000000}},
		{tool: "cipher_jwt_decode", args: map[string]any{"token": jwtioToken, "key": "zz", "key_enc": "hex"},
			want: map[string]any{"verification.state": ciphertools.VerifyError}},
		{tool: "cipher_jwt_sign", args: map[string]any{"key": signKey, "payload": `{"sub":"42","name":"Ada","admin":true}`,
			"header": `{"cty":"JWT"}`, "now": 1700000000, "iat": true, "exp": "1h"}},
		{tool: "cipher_hash", args: map[string]any{"text": "abc", "expected": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
		{tool: "cipher_hmac", args: map[string]any{"text": "what do ya want for nothing?", "key": "Jefe",
			"expected": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"}},
		{tool: "cipher_password_hash", args: map[string]any{"password": "hunter2", "bcrypt_cost": 4},
			want: map[string]any{"parsed.algorithm": "bcrypt", "password_bytes": num(7)}, random: true},
		{tool: "cipher_password_verify", args: map[string]any{"hash": hunter2Hash, "password": "hunter2"}},
		{tool: "cipher_encrypt", args: map[string]any{"key": zero, "nonce": zero[:24], "text": zero, "enc": "hex"}},
		{tool: "cipher_keys_generate", args: map[string]any{"type": "ed25519", "comment": "mcp-test"},
			want: map[string]any{"key.kind": "ed25519", "key.private": true}, random: true},
		{tool: "cipher_keys_inspect", args: map[string]any{"key": rfcEdKey}, varies: []string{"keys.0.openssh_private"}},
		{tool: "cipher_cert", args: map[string]any{"cert": testCert(), "now": 1750000000}},
		{tool: "cipher_totp", args: map[string]any{"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits": 8, "now": 59, "code": "94287082"}},
		{tool: "cipher_random", args: map[string]any{"kind": "password", "length": 24, "sets": []any{"digits"}, "count": 2},
			want: map[string]any{"kind": "password", "alphabet": "0123456789"}, random: true},
		{tool: "cipher_encode", args: map[string]any{"text": "aGVsbG8=", "from": "base64"}},
		{tool: "cipher_basic_auth", args: map[string]any{"user": "Aladdin", "password": "open sesame"}},
		{tool: "cipher_identify", args: map[string]any{"text": "5d41402abc4b2a76b9719d911017c592"}},
	} {
		got := object(t, call(t, cs, tc.tool, tc.args))
		for path, v := range tc.want {
			if g := dig(got, path); !cmp.Equal(g, v) {
				t.Errorf("%s: %s = %v, want %v", tc.tool, path, g, v)
			}
		}
		// REST takes a list as its form field does, comma-separated.
		form := maps.Clone(tc.args)
		for k, v := range form {
			if list, ok := v.([]any); ok {
				parts := make([]string, len(list))
				for i, e := range list {
					parts[i] = e.(string)
				}
				form[k] = strings.Join(parts, ",")
			}
		}
		body, _ := json.Marshal(form)
		want := s.restOK(t, cipherHost, paths[tc.tool], string(body))
		covered[tc.tool] = true
		for _, path := range append(tc.varies, "took_ms") {
			del(want, path)
			del(got, path)
		}
		if tc.random {
			want, got = shape(want).(map[string]any), shape(got).(map[string]any)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s vs REST (-rest +mcp):\n%s", tc.tool, diff)
		}
	}
	for tool := range paths {
		if !covered[tool] {
			t.Errorf("%s has no case", tool)
		}
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

func TestHeavyCipherOpsHoldTheirMemoryCost(t *testing.T) {
	var log syncBuffer
	s := newStack(t, stackOpts{log: &log})
	cs := s.client(t, "/mcp/cipher", nil)
	heavy := s.cipherLim.HeavyCap
	const budget = 256 << 20
	if !heavy.TryAcquire(otherClient, budget) {
		t.Fatal("a fresh heavy budget is not 256 MiB")
	}
	bcrypt := map[string]any{"password": "pw", "bcrypt_cost": 4}
	if res := call(t, cs, "cipher_password_hash", bcrypt); text(t, res) != platform.BusyMessage {
		t.Errorf("full budget = %q, want busy", text(t, res))
	}
	if code := s.rest(cipherHost, "/password/hash", `{"password":"pw","bcrypt_cost":4}`, nil).Code; code != http.StatusServiceUnavailable {
		t.Errorf("REST with the budget full = %d, want 503", code)
	}
	object(t, call(t, cs, "cipher_hash", map[string]any{"text": "abc"}))
	if !strings.Contains(log.String(), `"outcome":"busy"`) || !strings.Contains(log.String(), "#cipher_password_hash") {
		t.Errorf("log lacks the busy outcome:\n%s", log.String())
	}
	heavy.Release(otherClient, budget)

	// 20 MiB left: bcrypt's flat 16 MiB fits, a 64 MiB Argon2id does not.
	heavy.TryAcquire(otherClient, budget-20<<20)
	object(t, call(t, cs, "cipher_password_hash", bcrypt))
	argon := map[string]any{"password": "pw", "algo": "argon2id", "argon2_m": 65536, "argon2_t": 1, "argon2_p": 1}
	if res := call(t, cs, "cipher_password_hash", argon); text(t, res) != platform.BusyMessage {
		t.Errorf("64 MiB Argon2id with 20 MiB left = %q, want busy", text(t, res))
	}
}
