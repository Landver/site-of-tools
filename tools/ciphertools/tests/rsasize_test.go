package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// fakeRSA builds an RSA private key of any size in milliseconds, from odd
// numbers that aren't prime. Go's key validation multiplies; it doesn't test
// primality, so it accepts such a key, and every signature with it costs the
// full price. That is what makes an oversized key cheap to send and why the
// size caps must hold before any work starts.
func fakeRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	one, e := big.NewInt(1), big.NewInt(65537)
	odd := func() *big.Int {
		for {
			p, err := rand.Int(rand.Reader, new(big.Int).Lsh(one, uint(bits/2)))
			if err != nil {
				t.Fatal(err)
			}
			p.SetBit(p, bits/2-1, 1).SetBit(p, bits/2-2, 1).SetBit(p, 0, 1)
			if new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(p, one)).Cmp(one) == 0 {
				return p
			}
		}
	}
	for {
		p, q := odd(), odd()
		pm, qm := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
		lambda := new(big.Int).Div(new(big.Int).Mul(pm, qm), new(big.Int).GCD(nil, nil, pm, qm))
		d := new(big.Int).ModInverse(e, lambda)
		if d == nil || new(big.Int).GCD(nil, nil, p, q).Cmp(one) != 0 {
			continue
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}, D: d, Primes: []*big.Int{p, q}}
		// The CRT values by hand: Precompute's own assume p is prime.
		k.Precomputed.Dp, k.Precomputed.Dq = new(big.Int).Mod(d, pm), new(big.Int).Mod(d, qm)
		k.Precomputed.Qinv = new(big.Int).ModInverse(q, p)
		k.Precompute()
		if err := k.Validate(); err != nil {
			t.Fatalf("fake RSA-%d: %v", bits, err)
		}
		return k
	}
}

func rsaPrivatePEM(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func rsaPublicPEM(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Go puts no cap on an RSA modulus, and verifying grows with its square,
// signing with its cube: RSA-32768 takes seconds to sign with, a key filling
// the request body minutes to verify. Every key read from input stops at
// crypto/tls's 8192 bits, before any of that work.
func TestRSAKeyAboveLimitRefused(t *testing.T) {
	k := fakeRSA(t, 10240)
	b64 := base64.RawURLEncoding.EncodeToString
	for name, in := range map[string]string{
		"SPKI PEM":  rsaPublicPEM(t, &k.PublicKey),
		"PKCS#1":    rsaPrivatePEM(k),
		"JWK":       `{"kty":"RSA","e":"AQAB","n":"` + b64(k.N.Bytes()) + `"}`,
		"JWKS":      `{"keys":[{"kty":"RSA","e":"AQAB","n":"` + b64(k.N.Bytes()) + `"}]}`,
		"certified": pemOf(rsaCert(t, &k.PublicKey)),
	} {
		_, err := ciphertools.ParseKeys(in)
		if err == nil || !strings.Contains(err.Error(), "8,192") {
			t.Errorf("%s: err = %v, want the 8,192-bit limit named", name, err)
		}
	}

	// At the limit is fine.
	if _, err := ciphertools.ParseKeys(rsaPrivatePEM(fakeRSA(t, 8192))); err != nil {
		t.Errorf("RSA-8192: %v", err)
	}
}

// Go validates an RSA private key as it parses it, and that is quadratic in
// the key's size, so a bit cap checked afterwards would come too late: a block
// larger than any real key is refused unparsed.
func TestOversizedPrivateKeyNotParsed(t *testing.T) {
	huge := rsaPrivatePEM(fakeRSA(t, 32768)) // ~18 KB of DER
	_, err := ciphertools.ParseKeys(huge)
	if err == nil || !strings.Contains(err.Error(), "reads up to 16 KiB") {
		t.Errorf("ParseKeys: err = %v, want the DER size limit", err)
	}

	c, i := find(identify(t, huge), "RSA")
	if i < 0 || !strings.Contains(c.Why, "not parsed") {
		t.Errorf("identify: %+v, want it named but not parsed", c)
	}
}

// The certificate page checks signatures with each certificate's key, so the
// cap applies to the keys certificates carry.
func TestCertWithOversizedRSAKeyRefused(t *testing.T) {
	k := fakeRSA(t, 10240)
	_, err := runOp(t, "cert", url.Values{"cert": {pemOf(rsaCert(t, &k.PublicKey))}}, nil)
	if err == nil || !strings.Contains(err.Error(), "8,192") {
		t.Errorf("cert: err = %v, want the 8,192-bit limit named", err)
	}
}

// rsaCert is a certificate for pub, signed by a throwaway EC CA.
func rsaCert(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	ca := ecKey(t)
	caT := caTemplate(1, "Test Root CA", 1)
	_, caCert := mustCert(t, caT, caT, &ca.PublicKey, ca)
	der, _ := mustCert(t, leafTemplate(), caCert, pub, ca)
	return der
}
