package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// fakeRSA builds an RSA key of any size in milliseconds from odd non-primes: Go's validation
// doesn't test primality, so an oversized key is cheap to send and the caps must come first.
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
	return pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k))
}

// Every key read from input stops at crypto/tls's 8192 bits, before the work that grows with it.
func TestRSAKeyAboveLimitRefused(t *testing.T) {
	k := fakeRSA(t, 10240)
	b64 := base64.RawURLEncoding.EncodeToString
	for name, in := range map[string]string{
		"SPKI PEM":  spkiPEM(t, &k.PublicKey),
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

// Go validates an RSA key while parsing it, so a block larger than any real key is refused unparsed.
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

// The certificate page checks signatures with each certificate's key, so the cap applies there too.
func TestCertWithOversizedRSAKeyRefused(t *testing.T) {
	k := fakeRSA(t, 10240)
	wantErr(t, "cert", url.Values{"cert": {pemOf(rsaCert(t, &k.PublicKey))}}, "8,192")
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

func oddBits(bits int) *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	return n.SetBit(n.SetBit(n, bits-1, 1), 0, 1)
}

// Go validates an RSA key while parsing it in super-linear time, so oversized fakes must be refused unparsed.
func TestOversizedRSAPartsRefusedQuickly(t *testing.T) {
	p, q := oddBits(1<<19), oddBits(1<<19)
	pkcs1, _ := asn1.Marshal(struct {
		V                     int
		N                     *big.Int
		E                     int
		D, P, Q, Dp, Dq, Qinv *big.Int
	}{0, new(big.Int).Mul(p, q), 65537, oddBits(1 << 20), p, q, oddBits(1 << 19), oddBits(1 << 19), oddBits(1 << 19)})
	pkcs8, _ := asn1.Marshal(struct {
		V    int
		Algo pkix.AlgorithmIdentifier
		Key  []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.RawValue{Tag: 5}}, pkcs1})
	start := time.Now()
	r, err := ciphertools.Identify(base64.StdEncoding.EncodeToString(pkcs8))
	if err != nil || time.Since(start) > 2*time.Second || len(r.Candidates) > 0 && strings.Contains(r.Candidates[0].Why, "private key") {
		t.Errorf("identify of %d bytes of fake PKCS#8: %v after %v", len(pkcs8), err, time.Since(start))
	}

	b64u := func(x *big.Int) string { return base64.RawURLEncoding.EncodeToString(x.Bytes()) }
	jwk, _ := json.Marshal(map[string]string{"kty": "RSA", "n": b64u(oddBits(2048)), "e": "AQAB", "d": b64u(oddBits(2047)), "p": b64u(oddBits(1 << 20)), "q": b64u(oddBits(1024))})
	start = time.Now()
	wantErr(t, "keys-inspect", url.Values{"key": {string(jwk)}}, "a prime is longer than the modulus")
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("keys-inspect took %v", d)
	}
}
